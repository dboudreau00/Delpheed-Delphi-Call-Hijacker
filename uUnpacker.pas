unit uUnpacker;

{
  uUnpacker - a generic "run and dump" unpacker for 32-bit PE executables.

  It does what an analyst does by hand in OllyDbg/x64dbg:

    1. Launch the packed target under the Windows debug API so we control it.
    2. Put an INT3 on the packer stub's entry point and let it run there.
    3. Single-step until the stub executes PUSHAD (0x60) - the register save
       that almost every compressing stub does first.
    4. Arm a hardware data breakpoint on the saved-ESP slot. When the matching
       POPAD reads it back, we are microseconds from the tail jump to the
       Original Entry Point (this is the "calljacking" moment).
    5. Single-step from there until execution leaves the stub's section and
       lands in the real code section - that address is the OEP.
    6. ReadProcessMemory the now-unpacked image and write it back out with the
       section raw layout matched to the memory layout and the entry point
       fixed to the OEP.

  WARNING: this RUNS the target's unpacking stub. Only point it at samples you
  are authorised to analyse, and do it inside a throwaway VM.

  Scope / limits (be honest about these):
    * 32-bit targets only. Build this unit 32-bit (dcc32). PUSHAD/POPAD and the
      classic ESP trick do not exist on x64; that needs a guard-page method.
    * Works on plain compressors (UPX, ASPack, older PECompact, MPRESS...).
      Strong protectors (Themida, VMProtect, Enigma) use anti-debug and will
      not reach a clean OEP this way.
    * The import table is NOT reconstructed. The dump is meant to be *analysed*
      statically (feed it to the PE parser / VMT scanner), not re-run. Making it
      runnable again needs a Scylla-style IAT rebuild.
}

{$WARN SYMBOL_PLATFORM OFF}

{$IF Defined(WIN64)}
  {$MESSAGE WARN 'Compile this 32-bit (dcc32) to unpack 32-bit targets.'}
{$IFEND}

interface

uses
  Windows, SysUtils, Classes;

type
  TUnpackLog = reference to procedure(const Msg: string);

  TUnpackResult = record
    Success: Boolean;
    Message: string;
    ImageBase: NativeUInt;
    OEPRVA: Cardinal;
    OEPVA: NativeUInt;
    DumpFile: string;
  end;

  TGenericUnpacker = class
  private
    FLog: TUnpackLog;
    FProc: THandle;
    FThread: THandle;
    FBase: NativeUInt;
    FEntry: NativeUInt;
    FSizeOfImage: Cardinal;
    FSizeOfHeaders: Cardinal;
    FLfanew: Cardinal;
    FOptOfs: Cardinal;
    FSecTab: Cardinal;
    FNumSecs: Integer;
    FSecVA: TArray<Cardinal>;
    FSecVSize: TArray<Cardinal>;
    FSecChar: TArray<Cardinal>;
    FStubSec: Integer;
    FOrigEntryByte: Byte;
    FPrevEip: NativeUInt;
    FStepCount: Integer;
    FOepSteps: Integer;
    FOEP: NativeUInt;
    procedure Log(const S: string);
    function ReadMem(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
    function WriteMem(Addr: NativeUInt; const Buf; Size: NativeUInt): Boolean;
    function RByte(Addr: NativeUInt): Byte;
    procedure WByte(Addr: NativeUInt; B: Byte);
    function GetCtx(var Ctx: TContext): Boolean;
    function SetCtx(var Ctx: TContext): Boolean;
    function ParseHeaders: Boolean;
    function SectionOfRVA(RVA: Cardinal): Integer;
    procedure SetEntryBP;
    procedure RemoveEntryBP(var Ctx: TContext);
    function DumpTo(const OutFile: string): Boolean;
  public
    constructor Create(ALog: TUnpackLog = nil);
    function Unpack(const TargetExe, OutputExe: string): TUnpackResult;
  end;

implementation

// Import the memory calls ourselves so the byte-count parameter type is fixed
// regardless of RTL header differences across Delphi versions.
function K32Read(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpRead: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'ReadProcessMemory';
function K32Write(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpWritten: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'WriteProcessMemory';

const
  // debug event codes
  DE_EXCEPTION       = 1;
  DE_CREATE_PROCESS  = 3;
  DE_EXIT_PROCESS    = 5;
  DE_LOAD_DLL        = 6;

  // status codes
  ST_BREAKPOINT: DWORD  = $80000003;
  ST_SINGLE_STEP: DWORD = $80000004;

  // continue flags
  CONT_CONTINUE: DWORD    = $00010002;   // DBG_CONTINUE
  CONT_NOT_HANDLED: DWORD = $80010001;   // DBG_EXCEPTION_NOT_HANDLED

  // creation flag
  F_DEBUG_ONLY_THIS = $00000002;         // DEBUG_ONLY_THIS_PROCESS

  // x86 CONTEXT flags: CONTROL | INTEGER | SEGMENTS | DEBUG_REGISTERS
  CTX_ALL = $00010017;

  TRAP_FLAG   = $00000100;               // EFLAGS.TF
  DR7_DR0_RW4 = $000F0001;               // DR0 enabled, break on read/write, 4 bytes

  MAX_STUB_STEPS = 64;                   // give up looking for PUSHAD after this
  MAX_OEP_STEPS  = 2000;                 // give up looking for the OEP after this
  MAX_EVENTS     = 200000;               // hard cap on debug-loop iterations

constructor TGenericUnpacker.Create(ALog: TUnpackLog);
begin
  inherited Create;
  FLog := ALog;
end;

procedure TGenericUnpacker.Log(const S: string);
begin
  if Assigned(FLog) then FLog(S);
end;

function TGenericUnpacker.ReadMem(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
var
  got: NativeUInt;
begin
  got := 0;
  Result := K32Read(FProc, Pointer(Addr), @Buf, Size, @got) and (got = Size);
end;

function TGenericUnpacker.WriteMem(Addr: NativeUInt; const Buf; Size: NativeUInt): Boolean;
var
  put: NativeUInt;
begin
  put := 0;
  Result := K32Write(FProc, Pointer(Addr), @Buf, Size, @put) and (put = Size);
end;

function TGenericUnpacker.RByte(Addr: NativeUInt): Byte;
var
  b: Byte;
begin
  b := 0;
  ReadMem(Addr, b, 1);
  Result := b;
end;

procedure TGenericUnpacker.WByte(Addr: NativeUInt; B: Byte);
begin
  // WriteProcessMemory transparently adjusts page protection for us.
  WriteMem(Addr, B, 1);
end;

function TGenericUnpacker.GetCtx(var Ctx: TContext): Boolean;
begin
  FillChar(Ctx, SizeOf(Ctx), 0);
  Ctx.ContextFlags := CTX_ALL;
  Result := GetThreadContext(FThread, Ctx);
end;

function TGenericUnpacker.SetCtx(var Ctx: TContext): Boolean;
begin
  Ctx.ContextFlags := CTX_ALL;
  Result := SetThreadContext(FThread, Ctx);
end;

function TGenericUnpacker.ParseHeaders: Boolean;
var
  hdr: TBytes;
  need, i: Integer;
  machine, magic, numSecs, sizeOpt: Word;
begin
  Result := False;
  SetLength(hdr, 4096);
  if not ReadMem(FBase, hdr[0], 4096) then Exit;

  if PWord(@hdr[0])^ <> $5A4D then Exit;                  // 'MZ'
  FLfanew := PCardinal(@hdr[$3C])^;
  if FLfanew > $10000 then Exit;                          // absurd e_lfanew (malformed/hostile)
  if UInt64(FLfanew) + 256 > UInt64(Length(hdr)) then     // 64-bit compare: cannot wrap
  begin
    SetLength(hdr, FLfanew + 1024);
    if not ReadMem(FBase, hdr[0], Length(hdr)) then Exit;
  end;
  if PCardinal(@hdr[FLfanew])^ <> $00004550 then Exit;    // 'PE'#0#0

  machine := PWord(@hdr[FLfanew + 4])^;
  if machine <> $014C then Exit;                          // i386 only
  FOptOfs := FLfanew + 24;
  magic := PWord(@hdr[FOptOfs])^;
  if magic <> $10B then Exit;                             // PE32 only

  FSizeOfImage   := PCardinal(@hdr[FOptOfs + 56])^;
  FSizeOfHeaders := PCardinal(@hdr[FOptOfs + 60])^;
  if (FSizeOfImage = 0) or (FSizeOfImage > $40000000) then Exit;  // 0 or > 1 GB: malformed
  numSecs        := PWord(@hdr[FLfanew + 6])^;
  sizeOpt        := PWord(@hdr[FLfanew + 20])^;
  FSecTab        := FOptOfs + sizeOpt;
  FNumSecs       := numSecs;

  need := Integer(FSecTab) + numSecs * 40;
  if need > Length(hdr) then
  begin
    SetLength(hdr, need + 64);
    if not ReadMem(FBase, hdr[0], Length(hdr)) then Exit;
  end;

  SetLength(FSecVA, numSecs);
  SetLength(FSecVSize, numSecs);
  SetLength(FSecChar, numSecs);
  for i := 0 to numSecs - 1 do
  begin
    FSecVSize[i] := PCardinal(@hdr[FSecTab + Cardinal(i) * 40 + 8])^;
    FSecVA[i]    := PCardinal(@hdr[FSecTab + Cardinal(i) * 40 + 12])^;
    FSecChar[i]  := PCardinal(@hdr[FSecTab + Cardinal(i) * 40 + 36])^;
  end;
  Result := True;
end;

function TGenericUnpacker.SectionOfRVA(RVA: Cardinal): Integer;
var
  i: Integer;
  vs: Cardinal;
begin
  Result := -1;
  for i := 0 to FNumSecs - 1 do
  begin
    vs := FSecVSize[i];
    if vs = 0 then vs := 1;
    if (RVA >= FSecVA[i]) and (RVA < FSecVA[i] + vs) then Exit(i);
  end;
  // fall back to the section whose VA is the greatest that is <= RVA
  for i := FNumSecs - 1 downto 0 do
    if RVA >= FSecVA[i] then Exit(i);
end;

procedure TGenericUnpacker.SetEntryBP;
begin
  FOrigEntryByte := RByte(FEntry);
  WByte(FEntry, $CC);
  FlushInstructionCache(FProc, Pointer(FEntry), 1);
  if RByte(FEntry) <> $CC then
    Log('Warning: entry breakpoint write did not take; target may run unhooked.');
end;

procedure TGenericUnpacker.RemoveEntryBP(var Ctx: TContext);
begin
  WByte(FEntry, FOrigEntryByte);
  FlushInstructionCache(FProc, Pointer(FEntry), 1);
  Ctx.Eip := FEntry;                       // rewind over the INT3
  Ctx.EFlags := Ctx.EFlags or TRAP_FLAG;   // single-step the real entry instruction
  SetCtx(Ctx);
end;

function TGenericUnpacker.DumpTo(const OutFile: string): Boolean;
var
  buf: TBytes;
  off, chunk, got: NativeUInt;
  i: Integer;
  thisVA, nextVA, rawSize: Cardinal;
  fs: TFileStream;
begin
  Result := False;
  if FSizeOfImage = 0 then Exit;
  try
    SetLength(buf, FSizeOfImage);                // FSizeOfImage is capped in ParseHeaders
  except
    on E: Exception do
    begin
      Log('Dump allocation failed: ' + E.Message);
      Exit;
    end;
  end;

  // capture the whole image out of memory, tolerating uncommitted/guarded pages
  off := 0;
  while off < FSizeOfImage do
  begin
    chunk := 4096;
    if off + chunk > FSizeOfImage then chunk := FSizeOfImage - off;
    got := 0;
    K32Read(FProc, Pointer(FBase + off), @buf[off], chunk, @got);
    Inc(off, chunk);
  end;

  // rewrite headers so the on-disk layout matches the in-memory layout
  PCardinal(@buf[FOptOfs + 28])^ := Cardinal(FBase);              // ImageBase = actual load base
  PCardinal(@buf[FOptOfs + 16])^ := Cardinal(FOEP - FBase);       // AddressOfEntryPoint = OEP RVA
  PCardinal(@buf[FOptOfs + 36])^ := PCardinal(@buf[FOptOfs + 32])^; // FileAlignment := SectionAlignment

  for i := 0 to FNumSecs - 1 do
  begin
    thisVA := FSecVA[i];
    if i < FNumSecs - 1 then nextVA := FSecVA[i + 1] else nextVA := FSizeOfImage;
    if nextVA > thisVA then rawSize := nextVA - thisVA else rawSize := FSecVSize[i];
    PCardinal(@buf[FSecTab + Cardinal(i) * 40 + 16])^ := rawSize;  // SizeOfRawData
    PCardinal(@buf[FSecTab + Cardinal(i) * 40 + 20])^ := thisVA;   // PointerToRawData = RVA
  end;

  try
    fs := TFileStream.Create(OutFile, fmCreate);
    try
      fs.WriteBuffer(buf[0], Length(buf));
    finally
      fs.Free;
    end;
    Result := True;
  except
    on E: Exception do
      Log('Write failed: ' + E.Message);
  end;
end;

function TGenericUnpacker.Unpack(const TargetExe, OutputExe: string): TUnpackResult;
type
  TState = (stEntry, stStub, stPopad, stOEP, stDump);
var
  si: TStartupInfo;
  pi: TProcessInformation;
  de: TDebugEvent;
  ctx: TContext;
  state: TState;
  running: Boolean;
  contFlag: DWORD;
  code: DWORD;
  addr, esp: NativeUInt;
  rva: Cardinal;
  sec, events: Integer;
  b: Byte;
begin
  Result := Default(TUnpackResult);
  FillChar(si, SizeOf(si), 0);
  si.cb := SizeOf(si);
  FillChar(pi, SizeOf(pi), 0);

  if not CreateProcess(PChar(TargetExe), nil, nil, nil, False,
       F_DEBUG_ONLY_THIS, nil, nil, si, pi) then
  begin
    Result.Message := 'CreateProcess failed: ' + SysErrorMessage(GetLastError);
    Exit;
  end;

  FProc := pi.hProcess;
  FThread := pi.hThread;
  state := stEntry;
  running := True;
  events := 0;

  try
    while running do
    begin
      Inc(events);
      if events > MAX_EVENTS then
      begin
        Result.Message := 'Event budget exhausted.';
        Break;
      end;

      if not WaitForDebugEvent(de, 60000) then
      begin
        Result.Message := 'Timed out (possible anti-debug or hang).';
        Break;
      end;

      contFlag := CONT_CONTINUE;

      case de.dwDebugEventCode of
        DE_CREATE_PROCESS:
          begin
            FBase  := NativeUInt(de.CreateProcessInfo.lpBaseOfImage);
            FEntry := NativeUInt(de.CreateProcessInfo.lpStartAddress);
            if de.CreateProcessInfo.hFile <> 0 then
              CloseHandle(de.CreateProcessInfo.hFile);

            if not ParseHeaders then
            begin
              Result.Message := 'Not a 32-bit PE32 image, or headers unreadable.';
              running := False;
            end
            else
            begin
              FStubSec := SectionOfRVA(Cardinal(FEntry - FBase));
              SetEntryBP;
              Log(Format('base=$%x entry=$%x sizeofimage=$%x sections=%d stubsec=%d',
                [FBase, FEntry, FSizeOfImage, FNumSecs, FStubSec]));
            end;
          end;

        DE_LOAD_DLL:
          if de.LoadDll.hFile <> 0 then
            CloseHandle(de.LoadDll.hFile);

        DE_EXIT_PROCESS:
          begin
            if Result.Message = '' then
              Result.Message := 'Target exited before OEP was reached.';
            running := False;
          end;

        DE_EXCEPTION:
          begin
            code := de.Exception.ExceptionRecord.ExceptionCode;
            addr := NativeUInt(de.Exception.ExceptionRecord.ExceptionAddress);

            case state of
              stEntry:
                if (code = ST_BREAKPOINT) and (addr = FEntry) then
                begin
                  if GetCtx(ctx) then
                  begin
                    RemoveEntryBP(ctx);       // restore byte, rewind Eip, set TF
                    FPrevEip := FEntry;
                    FStepCount := 0;
                    state := stStub;
                  end;
                end
                else if code = ST_BREAKPOINT then
                  contFlag := CONT_CONTINUE    // loader / system breakpoint
                else
                  contFlag := CONT_NOT_HANDLED;

              stStub:
                if code = ST_SINGLE_STEP then
                begin
                  b := RByte(FPrevEip);
                  if b = $60 then               // PUSHAD just executed
                  begin
                    if GetCtx(ctx) then
                    begin
                      esp := ctx.Esp;
                      ctx.Dr0 := esp;
                      ctx.Dr7 := DR7_DR0_RW4;
                      ctx.Dr6 := 0;
                      ctx.EFlags := ctx.EFlags and not TRAP_FLAG;  // run full speed to POPAD
                      SetCtx(ctx);
                      Log(Format('PUSHAD found; HW bp armed at saved ESP $%x', [esp]));
                      state := stPopad;
                    end;
                  end
                  else
                  begin
                    Inc(FStepCount);
                    if FStepCount > MAX_STUB_STEPS then
                    begin
                      Result.Message :=
                        'No PUSHAD prologue; ESP trick not applicable (needs guard-page method).';
                      running := False;
                    end
                    else if GetCtx(ctx) then
                    begin
                      FPrevEip := ctx.Eip;
                      ctx.EFlags := ctx.EFlags or TRAP_FLAG;
                      SetCtx(ctx);
                    end;
                  end;
                end
                else
                  contFlag := CONT_NOT_HANDLED;

              stPopad:
                if code = ST_SINGLE_STEP then
                begin
                  if GetCtx(ctx) then
                  begin
                    if (ctx.Dr6 and $1) <> 0 then      // DR0 fired: POPAD read the block
                    begin
                      ctx.Dr0 := 0;
                      ctx.Dr7 := 0;
                      ctx.Dr6 := 0;
                      ctx.EFlags := ctx.EFlags or TRAP_FLAG;  // step toward OEP
                      SetCtx(ctx);
                      FOepSteps := 0;
                      state := stOEP;
                      Log('POPAD reached; stepping to OEP...');
                    end
                    else
                    begin
                      ctx.EFlags := ctx.EFlags and not TRAP_FLAG;
                      SetCtx(ctx);
                    end;
                  end;
                end
                else
                  contFlag := CONT_NOT_HANDLED;

              stOEP:
                if code = ST_SINGLE_STEP then
                begin
                  if GetCtx(ctx) then
                  begin
                    rva := Cardinal(ctx.Eip - FBase);
                    sec := SectionOfRVA(rva);
                    if (ctx.Eip >= FBase) and (ctx.Eip < FBase + FSizeOfImage) and
                       (sec >= 0) and (sec <> FStubSec) and
                       ((FSecChar[sec] and $20000000) <> 0) then    // executable section
                    begin
                      FOEP := ctx.Eip;
                      Log(Format('OEP at $%x (RVA $%x, section %d)', [FOEP, rva, sec]));
                      state := stDump;
                      running := False;          // stop WITHOUT resuming the payload
                    end
                    else
                    begin
                      Inc(FOepSteps);
                      if FOepSteps > MAX_OEP_STEPS then
                      begin
                        Result.Message := 'OEP not located within step budget.';
                        running := False;
                      end
                      else
                      begin
                        ctx.EFlags := ctx.EFlags or TRAP_FLAG;
                        SetCtx(ctx);
                      end;
                    end;
                  end;
                end
                else
                  contFlag := CONT_NOT_HANDLED;
            end; // case state
          end;
      end; // case event

      // If we reached the OEP, dump now and leave the target frozen.
      if (not running) and (state = stDump) then
      begin
        if DumpTo(OutputExe) then
        begin
          Result.Success   := True;
          Result.Message   := 'Unpacked image dumped.';
          Result.ImageBase := FBase;
          Result.OEPVA     := FOEP;
          Result.OEPRVA    := Cardinal(FOEP - FBase);
          Result.DumpFile  := OutputExe;
        end
        else if Result.Message = '' then
          Result.Message := 'Dump failed.';
        Break;                                   // do not ContinueDebugEvent -> payload never runs
      end;

      ContinueDebugEvent(de.dwProcessId, de.dwThreadId, contFlag);
    end; // while
  finally
    if FProc <> 0 then
      TerminateProcess(FProc, 0);
    if pi.hThread <> 0 then CloseHandle(pi.hThread);
    if pi.hProcess <> 0 then CloseHandle(pi.hProcess);
  end;
end;

end.
