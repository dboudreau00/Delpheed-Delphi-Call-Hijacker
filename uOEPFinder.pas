unit uOEPFinder;

{
  uOEPFinder - find the Original Entry Point of a packed 32-bit PE by page
  permissions instead of the ESP trick, so it works on stubs that do NOT begin
  with PUSHAD.

  Idea
  ----
  A stub decompresses the real code into memory, then jumps to the OEP. If we
  remove EXECUTE permission from every section except the stub's own, the stub
  can still READ and WRITE those pages while unpacking (no fault), but the very
  first attempt to EXECUTE in one of them - the jump to OEP - trips DEP and
  raises an access violation whose faulting address is the OEP. Exactly one
  fault, no single-stepping.

    1. Launch the target under the debugger, break at the stub entry.
    2. Set every non-stub section to PAGE_READWRITE (executable bit cleared).
    3. Run at full speed.
    4. Catch EXCEPTION_ACCESS_VIOLATION with access type = execute (8); if the
       faulting address is inside the image and outside the stub section, that
       address is the OEP.
    5. Optionally dump the now-unpacked image (same layout fix-up as uUnpacker).

  Requires DEP to be enforced for the target - the default for 32-bit processes
  on 64-bit Windows. Build and run this 32-bit.

  Complements uUnpacker (the ESP trick): use that when the stub starts with
  PUSHAD, use this when it does not.

  Limits: a stub that calls VirtualProtect to re-grant execute on the OEP
  section before jumping will not fault (no detection); code unpacked into a
  fresh VirtualAlloc region rather than back into the image runs outside the
  image and is not what gets dumped; and a stub whose helper code runs in a
  second section will fault there first (add it via ExtraStubSections).

  WARNING: this executes the target's stub. Untrusted samples in a VM only.
}

{$WARN SYMBOL_PLATFORM OFF}

{$IF Defined(WIN64)}
  {$MESSAGE WARN 'Compile this 32-bit (dcc32) to analyse 32-bit targets.'}
{$IFEND}

interface

uses
  Windows, SysUtils, Classes, uAntiAntiDebug, uIATRebuild;

type
  TOEPLog = reference to procedure(const Msg: string);

  TOEPResult = record
    Success: Boolean;
    Message: string;
    ImageBase: NativeUInt;
    OEPRVA: Cardinal;
    OEPVA: NativeUInt;
    DumpFile: string;         // '' when no dump was requested
  end;

  TOEPFinder = class
  private
    FLog: TOEPLog;
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
    FExtraStub: TArray<Integer>;
    FOrigEntryByte: Byte;
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
    function IsStubSection(Idx: Integer): Boolean;
    procedure StripExecuteFromNonStub;
    function DumpTo(const OutFile: string): Boolean;
  public
    // Set these before calling Find:
    AntiAntiDebug: Boolean;   // patch PEB / hook ntdll to hide the debugger
    RebuildImports: Boolean;  // after dumping, reconstruct the import table
    constructor Create(ALog: TOEPLog = nil);
    // ExtraStubSections: indices of any additional sections the stub executes
    // from (kept executable). Usually leave empty.
    procedure SetExtraStubSections(const Indices: array of Integer);
    function Find(const TargetExe: string; const DumpFile: string = ''): TOEPResult;
  end;

implementation

function K32Read(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpRead: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'ReadProcessMemory';
function K32Write(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpWritten: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'WriteProcessMemory';
function K32Protect(hProcess: THandle; lpAddress: Pointer; dwSize: NativeUInt;
  flNewProtect: DWORD; lpOld: PDWORD): BOOL; stdcall;
  external kernel32 name 'VirtualProtectEx';

const
  DE_EXCEPTION      = 1;
  DE_CREATE_PROCESS = 3;
  DE_EXIT_PROCESS   = 5;
  DE_LOAD_DLL       = 6;

  ST_BREAKPOINT: DWORD       = $80000003;
  ST_ACCESS_VIOLATION: DWORD = $C0000005;
  ST_GUARD_PAGE: DWORD       = $80000001;

  CONT_CONTINUE: DWORD    = $00010002;
  CONT_NOT_HANDLED: DWORD = $80010001;

  F_DEBUG_ONLY_THIS = $00000002;
  CTX_ALL           = $00010017;   // CONTROL | INTEGER | SEGMENTS | DEBUG
  TRAP_FLAG         = $00000100;

  ACCESS_EXECUTE = 8;              // ExceptionInformation[0] value for a DEP fault
  PAGE_SIZE      = $1000;
  SCN_EXECUTE    = $20000000;

  MAX_EVENTS = 200000;

constructor TOEPFinder.Create(ALog: TOEPLog);
begin
  inherited Create;
  FLog := ALog;
end;

procedure TOEPFinder.SetExtraStubSections(const Indices: array of Integer);
var
  i: Integer;
begin
  SetLength(FExtraStub, Length(Indices));
  for i := 0 to High(Indices) do
    FExtraStub[i] := Indices[i];
end;

procedure TOEPFinder.Log(const S: string);
begin
  if Assigned(FLog) then FLog(S);
end;

function TOEPFinder.ReadMem(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
var
  got: NativeUInt;
begin
  got := 0;
  Result := K32Read(FProc, Pointer(Addr), @Buf, Size, @got) and (got = Size);
end;

function TOEPFinder.WriteMem(Addr: NativeUInt; const Buf; Size: NativeUInt): Boolean;
var
  put: NativeUInt;
begin
  put := 0;
  Result := K32Write(FProc, Pointer(Addr), @Buf, Size, @put) and (put = Size);
end;

function TOEPFinder.RByte(Addr: NativeUInt): Byte;
var
  b: Byte;
begin
  b := 0;
  ReadMem(Addr, b, 1);
  Result := b;
end;

procedure TOEPFinder.WByte(Addr: NativeUInt; B: Byte);
begin
  WriteMem(Addr, B, 1);
end;

function TOEPFinder.GetCtx(var Ctx: TContext): Boolean;
begin
  FillChar(Ctx, SizeOf(Ctx), 0);
  Ctx.ContextFlags := CTX_ALL;
  Result := GetThreadContext(FThread, Ctx);
end;

function TOEPFinder.SetCtx(var Ctx: TContext): Boolean;
begin
  Ctx.ContextFlags := CTX_ALL;
  Result := SetThreadContext(FThread, Ctx);
end;

function TOEPFinder.ParseHeaders: Boolean;
var
  hdr: TBytes;
  need, i: Integer;
  machine, magic, numSecs, sizeOpt: Word;
begin
  Result := False;
  SetLength(hdr, 4096);
  if not ReadMem(FBase, hdr[0], 4096) then Exit;

  if PWord(@hdr[0])^ <> $5A4D then Exit;
  FLfanew := PCardinal(@hdr[$3C])^;
  if FLfanew + 256 > Cardinal(Length(hdr)) then
  begin
    SetLength(hdr, FLfanew + 1024);
    if not ReadMem(FBase, hdr[0], Length(hdr)) then Exit;
  end;
  if PCardinal(@hdr[FLfanew])^ <> $00004550 then Exit;

  machine := PWord(@hdr[FLfanew + 4])^;
  if machine <> $014C then Exit;
  FOptOfs := FLfanew + 24;
  magic := PWord(@hdr[FOptOfs])^;
  if magic <> $10B then Exit;

  FSizeOfImage   := PCardinal(@hdr[FOptOfs + 56])^;
  FSizeOfHeaders := PCardinal(@hdr[FOptOfs + 60])^;
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

function TOEPFinder.SectionOfRVA(RVA: Cardinal): Integer;
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
  for i := FNumSecs - 1 downto 0 do
    if RVA >= FSecVA[i] then Exit(i);
end;

function TOEPFinder.IsStubSection(Idx: Integer): Boolean;
var
  i: Integer;
begin
  Result := (Idx = FStubSec);
  if Result then Exit;
  for i := 0 to High(FExtraStub) do
    if FExtraStub[i] = Idx then Exit(True);
end;

procedure TOEPFinder.StripExecuteFromNonStub;
var
  i: Integer;
  addr: NativeUInt;
  size, old: DWORD;
begin
  for i := 0 to FNumSecs - 1 do
  begin
    if IsStubSection(i) then Continue;
    addr := FBase + FSecVA[i];
    size := FSecVSize[i];
    if size = 0 then size := PAGE_SIZE;
    size := (size + PAGE_SIZE - 1) and not (PAGE_SIZE - 1);   // round up to page
    old := 0;
    // read+write but NOT execute -> unpacking writes are fine, execution faults
    if not K32Protect(FProc, Pointer(addr), size, PAGE_READWRITE, @old) then
      Log(Format('VirtualProtectEx failed on section %d (err %d)', [i, GetLastError]));
  end;
  Log('Execute permission stripped from non-stub sections.');
end;

function TOEPFinder.DumpTo(const OutFile: string): Boolean;
var
  buf: TBytes;
  off, chunk, got, total: NativeUInt;
  i: Integer;
  thisVA, nextVA, rawSize: Cardinal;
  fs: TFileStream;
begin
  Result := False;
  if FSizeOfImage = 0 then Exit;
  SetLength(buf, FSizeOfImage);

  off := 0; total := 0;
  while off < FSizeOfImage do
  begin
    chunk := 4096;
    if off + chunk > FSizeOfImage then chunk := FSizeOfImage - off;
    got := 0;
    K32Read(FProc, Pointer(FBase + off), @buf[off], chunk, @got);
    Inc(total, got);
    Inc(off, chunk);
  end;
  if total = 0 then
    Log('Warning: no image memory could be read; dump will be empty.');

  PCardinal(@buf[FOptOfs + 28])^ := Cardinal(FBase);
  PCardinal(@buf[FOptOfs + 16])^ := Cardinal(FOEP - FBase);
  PCardinal(@buf[FOptOfs + 36])^ := PCardinal(@buf[FOptOfs + 32])^;

  for i := 0 to FNumSecs - 1 do
  begin
    thisVA := FSecVA[i];
    if i < FNumSecs - 1 then nextVA := FSecVA[i + 1] else nextVA := FSizeOfImage;
    if nextVA > thisVA then rawSize := nextVA - thisVA else rawSize := FSecVSize[i];
    PCardinal(@buf[FSecTab + Cardinal(i) * 40 + 16])^ := rawSize;
    PCardinal(@buf[FSecTab + Cardinal(i) * 40 + 20])^ := thisVA;
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

function TOEPFinder.Find(const TargetExe, DumpFile: string): TOEPResult;
type
  TState = (stEntry, stRun, stDone);
var
  si: TStartupInfo;
  pi: TProcessInformation;
  de: TDebugEvent;
  ctx: TContext;
  state: TState;
  running: Boolean;
  contFlag, code: DWORD;
  addr, faultAddr: NativeUInt;
  access: NativeUInt;
  rva: Cardinal;
  sec, events: Integer;
begin
  Result := Default(TOEPResult);
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
              FOrigEntryByte := RByte(FEntry);
              WByte(FEntry, $CC);
              FlushInstructionCache(FProc, Pointer(FEntry), 1);
              if RByte(FEntry) <> $CC then
              begin
                Result.Message := 'Could not set entry breakpoint (write to target failed).';
                running := False;
              end;
              Log(Format('base=$%x entry=$%x sizeofimage=$%x sections=%d stubsec=%d',
                [FBase, FEntry, FSizeOfImage, FNumSecs, FStubSec]));
              if AntiAntiDebug then
              begin
                var aad := TAntiAntiDebug.Create(FProc,
                  procedure(const m: string) begin Log('AAD: ' + m); end);
                try
                  aad.Apply;
                finally
                  aad.Free;
                end;
              end;
            end;
          end;

        DE_LOAD_DLL:
          if de.LoadDll.hFile <> 0 then
            CloseHandle(de.LoadDll.hFile);

        DE_EXIT_PROCESS:
          begin
            if Result.Message = '' then
              Result.Message :=
                'Target exited before an OEP fault. DEP may be disabled, or the ' +
                'stub re-granted execute / unpacked outside the image.';
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
                    WByte(FEntry, FOrigEntryByte);   // restore real instruction
                    FlushInstructionCache(FProc, Pointer(FEntry), 1);
                    ctx.Eip := FEntry;               // rewind over the INT3
                    ctx.EFlags := ctx.EFlags and not TRAP_FLAG;   // run full speed
                    SetCtx(ctx);
                    StripExecuteFromNonStub;
                    state := stRun;
                  end;
                end
                else if code = ST_BREAKPOINT then
                  contFlag := CONT_CONTINUE            // loader / system breakpoint
                else
                  contFlag := CONT_NOT_HANDLED;

              stRun:
                if (code = ST_ACCESS_VIOLATION) or (code = ST_GUARD_PAGE) then
                begin
                  access := 0;
                  faultAddr := 0;
                  if de.Exception.ExceptionRecord.NumberParameters >= 2 then
                  begin
                    access    := de.Exception.ExceptionRecord.ExceptionInformation[0];
                    faultAddr := de.Exception.ExceptionRecord.ExceptionInformation[1];
                  end;

                  if (access = ACCESS_EXECUTE) and
                     (faultAddr >= FBase) and (faultAddr < FBase + FSizeOfImage) then
                  begin
                    rva := Cardinal(faultAddr - FBase);
                    sec := SectionOfRVA(rva);
                    if (sec >= 0) and (not IsStubSection(sec)) then
                    begin
                      FOEP := faultAddr;
                      Log(Format('OEP at $%x (RVA $%x, section %d)', [FOEP, rva, sec]));
                      state := stDone;
                      running := False;               // freeze here, do not resume
                    end
                    else
                      contFlag := CONT_NOT_HANDLED;    // execute fault inside stub: pass
                  end
                  else
                    contFlag := CONT_NOT_HANDLED;      // read/write fault or outside image
                end
                else
                  contFlag := CONT_NOT_HANDLED;
            end; // case state
          end;
      end; // case event

      if (not running) and (state = stDone) then
      begin
        Result.ImageBase := FBase;
        Result.OEPVA     := FOEP;
        Result.OEPRVA    := Cardinal(FOEP - FBase);
        Result.Success   := True;
        Result.Message   := 'OEP located.';
        if DumpFile <> '' then
        begin
          if DumpTo(DumpFile) then
          begin
            Result.DumpFile := DumpFile;
            Result.Message  := 'OEP located and image dumped.';
            if RebuildImports then
            begin
              var fixed := ChangeFileExt(DumpFile, '') + '_fixed.exe';
              var rb := TIATRebuilder.Create(FProc,
                procedure(const m: string) begin Log('IAT: ' + m); end);
              try
                if rb.RebuildImports(DumpFile, fixed).Success then
                  Result.Message := Result.Message + ' Imports rebuilt: ' + fixed;
              finally
                rb.Free;
              end;
            end;
          end
          else
            Result.Message := 'OEP located, but dump failed.';
        end;
        Break;                                       // do not resume the payload
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
