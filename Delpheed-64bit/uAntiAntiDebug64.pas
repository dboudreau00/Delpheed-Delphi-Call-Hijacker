unit uAntiAntiDebug64;

{
  uAntiAntiDebug64 - 64-bit anti-anti-debug. The x64 counterpart of uAntiAntiDebug.

  Two layers, same intent as x86 but with the x64 differences:

  1. PEB / heap patching (reliable):
       * PEB.BeingDebugged (+0x02) -> 0
       * PEB.NtGlobalFlag  (+0xBC) -> clear 0x70      (x64 offset, not 0x68)
       * ProcessHeap (+0x30) Flags/ForceFlags (+0x70/+0x74) -> cleared

  2. ntdll inline hooks - harder on x64 and done conservatively:
       * The syscall stub begins `mov r10, rcx` (4C 8B D1) then `mov eax, imm32`,
         and a near jump (E9 rel32) cannot reach an arbitrary code cave, so the
         patch is a 14-byte absolute jump (FF 25 ... + qword) over the first 16
         bytes. Those 16 bytes (mov r10,rcx / mov eax,ssn / test byte [abs],1)
         are position-independent on modern Windows, so they relocate cleanly.
       * The hook is installed ONLY if the prologue matches that modern pattern;
         otherwise it is skipped (PEB patching still applies). This avoids a bad
         patch on an unexpected/older stub.
       * x64 passes arguments in registers, so the filter reads RDX (class) and
         R8 (out buffer) directly - cleaner than the x86 stack math.

     Hooks: NtSetInformationThread (neutralise ThreadHideFromDebugger) and
     NtQueryInformationProcess (spoof the debug-info classes).

  Build 64-bit. Untrusted samples in a VM only.
}

{$WARN SYMBOL_PLATFORM OFF}

interface

uses
  Windows, SysUtils;

type
  TAAD64Log = reference to procedure(const Msg: string);

  TAntiAntiDebug64 = class
  private
    FProc: THandle;
    FLog: TAAD64Log;
    procedure Log(const S: string);
    function RPM(Addr: UInt64; var Buf; Size: NativeUInt): Boolean;
    function WPM(Addr: UInt64; const Buf; Size: NativeUInt): Boolean;
    function RU32(Addr: UInt64): Cardinal;
    function RU64(Addr: UInt64): UInt64;
    procedure PatchPEB;
    function StubHideThread(FnAddr: UInt64; const Orig: TBytes; Cave: UInt64): TBytes;
    function StubQueryProc(FnAddr: UInt64; const Orig: TBytes; Cave: UInt64): TBytes;
    function InstallHook(const FnName: string; QueryProc: Boolean): Boolean;
  public
    constructor Create(hProcess: THandle; ALog: TAAD64Log = nil);
    function Apply: Boolean;
  end;

implementation

function K32Read(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpRead: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'ReadProcessMemory';
function K32Write(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpWritten: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'WriteProcessMemory';

function NtQueryInformationProcess(ProcessHandle: THandle; InfoClass: DWORD;
  ProcessInformation: Pointer; Len: ULONG; ReturnLength: PULONG): LONG; stdcall;
  external 'ntdll.dll';

type
  TProcessBasicInformation = record
    ExitStatus: LONG;
    PebBaseAddress: Pointer;
    AffinityMask: NativeUInt;
    BasePriority: LONG;
    UniqueProcessId: NativeUInt;
    InheritedFromUniqueProcessId: NativeUInt;
  end;

constructor TAntiAntiDebug64.Create(hProcess: THandle; ALog: TAAD64Log);
begin
  inherited Create;
  FProc := hProcess;
  FLog := ALog;
end;

procedure TAntiAntiDebug64.Log(const S: string);
begin
  if Assigned(FLog) then FLog(S);
end;

function TAntiAntiDebug64.RPM(Addr: UInt64; var Buf; Size: NativeUInt): Boolean;
var
  n: NativeUInt;
begin
  n := 0;
  Result := K32Read(FProc, Pointer(Addr), @Buf, Size, @n) and (n = Size);
end;

function TAntiAntiDebug64.WPM(Addr: UInt64; const Buf; Size: NativeUInt): Boolean;
var
  n: NativeUInt;
begin
  n := 0;
  Result := K32Write(FProc, Pointer(Addr), @Buf, Size, @n) and (n = Size);
end;

function TAntiAntiDebug64.RU32(Addr: UInt64): Cardinal;
begin
  Result := 0;
  RPM(Addr, Result, 4);
end;

function TAntiAntiDebug64.RU64(Addr: UInt64): UInt64;
begin
  Result := 0;
  RPM(Addr, Result, 8);
end;

procedure TAntiAntiDebug64.PatchPEB;
var
  pbi: TProcessBasicInformation;
  retLen: ULONG;
  peb, heap: UInt64;
  b: Byte;
  v: Cardinal;
begin
  retLen := 0;
  if NtQueryInformationProcess(FProc, 0, @pbi, SizeOf(pbi), @retLen) <> 0 then
  begin
    Log('PEB query failed; skipping PEB patch.');
    Exit;
  end;
  peb := UInt64(pbi.PebBaseAddress);
  if peb = 0 then Exit;

  b := 0;
  if not WPM(peb + $02, b, 1) then Log('Could not clear BeingDebugged.');

  v := RU32(peb + $BC);                          // NtGlobalFlag (x64 offset)
  v := v and not Cardinal($70);
  if not WPM(peb + $BC, v, 4) then Log('Could not clear NtGlobalFlag.');

  heap := RU64(peb + $30);                        // ProcessHeap (x64 offset)
  if heap <> 0 then
  begin
    v := RU32(heap + $70);                        // Heap.Flags (x64)
    v := v and not Cardinal($20 or $40 or $40000000);
    WPM(heap + $70, v, 4);
    v := 0;
    WPM(heap + $74, v, 4);                         // Heap.ForceFlags (x64)
  end;

  Log('PEB patched (BeingDebugged, NtGlobalFlag, heap flags).');
end;

function TAntiAntiDebug64.StubHideThread(FnAddr: UInt64; const Orig: TBytes;
  Cave: UInt64): TBytes;
var
  s: TBytes;
  len, pj, i: Integer;
  procedure DB(V: Byte); begin s[len] := V; Inc(len); end;
  procedure DQ(V: UInt64); begin PUInt64(@s[len])^ := V; Inc(len, 8); end;
begin
  SetLength(s, 96);
  len := 0;
  DB($83); DB($FA); DB($11);                      // cmp edx, 11h  (ThreadHideFromDebugger)
  DB($75); pj := len; DB(0);                      // jne do_orig
  DB($33); DB($C0);                               // xor eax, eax
  DB($C3);                                        // ret
  s[pj] := Byte(len - (pj + 1));                  // do_orig here
  for i := 0 to 15 do DB(Orig[i]);               // stolen 16 (mov r10,rcx / mov eax,ssn / test)
  DB($FF); DB($25); DB(0); DB(0); DB(0); DB(0);   // jmp qword ptr [rip+0]
  DQ(FnAddr + 16);
  SetLength(s, len);
  Result := s;
end;

function TAntiAntiDebug64.StubQueryProc(FnAddr: UInt64; const Orig: TBytes;
  Cave: UInt64): TBytes;
var
  s: TBytes;
  len, i: Integer;
  pPort, pObj, pFlags, q: Integer;
  procedure DB(V: Byte); begin s[len] := V; Inc(len); end;
  procedure DQ(V: UInt64); begin PUInt64(@s[len])^ := V; Inc(len, 8); end;
  procedure P8(At: Integer); begin s[At] := Byte(len - (At + 1)); end;
begin
  SetLength(s, 256);
  len := 0;

  DB($8B); DB($C2);                              // mov eax, edx  (InfoClass)
  DB($83); DB($F8); DB($07);                     // cmp eax, 7
  DB($74); pPort := len; DB(0);                  // je Lport
  DB($83); DB($F8); DB($1E);                     // cmp eax, 1Eh
  DB($74); pObj := len; DB(0);                   // je Lobj
  DB($83); DB($F8); DB($1F);                     // cmp eax, 1Fh
  DB($74); pFlags := len; DB(0);                 // je Lflags
  for i := 0 to 15 do DB(Orig[i]);               // default: stolen prologue
  DB($FF); DB($25); DB(0); DB(0); DB(0); DB(0);
  DQ(FnAddr + 16);

  P8(pPort);                                     // Lport
  DB($4D); DB($85); DB($C0);                     // test r8, r8
  DB($74); q := len; DB(0);                      // je pdone
  DB($49); DB($C7); DB($00); DB(0); DB(0); DB(0); DB(0);  // mov qword [r8], 0
  P8(q);
  DB($33); DB($C0); DB($C3);                     // xor eax,eax / ret

  P8(pObj);                                      // Lobj
  DB($4D); DB($85); DB($C0);
  DB($74); q := len; DB(0);
  DB($49); DB($C7); DB($00); DB(0); DB(0); DB(0); DB(0);
  P8(q);
  DB($B8); DB($53); DB($03); DB($00); DB($C0);   // mov eax, 0C0000353h
  DB($C3);

  P8(pFlags);                                    // Lflags
  DB($4D); DB($85); DB($C0);
  DB($74); q := len; DB(0);
  DB($41); DB($C7); DB($00); DB($01); DB(0); DB(0); DB(0);  // mov dword [r8], 1
  P8(q);
  DB($33); DB($C0); DB($C3);

  SetLength(s, len);
  Result := s;
end;

function TAntiAntiDebug64.InstallHook(const FnName: string; QueryProc: Boolean): Boolean;
var
  hNt: HMODULE;
  fn: Pointer;
  fnAddr, cave: UInt64;
  orig, stub, patch: TBytes;
begin
  Result := False;
  hNt := GetModuleHandle('ntdll.dll');
  if hNt = 0 then Exit;
  fn := GetProcAddress(hNt, PAnsiChar(AnsiString(FnName)));
  if fn = nil then Exit;
  fnAddr := UInt64(fn);

  SetLength(orig, 16);
  if not RPM(fnAddr, orig[0], 16) then Exit;
  // require the modern x64 syscall-stub prologue:
  //   4C 8B D1              mov r10, rcx
  //   B8 ?? ?? ?? ??        mov eax, imm32
  //   F6 04 25 ?? ?? ?? ??  test byte ptr [abs], imm8
  if (orig[0] <> $4C) or (orig[1] <> $8B) or (orig[2] <> $D1) or
     (orig[3] <> $B8) or (orig[8] <> $F6) or (orig[9] <> $04) or (orig[10] <> $25) then
  begin
    Log(FnName + ': unexpected prologue, hook skipped.');
    Exit;
  end;

  cave := UInt64(VirtualAllocEx(FProc, nil, 512,
    MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  if cave = 0 then
  begin
    Log(FnName + ': cave allocation failed.');
    Exit;
  end;

  if QueryProc then
    stub := StubQueryProc(fnAddr, orig, cave)
  else
    stub := StubHideThread(fnAddr, orig, cave);

  if not WPM(cave, stub[0], Length(stub)) then Exit;

  // 14-byte absolute jump to the cave, padded to 16 with NOPs
  SetLength(patch, 16);
  patch[0] := $FF; patch[1] := $25;
  patch[2] := 0; patch[3] := 0; patch[4] := 0; patch[5] := 0;
  PUInt64(@patch[6])^ := cave;
  patch[14] := $90; patch[15] := $90;
  if not WPM(fnAddr, patch[0], 16) then Exit;
  FlushInstructionCache(FProc, Pointer(fnAddr), 16);

  Log(FnName + ': hooked.');
  Result := True;
end;

function TAntiAntiDebug64.Apply: Boolean;
begin
  PatchPEB;
  InstallHook('NtSetInformationThread', False);
  InstallHook('NtQueryInformationProcess', True);
  Result := True;
end;

end.
