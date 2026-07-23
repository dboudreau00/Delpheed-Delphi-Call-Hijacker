unit uAntiAntiDebug;

{
  uAntiAntiDebug - hide our debugger from a target that tries to detect it, so
  the OEP finder / unpacker survive against protectors (ScyllaHide-lite).

  Applied once, at process create, before the stub runs. Two layers:

  1. PEB / heap patching (reliable, low risk):
       * PEB.BeingDebugged  (+0x02) -> 0   defeats IsDebuggerPresent
       * PEB.NtGlobalFlag   (+0x68) -> clear 0x70   defeats the NtGlobalFlag check
       * ProcessHeap Flags/ForceFlags -> cleared   defeats heap-flag checks

  2. ntdll inline hooks (write a 5-byte jmp over a syscall stub into a code cave):
       * NtSetInformationThread : neutralise ThreadHideFromDebugger (0x11) so the
         target cannot detach its own thread and go dark on us - the single most
         important hook for keeping the debug session alive.
       * NtQueryInformationProcess : spoof the debug-info classes (ProcessDebugPort
         7, ProcessDebugObjectHandle 0x1E, ProcessDebugFlags 0x1F) to "not debugged".

  32-bit target, 32-bit build. Heap offsets and the syscall-stub prologue (a 5-byte
  "mov eax, imm32") are the x86 Win7+ shape; if the prologue is not that, the hook
  is skipped rather than risking a bad patch.

  Assumes ntdll loads at the same base in the target as in this process (true on a
  given boot for system DLLs); the prologue is validated by reading it back from the
  target before patching, which catches a base mismatch.
}

{$WARN SYMBOL_PLATFORM OFF}

interface

uses
  Windows, SysUtils;

type
  TAADLog = reference to procedure(const Msg: string);

  TAntiAntiDebug = class
  private
    FProc: THandle;
    FLog: TAADLog;
    procedure Log(const S: string);
    function RPM(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
    function WPM(Addr: NativeUInt; const Buf; Size: NativeUInt): Boolean;
    function RU32(Addr: NativeUInt): Cardinal;
    procedure PatchPEB;
    function StubHideThread(FnAddr: NativeUInt; const Orig: TBytes; Cave: NativeUInt): TBytes;
    function StubQueryProc(FnAddr: NativeUInt; const Orig: TBytes; Cave: NativeUInt): TBytes;
    function InstallHook(const FnName: string; QueryProc: Boolean): Boolean;
  public
    constructor Create(hProcess: THandle; ALog: TAADLog = nil);
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

constructor TAntiAntiDebug.Create(hProcess: THandle; ALog: TAADLog);
begin
  inherited Create;
  FProc := hProcess;
  FLog := ALog;
end;

procedure TAntiAntiDebug.Log(const S: string);
begin
  if Assigned(FLog) then FLog(S);
end;

function TAntiAntiDebug.RPM(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
var
  n: NativeUInt;
begin
  n := 0;
  Result := K32Read(FProc, Pointer(Addr), @Buf, Size, @n) and (n = Size);
end;

function TAntiAntiDebug.WPM(Addr: NativeUInt; const Buf; Size: NativeUInt): Boolean;
var
  n: NativeUInt;
begin
  n := 0;
  Result := K32Write(FProc, Pointer(Addr), @Buf, Size, @n) and (n = Size);
end;

function TAntiAntiDebug.RU32(Addr: NativeUInt): Cardinal;
begin
  Result := 0;
  RPM(Addr, Result, 4);
end;

procedure TAntiAntiDebug.PatchPEB;
var
  pbi: TProcessBasicInformation;
  retLen: ULONG;
  peb, heap: NativeUInt;
  b: Byte;
  v: Cardinal;
begin
  retLen := 0;
  if NtQueryInformationProcess(FProc, 0, @pbi, SizeOf(pbi), @retLen) <> 0 then
  begin
    Log('PEB query failed; skipping PEB patch.');
    Exit;
  end;
  peb := NativeUInt(pbi.PebBaseAddress);
  if peb = 0 then Exit;

  b := 0;
  if not WPM(peb + $02, b, 1) then Log('Could not clear BeingDebugged.');

  v := RU32(peb + $68);
  v := v and not Cardinal($70);
  if not WPM(peb + $68, v, 4) then Log('Could not clear NtGlobalFlag.');

  heap := RU32(peb + $18);
  if heap <> 0 then
  begin
    v := RU32(heap + $40);
    v := v and not Cardinal($20 or $40 or $40000000);   // tail/free/validate checks
    WPM(heap + $40, v, 4);
    v := 0;
    WPM(heap + $44, v, 4);                                // ForceFlags = 0
  end;

  Log('PEB patched (BeingDebugged, NtGlobalFlag, heap flags).');
end;

function TAntiAntiDebug.StubHideThread(FnAddr: NativeUInt; const Orig: TBytes;
  Cave: NativeUInt): TBytes;
var
  s: TBytes;
  len, pj, i: Integer;
  procedure DB(V: Byte);
  begin
    s[len] := V; Inc(len);
  end;
begin
  SetLength(s, 64);
  len := 0;
  DB($83); DB($7C); DB($24); DB($08); DB($11);   // cmp dword ptr [esp+8], 11h  (ThreadHideFromDebugger)
  DB($75); DB($05);                              // jne +5
  DB($33); DB($C0);                              // xor eax, eax   (STATUS_SUCCESS)
  DB($C2); DB($10); DB($00);                     // ret 10h
  for i := 0 to 4 do DB(Orig[i]);                // stolen prologue (mov eax, imm32)
  DB($E9); pj := len; DB(0); DB(0); DB(0); DB(0);// jmp FnAddr+5
  PCardinal(@s[pj])^ := Cardinal((FnAddr + 5) - (Cave + NativeUInt(pj) + 4));
  SetLength(s, len);
  Result := s;
end;

function TAntiAntiDebug.StubQueryProc(FnAddr: NativeUInt; const Orig: TBytes;
  Cave: NativeUInt): TBytes;
var
  s: TBytes;
  len, i: Integer;
  pPort, pObj, pFlags, pJmp, q: Integer;
  procedure DB(V: Byte);
  begin
    s[len] := V; Inc(len);
  end;
  procedure Patch8(At: Integer);
  begin
    s[At] := Byte(len - (At + 1));   // rel8 = target(now) - end-of-jcc
  end;
begin
  SetLength(s, 256);
  len := 0;

  DB($8B); DB($44); DB($24); DB($08);            // mov eax, [esp+8]   (InfoClass)
  DB($83); DB($F8); DB($07);                     // cmp eax, 7         (ProcessDebugPort)
  DB($74); pPort := len; DB(0);                  // je Lport
  DB($83); DB($F8); DB($1E);                     // cmp eax, 1Eh       (DebugObjectHandle)
  DB($74); pObj := len; DB(0);                   // je Lobj
  DB($83); DB($F8); DB($1F);                     // cmp eax, 1Fh       (DebugFlags)
  DB($74); pFlags := len; DB(0);                 // je Lflags
  for i := 0 to 4 do DB(Orig[i]);                // default: stolen prologue
  DB($E9); pJmp := len; DB(0); DB(0); DB(0); DB(0); // jmp FnAddr+5

  // Lport: zero the out handle, return STATUS_SUCCESS
  Patch8(pPort);
  DB($8B); DB($4C); DB($24); DB($0C);            // mov ecx, [esp+0Ch] (out ptr)
  DB($85); DB($C9); DB($74); q := len; DB(0);    // test ecx,ecx / je +6
  DB($C7); DB($01); DB(0); DB(0); DB(0); DB(0);  // mov dword ptr [ecx], 0
  Patch8(q);
  DB($8B); DB($4C); DB($24); DB($14);            // mov ecx, [esp+14h] (ReturnLength)
  DB($85); DB($C9); DB($74); q := len; DB(0);
  DB($C7); DB($01); DB(4); DB(0); DB(0); DB(0);  // mov dword ptr [ecx], 4
  Patch8(q);
  DB($33); DB($C0);                              // xor eax, eax
  DB($C2); DB($14); DB($00);                     // ret 14h

  // Lobj: zero the out handle, return STATUS_PORT_NOT_SET
  Patch8(pObj);
  DB($8B); DB($4C); DB($24); DB($0C);
  DB($85); DB($C9); DB($74); q := len; DB(0);
  DB($C7); DB($01); DB(0); DB(0); DB(0); DB(0);
  Patch8(q);
  DB($B8); DB($53); DB($03); DB($00); DB($C0);   // mov eax, 0C0000353h
  DB($C2); DB($14); DB($00);                     // ret 14h

  // Lflags: out := 1 (not debugged), return STATUS_SUCCESS
  Patch8(pFlags);
  DB($8B); DB($4C); DB($24); DB($0C);
  DB($85); DB($C9); DB($74); q := len; DB(0);
  DB($C7); DB($01); DB(1); DB(0); DB(0); DB(0);  // mov dword ptr [ecx], 1
  Patch8(q);
  DB($8B); DB($4C); DB($24); DB($14);
  DB($85); DB($C9); DB($74); q := len; DB(0);
  DB($C7); DB($01); DB(4); DB(0); DB(0); DB(0);
  Patch8(q);
  DB($33); DB($C0);
  DB($C2); DB($14); DB($00);

  PCardinal(@s[pJmp])^ := Cardinal((FnAddr + 5) - (Cave + NativeUInt(pJmp) + 4));
  SetLength(s, len);
  Result := s;
end;

function TAntiAntiDebug.InstallHook(const FnName: string; QueryProc: Boolean): Boolean;
var
  hNt: HMODULE;
  fn: Pointer;
  fnAddr, cave: NativeUInt;
  orig, stub, patch: TBytes;
begin
  Result := False;
  hNt := GetModuleHandle('ntdll.dll');
  if hNt = 0 then Exit;
  fn := GetProcAddress(hNt, PAnsiChar(AnsiString(FnName)));
  if fn = nil then Exit;
  fnAddr := NativeUInt(fn);

  SetLength(orig, 5);
  if not RPM(fnAddr, orig[0], 5) then Exit;
  if orig[0] <> $B8 then                                  // not a "mov eax, imm32" stub
  begin
    Log(FnName + ': unexpected prologue, hook skipped.');
    Exit;
  end;

  cave := NativeUInt(VirtualAllocEx(FProc, nil, 256,
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

  SetLength(patch, 5);
  patch[0] := $E9;
  PCardinal(@patch[1])^ := Cardinal(cave - (fnAddr + 5));
  if not WPM(fnAddr, patch[0], 5) then Exit;
  FlushInstructionCache(FProc, Pointer(fnAddr), 5);

  Log(FnName + ': hooked.');
  Result := True;
end;

function TAntiAntiDebug.Apply: Boolean;
begin
  PatchPEB;
  InstallHook('NtSetInformationThread', False);
  InstallHook('NtQueryInformationProcess', True);
  Result := True;   // best-effort; the PEB patch is the baseline and rarely fails
end;

end.
