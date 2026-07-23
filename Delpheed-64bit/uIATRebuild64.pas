unit uIATRebuild64;

{
  uIATRebuild64 - 64-bit (PE32+) import-table reconstruction. The x64 counterpart
  of uIATRebuild.

  Same algorithm - enumerate modules, find the resolved IAT as the longest run of
  pointers into loaded DLLs, resolve each against the DLL's export table, and emit
  a fresh import directory into an appended section - with the x64 differences:
    * PE32+ headers: 8-byte image base at optional-header +24, data directories
      at +112.
    * IAT / ILT thunks are 8 bytes; the import-by-ordinal flag is bit 63.
  Import descriptors stay 20 bytes (their fields are 32-bit RVAs in both formats).

  Must be called while the target is alive at the OEP. Build 64-bit.
}

{$WARN SYMBOL_PLATFORM OFF}

interface

uses
  Windows, SysUtils, Classes, Generics.Collections, TlHelp32;

type
  TIAT64Log = reference to procedure(const Msg: string);

  TIAT64Result = record
    Success: Boolean;
    Message: string;
    IATStartRVA: Cardinal;
    IATSize: Cardinal;
    Imports: Integer;
    Unresolved: Integer;
    Descriptors: Integer;
    OutFile: string;
  end;

  TImp64 = record
    ByName: Boolean;
    Name: AnsiString;
    Ordinal: Word;
  end;

  TImpGroup64 = record
    ModIndex: Integer;
    StartRVA: Cardinal;
    Entries: TArray<TImp64>;
    ILTOffset: Cardinal;
  end;

  TModExports64 = class
  public
    Index: Integer;
    Base: UInt64;
    Size: UInt64;
    Name: string;
    IsImage: Boolean;
    Parsed: Boolean;
    HasExports: Boolean;
    ExpBase: Cardinal;
    ExpDirRVA: Cardinal;
    ExpDirSize: Cardinal;
    FuncRVAs: TArray<Cardinal>;
    NameByIndex: TArray<AnsiString>;
    RVAToIndex: TDictionary<Cardinal, Integer>;
    constructor Create;
    destructor Destroy; override;
  end;

  TIATRebuilder64 = class
  private
    FLog: TIAT64Log;
    FProc: THandle;
    FImageBase: UInt64;
    FSizeOfImage: Cardinal;
    FMods: TObjectList<TModExports64>;
    procedure Log(const S: string);
    function RBytes(Addr: UInt64; var Buf; Size: NativeUInt): Boolean;
    function RU32(Addr: UInt64): Cardinal;
    function RU16(Addr: UInt64): Word;
    function RCStr(Addr: UInt64): AnsiString;
    procedure EnumModules;
    procedure ParseModule(M: TModExports64);
    function ModuleOf(VA: UInt64): TModExports64;
    function Resolve(VA: UInt64; out ModIdx: Integer; out Imp: TImp64): Boolean;
  public
    constructor Create(hProcess: THandle; ALog: TIAT64Log = nil);
    destructor Destroy; override;
    function RebuildImports(const InDumpFile, OutFixedFile: string): TIAT64Result;
  end;

implementation

function K32Read(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpRead: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'ReadProcessMemory';

const
  MIN_IMPORTS = 5;
  IMPORT_BY_ORDINAL64: UInt64 = $8000000000000000;
  DDIR_IMPORT = 1;
  DDIR_BOUND  = 11;
  DDIR_IAT    = 12;

function Align(V, A: Cardinal): Cardinal;
begin
  Result := (V + A - 1) and not (A - 1);
end;

constructor TModExports64.Create;
begin
  inherited Create;
  RVAToIndex := TDictionary<Cardinal, Integer>.Create;
end;

destructor TModExports64.Destroy;
begin
  RVAToIndex.Free;
  inherited Destroy;
end;

constructor TIATRebuilder64.Create(hProcess: THandle; ALog: TIAT64Log);
begin
  inherited Create;
  FProc := hProcess;
  FLog := ALog;
  FMods := TObjectList<TModExports64>.Create(True);
end;

destructor TIATRebuilder64.Destroy;
begin
  FMods.Free;
  inherited Destroy;
end;

procedure TIATRebuilder64.Log(const S: string);
begin
  if Assigned(FLog) then FLog(S);
end;

function TIATRebuilder64.RBytes(Addr: UInt64; var Buf; Size: NativeUInt): Boolean;
var
  got: NativeUInt;
begin
  got := 0;
  Result := K32Read(FProc, Pointer(Addr), @Buf, Size, @got) and (got = Size);
end;

function TIATRebuilder64.RU32(Addr: UInt64): Cardinal;
begin
  Result := 0;
  RBytes(Addr, Result, 4);
end;

function TIATRebuilder64.RU16(Addr: UInt64): Word;
begin
  Result := 0;
  RBytes(Addr, Result, 2);
end;

function TIATRebuilder64.RCStr(Addr: UInt64): AnsiString;
var
  b: Byte;
  n: Integer;
begin
  Result := '';
  n := 0;
  while n < 512 do
  begin
    b := 0;
    if not RBytes(Addr + UInt64(n), b, 1) then Break;
    if b = 0 then Break;
    Result := Result + AnsiChar(b);
    Inc(n);
  end;
end;

procedure TIATRebuilder64.EnumModules;
var
  snap: THandle;
  me: TModuleEntry32;
  M: TModExports64;
  pid: DWORD;
begin
  pid := GetProcessId(FProc);
  snap := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, pid);
  if snap = INVALID_HANDLE_VALUE then Exit;
  try
    FillChar(me, SizeOf(me), 0);
    me.dwSize := SizeOf(me);
    if Module32First(snap, me) then
      repeat
        M := TModExports64.Create;
        M.Index := FMods.Count;
        M.Base := UInt64(me.modBaseAddr);
        M.Size := me.modBaseSize;
        M.Name := string(me.szModule);
        M.IsImage := (M.Base = FImageBase);
        FMods.Add(M);
      until not Module32Next(snap, me);
  finally
    CloseHandle(snap);
  end;
  Log(Format('%d modules loaded in target.', [FMods.Count]));
end;

procedure TIATRebuilder64.ParseModule(M: TModExports64);
var
  lfanew, optOfs, ddBase: UInt64;
  magic: Word;
  numFuncs, numNames, aof, aon, aoo, i: Cardinal;
  nameRVA: Cardinal;
  ordv: Word;
  raw: TBytes;
begin
  M.Parsed := True;
  M.HasExports := False;
  if RU16(M.Base) <> $5A4D then Exit;
  lfanew := M.Base + RU32(M.Base + $3C);
  if RU32(lfanew) <> $00004550 then Exit;
  optOfs := lfanew + 24;
  magic := RU16(optOfs);
  if magic = $20B then
    ddBase := optOfs + 112
  else
    ddBase := optOfs + 96;

  M.ExpDirRVA  := RU32(ddBase);
  M.ExpDirSize := RU32(ddBase + 4);
  if M.ExpDirRVA = 0 then Exit;

  M.ExpBase := RU32(M.Base + M.ExpDirRVA + 16);
  numFuncs  := RU32(M.Base + M.ExpDirRVA + 20);
  numNames  := RU32(M.Base + M.ExpDirRVA + 24);
  aof       := RU32(M.Base + M.ExpDirRVA + 28);
  aon       := RU32(M.Base + M.ExpDirRVA + 32);
  aoo       := RU32(M.Base + M.ExpDirRVA + 36);
  if (numFuncs = 0) or (numFuncs > 100000) then Exit;

  SetLength(M.FuncRVAs, numFuncs);
  SetLength(raw, numFuncs * 4);
  if not RBytes(M.Base + aof, raw[0], numFuncs * 4) then Exit;
  for i := 0 to numFuncs - 1 do
    M.FuncRVAs[i] := PCardinal(@raw[i * 4])^;

  SetLength(M.NameByIndex, numFuncs);
  if numNames > 100000 then numNames := 0;
  for i := 0 to numNames - 1 do
  begin
    nameRVA := RU32(M.Base + aon + i * 4);
    ordv    := RU16(M.Base + aoo + i * 2);
    if ordv < numFuncs then
      M.NameByIndex[ordv] := RCStr(M.Base + nameRVA);
  end;

  M.RVAToIndex.Clear;
  for i := 0 to numFuncs - 1 do
    if not M.RVAToIndex.ContainsKey(M.FuncRVAs[i]) then
      M.RVAToIndex.Add(M.FuncRVAs[i], i);

  M.HasExports := True;
end;

function TIATRebuilder64.ModuleOf(VA: UInt64): TModExports64;
var
  i: Integer;
begin
  Result := nil;
  for i := 0 to FMods.Count - 1 do
    if (VA >= FMods[i].Base) and (VA < FMods[i].Base + FMods[i].Size) then
      Exit(FMods[i]);
end;

function TIATRebuilder64.Resolve(VA: UInt64; out ModIdx: Integer; out Imp: TImp64): Boolean;
var
  M: TModExports64;
  funcRVA: Cardinal;
  idx: Integer;
begin
  Result := False;
  ModIdx := -1;
  Imp.ByName := False;
  Imp.Name := '';
  Imp.Ordinal := 0;

  M := ModuleOf(VA);
  if (M = nil) or M.IsImage then Exit;
  if not M.Parsed then ParseModule(M);
  if not M.HasExports then Exit;

  funcRVA := Cardinal(VA - M.Base);
  if not M.RVAToIndex.TryGetValue(funcRVA, idx) then Exit;

  ModIdx := M.Index;
  if M.NameByIndex[idx] <> '' then
  begin
    Imp.ByName := True;
    Imp.Name := M.NameByIndex[idx];
  end
  else
  begin
    Imp.ByName := False;
    Imp.Ordinal := Word(M.ExpBase + Cardinal(idx));
  end;
  Result := True;
end;

function TIATRebuilder64.RebuildImports(const InDumpFile, OutFixedFile: string): TIAT64Result;
var
  R: TIAT64Result;
  f, blob, strbytes: TBytes;
  fs: TFileStream;
  lfanew, optOfs, secTab, ddBase: Cardinal;
  numSecs, sizeOpt: Word;
  secAlign, fileAlign, sizeOfHeaders: Cardinal;
  i, scanEnd: NativeInt;
  V: UInt64;
  cls: Integer;
  runStart, runImp, runFirstImp, runLastImp: NativeInt;
  bestStart, bestEnd: NativeInt;
  bestImp: Integer;
  iatStart, iatEnd: Cardinal;
  groups: TList<TImpGroup64>;
  curEntries: TList<TImp64>;
  g: TImpGroup64;
  curMod: Integer;
  grpStart: Cardinal;
  mIdx: Integer;
  imp: TImp64;
  descCount, descSize, iltTotal, strBase, blobSize: Cardinal;
  runIlt: Cardinal;
  gi, k: Integer;
  dllOff: TDictionary<Integer, Cardinal>;
  ibnOff: TDictionary<AnsiString, Cardinal>;
  baseRVA, newSecVA, rawSize: Cardinal;
  off, p: Cardinal;
  nm: AnsiString;
  o: Cardinal;

  procedure CloseGroup;
  begin
    if (curMod <> -1) and (curEntries.Count > 0) then
    begin
      g.ModIndex := curMod;
      g.StartRVA := grpStart;
      g.Entries := curEntries.ToArray;
      g.ILTOffset := 0;
      groups.Add(g);
    end;
    curEntries.Clear;
    curMod := -1;
  end;

begin
  R := Default(TIAT64Result);
  R.OutFile := OutFixedFile;

  try
    fs := TFileStream.Create(InDumpFile, fmOpenRead or fmShareDenyWrite);
    try
      SetLength(f, fs.Size);
      if fs.Size > 0 then fs.ReadBuffer(f[0], fs.Size);
    finally
      fs.Free;
    end;
  except
    on E: Exception do
    begin
      R.Message := 'Cannot read dump: ' + E.Message;
      Exit(R);
    end;
  end;

  if (Length(f) < 64) or (PWord(@f[0])^ <> $5A4D) then
  begin
    R.Message := 'Dump is not a PE.';
    Exit(R);
  end;
  lfanew := PCardinal(@f[$3C])^;
  optOfs := lfanew + 24;
  if PWord(@f[optOfs])^ <> $20B then
  begin
    R.Message := 'Dump is not PE32+ (64-bit).';
    Exit(R);
  end;
  FImageBase    := PUInt64(@f[optOfs + 24])^;
  FSizeOfImage  := PCardinal(@f[optOfs + 56])^;
  sizeOfHeaders := PCardinal(@f[optOfs + 60])^;
  secAlign      := PCardinal(@f[optOfs + 32])^;
  fileAlign     := PCardinal(@f[optOfs + 36])^;
  numSecs       := PWord(@f[lfanew + 6])^;
  sizeOpt       := PWord(@f[lfanew + 20])^;
  secTab        := optOfs + sizeOpt;
  ddBase        := optOfs + 112;

  if (Cardinal(Length(f)) < optOfs + 120) or
     (Cardinal(Length(f)) < secTab + Cardinal(numSecs) * 40) or
     (Cardinal(Length(f)) < ddBase + (DDIR_IAT + 1) * 8) then
  begin
    R.Message := 'Dump headers are truncated; cannot rebuild.';
    Exit(R);
  end;

  EnumModules;
  if FMods.Count = 0 then
  begin
    R.Message := 'Could not enumerate target modules (is it still alive at OEP?).';
    Exit(R);
  end;

  // scan for the IAT (best run of 8-byte module pointers)
  scanEnd := Length(f) - 8;
  if NativeInt(FSizeOfImage) - 8 < scanEnd then scanEnd := NativeInt(FSizeOfImage) - 8;

  bestStart := -1; bestEnd := -1; bestImp := 0;
  runStart := -1; runImp := 0; runFirstImp := -1; runLastImp := -1;

  i := sizeOfHeaders;
  while i <= scanEnd do
  begin
    V := PUInt64(@f[i])^;
    if V = 0 then
      cls := 2
    else if (ModuleOf(V) <> nil) and (not ModuleOf(V).IsImage) then
      cls := 1
    else
      cls := 0;

    if cls = 0 then
    begin
      if (runStart >= 0) and (runImp >= MIN_IMPORTS) and (runImp > bestImp) then
      begin
        bestImp := runImp; bestStart := runFirstImp; bestEnd := runLastImp + 8;
      end;
      runStart := -1; runImp := 0; runFirstImp := -1; runLastImp := -1;
    end
    else
    begin
      if runStart < 0 then runStart := i;
      if cls = 1 then
      begin
        Inc(runImp);
        if runFirstImp < 0 then runFirstImp := i;
        runLastImp := i;
      end;
    end;
    Inc(i, 8);
  end;
  if (runStart >= 0) and (runImp >= MIN_IMPORTS) and (runImp > bestImp) then
  begin
    bestImp := runImp; bestStart := runFirstImp; bestEnd := runLastImp + 8;
  end;

  if bestStart < 0 then
  begin
    R.Message := 'No IAT found (no run of >= ' + IntToStr(MIN_IMPORTS) + ' import pointers).';
    Exit(R);
  end;

  iatStart := Cardinal(bestStart);
  iatEnd := Cardinal(bestEnd);
  R.IATStartRVA := iatStart;
  R.IATSize := iatEnd - iatStart;
  Log(Format('IAT at RVA $%x .. $%x (%d pointers)', [iatStart, iatEnd, bestImp]));

  groups := TList<TImpGroup64>.Create;
  curEntries := TList<TImp64>.Create;
  curMod := -1; grpStart := 0;
  try
    i := iatStart;
    while i <= NativeInt(iatEnd) - 8 do
    begin
      V := PUInt64(@f[i])^;
      if V = 0 then
        CloseGroup
      else if Resolve(V, mIdx, imp) then
      begin
        if curMod = -1 then
        begin
          curMod := mIdx; grpStart := Cardinal(i);
        end
        else if mIdx <> curMod then
        begin
          CloseGroup;
          curMod := mIdx; grpStart := Cardinal(i);
        end;
        curEntries.Add(imp);
        Inc(R.Imports);
      end
      else
      begin
        Inc(R.Unresolved);
        CloseGroup;
      end;
      Inc(i, 8);
    end;
    CloseGroup;

    R.Descriptors := groups.Count;
    if groups.Count = 0 then
    begin
      R.Message := 'IAT found but nothing resolved to known exports.';
      Exit(R);
    end;

    descCount := groups.Count;
    descSize := (descCount + 1) * 20;

    runIlt := descSize;
    for gi := 0 to groups.Count - 1 do
    begin
      g := groups[gi];
      g.ILTOffset := runIlt;
      groups[gi] := g;
      runIlt := runIlt + Cardinal(Length(g.Entries) + 1) * 8;   // 8-byte thunks
    end;
    iltTotal := runIlt - descSize;
    strBase := descSize + iltTotal;

    dllOff := TDictionary<Integer, Cardinal>.Create;
    ibnOff := TDictionary<AnsiString, Cardinal>.Create;
    SetLength(strbytes, 0);
    try
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        if not dllOff.ContainsKey(g.ModIndex) then
        begin
          nm := AnsiString(FMods[g.ModIndex].Name);
          o := Cardinal(Length(strbytes));
          dllOff.Add(g.ModIndex, o);
          SetLength(strbytes, Length(strbytes) + Length(nm) + 1);
          if Length(nm) > 0 then Move(nm[1], strbytes[o], Length(nm));
          strbytes[o + Cardinal(Length(nm))] := 0;
        end;
        for k := 0 to High(g.Entries) do
          if g.Entries[k].ByName and (not ibnOff.ContainsKey(g.Entries[k].Name)) then
          begin
            if Odd(Length(strbytes)) then
              SetLength(strbytes, Length(strbytes) + 1);
            nm := g.Entries[k].Name;
            o := Cardinal(Length(strbytes));
            ibnOff.Add(nm, o);
            SetLength(strbytes, Length(strbytes) + 2 + Length(nm) + 1);
            PWord(@strbytes[o])^ := 0;
            if Length(nm) > 0 then Move(nm[1], strbytes[o + 2], Length(nm));
            strbytes[o + 2 + Cardinal(Length(nm))] := 0;
          end;
      end;

      blobSize := strBase + Cardinal(Length(strbytes));

      newSecVA := Align(Cardinal(Length(f)), secAlign);
      if newSecVA < Align(FSizeOfImage, secAlign) then
        newSecVA := Align(FSizeOfImage, secAlign);
      baseRVA := newSecVA;

      if secTab + (Cardinal(numSecs) + 1) * 40 > sizeOfHeaders then
      begin
        R.Message := 'No room in PE header for an extra section.';
        Exit(R);
      end;

      SetLength(blob, blobSize);
      // descriptors (20 bytes each; fields are 32-bit RVAs in PE32+ too)
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        off := Cardinal(gi) * 20;
        PCardinal(@blob[off + 0])^  := baseRVA + g.ILTOffset;
        PCardinal(@blob[off + 12])^ := baseRVA + strBase + dllOff[g.ModIndex];
        PCardinal(@blob[off + 16])^ := g.StartRVA;
      end;
      // ILTs (8-byte thunks)
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        p := g.ILTOffset;
        for k := 0 to High(g.Entries) do
        begin
          if g.Entries[k].ByName then
            PUInt64(@blob[p])^ := UInt64(baseRVA + strBase + ibnOff[g.Entries[k].Name])
          else
            PUInt64(@blob[p])^ := IMPORT_BY_ORDINAL64 or UInt64(g.Entries[k].Ordinal);
          Inc(p, 8);
        end;
        PUInt64(@blob[p])^ := 0;
      end;
      if Length(strbytes) > 0 then
        Move(strbytes[0], blob[strBase], Length(strbytes));

      rawSize := Align(blobSize, fileAlign);
      SetLength(f, newSecVA + rawSize);
      Move(blob[0], f[newSecVA], blobSize);

      off := secTab + Cardinal(numSecs) * 40;
      FillChar(f[off], 40, 0);
      nm := '.ncimp';
      Move(nm[1], f[off], Length(nm));
      PCardinal(@f[off + 8])^  := blobSize;
      PCardinal(@f[off + 12])^ := newSecVA;
      PCardinal(@f[off + 16])^ := rawSize;
      PCardinal(@f[off + 20])^ := newSecVA;
      PCardinal(@f[off + 36])^ := $C0000040;

      PWord(@f[lfanew + 6])^      := numSecs + 1;
      PCardinal(@f[optOfs + 56])^ := newSecVA + Align(blobSize, secAlign);
      PCardinal(@f[ddBase + DDIR_IMPORT * 8])^     := baseRVA;
      PCardinal(@f[ddBase + DDIR_IMPORT * 8 + 4])^ := descSize;
      PCardinal(@f[ddBase + DDIR_IAT * 8])^        := iatStart;
      PCardinal(@f[ddBase + DDIR_IAT * 8 + 4])^    := iatEnd - iatStart;
      PCardinal(@f[ddBase + DDIR_BOUND * 8])^      := 0;
      PCardinal(@f[ddBase + DDIR_BOUND * 8 + 4])^  := 0;

      try
        fs := TFileStream.Create(OutFixedFile, fmCreate);
        try
          fs.WriteBuffer(f[0], Length(f));
        finally
          fs.Free;
        end;
        R.Success := True;
        R.Message := Format('Rebuilt %d imports across %d descriptors (%d unresolved).',
          [R.Imports, R.Descriptors, R.Unresolved]);
      except
        on E: Exception do
          R.Message := 'Write failed: ' + E.Message;
      end;
    finally
      dllOff.Free;
      ibnOff.Free;
    end;
  finally
    curEntries.Free;
    groups.Free;
  end;

  Result := R;
end;

end.
