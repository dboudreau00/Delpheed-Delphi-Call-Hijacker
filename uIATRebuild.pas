unit uIATRebuild;

{
  uIATRebuild - reconstruct the import table of an unpacked dump so it loads again.

  After unpacking, the stub has resolved every API the program needs and written
  the addresses into the Import Address Table in memory. But the on-disk import
  *directory* (the descriptors the loader reads) is gone. This rebuilds it, the
  way Scylla/ImpREC do:

    1. Enumerate the loaded modules of the live target (base, size, name).
    2. Scan the dumped image for the IAT: the longest run of pointer slots that
       all point into a loaded DLL (self-pointers into the image are ignored).
    3. Resolve each pointer to (DLL, function) by reading that DLL's export
       table out of the live process.
    4. Group the resolved pointers by DLL (contiguous runs) and emit a new
       import directory - descriptors + import lookup tables + hint/name tables
       + DLL name strings - into a fresh section appended to the file, with the
       FirstThunk of each descriptor pointing back at the existing IAT slots.
    5. Point the PE's import data directory at the new descriptors.

  MUST be called while the target is still alive and frozen at the OEP (its DLLs
  loaded, its IAT resolved). That means calling it from inside the OEP finder,
  before it terminates the process - see the integration note shipped with this.

  32-bit (PE32) targets. Build 32-bit.

  Honest limits: entries the packer resolved by GetProcAddress land on exact
  export addresses and resolve cleanly; forwarded exports resolve because we
  match the final address in the destination DLL; anything that doesn't match an
  export (hooked/redirected thunks) is counted as unresolved and left as a raw
  pointer, which only works at runtime if that DLL loads at the same base. The
  IAT search is heuristic (longest module-pointer run); a disassembly-from-OEP
  search would be more precise but needs a disassembler.
}

{$WARN SYMBOL_PLATFORM OFF}

interface

uses
  Windows, SysUtils, Classes, Generics.Collections, TlHelp32;

type
  TIATLog = reference to procedure(const Msg: string);

  TIATResult = record
    Success: Boolean;
    Message: string;
    IATStartRVA: Cardinal;
    IATSize: Cardinal;
    Imports: Integer;
    Unresolved: Integer;
    Descriptors: Integer;
    OutFile: string;
  end;

  TImp = record
    ByName: Boolean;
    Name: AnsiString;
    Ordinal: Word;
  end;

  TImpGroup = record
    ModIndex: Integer;
    StartRVA: Cardinal;          // FirstThunk: RVA of the first IAT slot in the group
    Entries: TArray<TImp>;
    ILTOffset: Cardinal;         // offset of this group's ILT inside the new blob
  end;

  TModExports = class
  public
    Index: Integer;
    Base: NativeUInt;
    Size: NativeUInt;
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

  TIATRebuilder = class
  private
    FLog: TIATLog;
    FProc: THandle;
    FImageBase: NativeUInt;
    FSizeOfImage: Cardinal;
    FMods: TObjectList<TModExports>;
    procedure Log(const S: string);
    function RBytes(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
    function RU32(Addr: NativeUInt): Cardinal;
    function RU16(Addr: NativeUInt): Word;
    function RCStr(Addr: NativeUInt): AnsiString;
    procedure EnumModules;
    procedure ParseModule(M: TModExports);
    function ModuleOf(VA: NativeUInt): TModExports;
    function Resolve(VA: NativeUInt; out ModIdx: Integer; out Imp: TImp): Boolean;
  public
    constructor Create(hProcess: THandle; ALog: TIATLog = nil);
    destructor Destroy; override;
    function RebuildImports(const InDumpFile, OutFixedFile: string): TIATResult;
  end;

implementation

function K32Read(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer;
  nSize: NativeUInt; lpRead: PNativeUInt): BOOL; stdcall;
  external kernel32 name 'ReadProcessMemory';

const
  MIN_IMPORTS = 5;
  IMPORT_BY_ORDINAL = $80000000;
  DDIR_IMPORT = 1;
  DDIR_BOUND  = 11;
  DDIR_IAT    = 12;

function Align(V, A: Cardinal): Cardinal;
begin
  Result := (V + A - 1) and not (A - 1);
end;

{ TModExports }

constructor TModExports.Create;
begin
  inherited Create;
  RVAToIndex := TDictionary<Cardinal, Integer>.Create;
end;

destructor TModExports.Destroy;
begin
  RVAToIndex.Free;
  inherited Destroy;
end;

{ TIATRebuilder }

constructor TIATRebuilder.Create(hProcess: THandle; ALog: TIATLog);
begin
  inherited Create;
  FProc := hProcess;
  FLog := ALog;
  FMods := TObjectList<TModExports>.Create(True);
end;

destructor TIATRebuilder.Destroy;
begin
  FMods.Free;
  inherited Destroy;
end;

procedure TIATRebuilder.Log(const S: string);
begin
  if Assigned(FLog) then FLog(S);
end;

function TIATRebuilder.RBytes(Addr: NativeUInt; var Buf; Size: NativeUInt): Boolean;
var
  got: NativeUInt;
begin
  got := 0;
  Result := K32Read(FProc, Pointer(Addr), @Buf, Size, @got) and (got = Size);
end;

function TIATRebuilder.RU32(Addr: NativeUInt): Cardinal;
begin
  Result := 0;
  RBytes(Addr, Result, 4);
end;

function TIATRebuilder.RU16(Addr: NativeUInt): Word;
begin
  Result := 0;
  RBytes(Addr, Result, 2);
end;

function TIATRebuilder.RCStr(Addr: NativeUInt): AnsiString;
var
  b: Byte;
  n: Integer;
begin
  Result := '';
  n := 0;
  while n < 512 do
  begin
    b := 0;
    if not RBytes(Addr + NativeUInt(n), b, 1) then Break;
    if b = 0 then Break;
    Result := Result + AnsiChar(b);
    Inc(n);
  end;
end;

procedure TIATRebuilder.EnumModules;
var
  snap: THandle;
  me: TModuleEntry32;
  M: TModExports;
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
        M := TModExports.Create;
        M.Index := FMods.Count;
        M.Base := NativeUInt(me.modBaseAddr);
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

procedure TIATRebuilder.ParseModule(M: TModExports);
var
  lfanew, optOfs, ddBase: NativeUInt;
  magic: Word;
  numFuncs, numNames, aof, aon, aoo, i: Cardinal;
  nameRVA: Cardinal;
  ordv: Word;
  raw: TBytes;
begin
  M.Parsed := True;
  M.HasExports := False;
  if RU16(M.Base) <> $5A4D then Exit;               // 'MZ'
  lfanew := M.Base + RU32(M.Base + $3C);
  if RU32(lfanew) <> $00004550 then Exit;           // 'PE'#0#0
  optOfs := lfanew + 24;
  magic := RU16(optOfs);
  if magic = $20B then
    ddBase := optOfs + 112
  else
    ddBase := optOfs + 96;                           // PE32

  M.ExpDirRVA  := RU32(ddBase + DDIR_IMPORT * 0);    // export = index 0
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

function TIATRebuilder.ModuleOf(VA: NativeUInt): TModExports;
var
  i: Integer;
begin
  Result := nil;
  for i := 0 to FMods.Count - 1 do
    if (VA >= FMods[i].Base) and (VA < FMods[i].Base + FMods[i].Size) then
      Exit(FMods[i]);
end;

function TIATRebuilder.Resolve(VA: NativeUInt; out ModIdx: Integer; out Imp: TImp): Boolean;
var
  M: TModExports;
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

function TIATRebuilder.RebuildImports(const InDumpFile, OutFixedFile: string): TIATResult;
var
  R: TIATResult;
  f, blob, strbytes: TBytes;
  fs: TFileStream;
  lfanew, optOfs, secTab, ddBase: Cardinal;
  numSecs, sizeOpt: Word;
  secAlign, fileAlign, sizeOfHeaders: Cardinal;
  i, scanEnd: NativeInt;
  V: Cardinal;
  cls: Integer;                       // 0=other, 1=impptr, 2=zero
  runStart, runImp, runFirstImp, runLastImp: NativeInt;
  bestStart, bestEnd: NativeInt;
  bestImp: Integer;
  iatStart, iatEnd: Cardinal;
  groups: TList<TImpGroup>;
  curEntries: TList<TImp>;
  g: TImpGroup;
  curMod: Integer;
  grpStart: Cardinal;
  mIdx: Integer;
  imp: TImp;
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
  R := Default(TIATResult);
  R.OutFile := OutFixedFile;

  // ---- load dump + parse headers ----
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
  // The dump's headers come from an untrusted target's memory; validate the PE
  // header window in 64-bit before dereferencing anything through lfanew.
  // 24 (file header) + 96 (to data dirs, PE32) + (DDIR_IAT+1)*8 (through the IAT dir).
  if UInt64(lfanew) + 24 + 96 + (DDIR_IAT + 1) * 8 > UInt64(Length(f)) then
  begin
    R.Message := 'Dump headers are truncated; cannot rebuild.';
    Exit(R);
  end;
  optOfs := lfanew + 24;
  if PWord(@f[optOfs])^ <> $10B then
  begin
    R.Message := 'Dump is not PE32 (32-bit).';
    Exit(R);
  end;
  FImageBase    := PCardinal(@f[optOfs + 28])^;
  FSizeOfImage  := PCardinal(@f[optOfs + 56])^;
  sizeOfHeaders := PCardinal(@f[optOfs + 60])^;
  secAlign      := PCardinal(@f[optOfs + 32])^;
  fileAlign     := PCardinal(@f[optOfs + 36])^;
  numSecs       := PWord(@f[lfanew + 6])^;
  sizeOpt       := PWord(@f[lfanew + 20])^;
  secTab        := optOfs + sizeOpt;
  ddBase        := optOfs + 96;

  if UInt64(secTab) + UInt64(numSecs) * 40 > UInt64(Length(f)) then
  begin
    R.Message := 'Dump headers are truncated; cannot rebuild.';
    Exit(R);
  end;

  // Alignment fields feed Align(); a zero or non-power-of-two value makes Align()
  // return 0 and turns the section-append below into an out-of-bounds heap write.
  if (fileAlign = 0) or ((fileAlign and (fileAlign - 1)) <> 0) or
     (secAlign = 0)  or ((secAlign and (secAlign - 1)) <> 0) or
     (fileAlign > $10000) or (secAlign < fileAlign) or
     (FSizeOfImage > $40000000) then
  begin
    R.Message := 'Dump has invalid alignment/size fields; cannot rebuild.';
    Exit(R);
  end;

  // sizeOfHeaders drives the IAT-scan start and the section-room check; clamp it so
  // a bogus value cannot truncate to a negative scan index on a 32-bit build.
  if sizeOfHeaders > Cardinal(Length(f)) then
    sizeOfHeaders := Cardinal(Length(f));

  EnumModules;
  if FMods.Count = 0 then
  begin
    R.Message := 'Could not enumerate target modules (is it still alive at OEP?).';
    Exit(R);
  end;

  // ---- scan for the IAT (best run of module pointers) ----
  scanEnd := Length(f) - 4;
  if NativeInt(FSizeOfImage) - 4 < scanEnd then scanEnd := NativeInt(FSizeOfImage) - 4;

  bestStart := -1; bestEnd := -1; bestImp := 0;
  runStart := -1; runImp := 0; runFirstImp := -1; runLastImp := -1;

  i := sizeOfHeaders;
  while i <= scanEnd do
  begin
    V := PCardinal(@f[i])^;
    if V = 0 then
      cls := 2
    else if (ModuleOf(V) <> nil) and (not ModuleOf(V).IsImage) then
      cls := 1
    else
      cls := 0;

    if cls = 0 then
    begin
      // close current run
      if (runStart >= 0) and (runImp >= MIN_IMPORTS) and (runImp > bestImp) then
      begin
        bestImp := runImp; bestStart := runFirstImp; bestEnd := runLastImp + 4;
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
    Inc(i, 4);
  end;
  if (runStart >= 0) and (runImp >= MIN_IMPORTS) and (runImp > bestImp) then
  begin
    bestImp := runImp; bestStart := runFirstImp; bestEnd := runLastImp + 4;
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

  // ---- walk the IAT, resolve, group by module ----
  groups := TList<TImpGroup>.Create;
  curEntries := TList<TImp>.Create;
  curMod := -1; grpStart := 0;
  try
    i := iatStart;
    while i <= NativeInt(iatEnd) - 4 do
    begin
      V := PCardinal(@f[i])^;
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
        CloseGroup;                    // unresolved pointer breaks the group
      end;
      Inc(i, 4);
    end;
    CloseGroup;

    R.Descriptors := groups.Count;
    if groups.Count = 0 then
    begin
      R.Message := 'IAT found but nothing resolved to known exports.';
      Exit(R);
    end;

    // ---- lay out the new blob: descriptors | ILTs | strings ----
    descCount := groups.Count;
    descSize := (descCount + 1) * 20;

    runIlt := descSize;
    for gi := 0 to groups.Count - 1 do
    begin
      g := groups[gi];
      g.ILTOffset := runIlt;
      groups[gi] := g;
      runIlt := runIlt + Cardinal(Length(g.Entries) + 1) * 4;
    end;
    iltTotal := runIlt - descSize;
    strBase := descSize + iltTotal;

    // intern DLL names and hint/name entries into strbytes (offsets relative to strBase)
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
              SetLength(strbytes, Length(strbytes) + 1);   // 2-align IMAGE_IMPORT_BY_NAME
            nm := g.Entries[k].Name;
            o := Cardinal(Length(strbytes));
            ibnOff.Add(nm, o);
            SetLength(strbytes, Length(strbytes) + 2 + Length(nm) + 1);
            PWord(@strbytes[o])^ := 0;                     // hint
            Move(nm[1], strbytes[o + 2], Length(nm));
            strbytes[o + 2 + Cardinal(Length(nm))] := 0;
          end;
      end;

      blobSize := strBase + Cardinal(Length(strbytes));

      // ---- placement: keep file offset == RVA (matches the dump's layout) ----
      newSecVA := Align(Cardinal(Length(f)), secAlign);
      if newSecVA < Align(FSizeOfImage, secAlign) then
        newSecVA := Align(FSizeOfImage, secAlign);
      baseRVA := newSecVA;

      // room for one more section header?
      if secTab + (Cardinal(numSecs) + 1) * 40 > sizeOfHeaders then
      begin
        R.Message := 'No room in PE header for an extra section.';
        Exit(R);
      end;

      // ---- realise the blob ----
      SetLength(blob, blobSize);
      // descriptors
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        off := Cardinal(gi) * 20;
        PCardinal(@blob[off + 0])^  := baseRVA + g.ILTOffset;                 // OriginalFirstThunk
        PCardinal(@blob[off + 12])^ := baseRVA + strBase + dllOff[g.ModIndex]; // Name
        PCardinal(@blob[off + 16])^ := g.StartRVA;                            // FirstThunk (existing IAT)
      end;
      // ILTs
      for gi := 0 to groups.Count - 1 do
      begin
        g := groups[gi];
        p := g.ILTOffset;
        for k := 0 to High(g.Entries) do
        begin
          if g.Entries[k].ByName then
            PCardinal(@blob[p])^ := baseRVA + strBase + ibnOff[g.Entries[k].Name]
          else
            PCardinal(@blob[p])^ := IMPORT_BY_ORDINAL or Cardinal(g.Entries[k].Ordinal);
          Inc(p, 4);
        end;
        PCardinal(@blob[p])^ := 0;   // ILT terminator
      end;
      // strings
      if Length(strbytes) > 0 then
        Move(strbytes[0], blob[strBase], Length(strbytes));

      // ---- splice into the file ----
      rawSize := Align(blobSize, fileAlign);
      SetLength(f, newSecVA + rawSize);           // zero-pads [oldlen..newSecVA) and the raw tail
      Move(blob[0], f[newSecVA], blobSize);

      // new section header
      off := secTab + Cardinal(numSecs) * 40;
      FillChar(f[off], 40, 0);
      nm := '.ncimp';
      Move(nm[1], f[off], Length(nm));                      // 8-byte name field, null-padded
      PCardinal(@f[off + 8])^  := blobSize;                 // VirtualSize
      PCardinal(@f[off + 12])^ := newSecVA;                 // VirtualAddress
      PCardinal(@f[off + 16])^ := rawSize;                  // SizeOfRawData
      PCardinal(@f[off + 20])^ := newSecVA;                 // PointerToRawData (== RVA)
      PCardinal(@f[off + 36])^ := $C0000040;                // INITIALIZED_DATA | READ | WRITE

      // header fixups
      PWord(@f[lfanew + 6])^    := numSecs + 1;                        // NumberOfSections
      PCardinal(@f[optOfs + 56])^ := newSecVA + Align(blobSize, secAlign); // SizeOfImage
      PCardinal(@f[ddBase + DDIR_IMPORT * 8])^     := baseRVA;         // import dir VA
      PCardinal(@f[ddBase + DDIR_IMPORT * 8 + 4])^ := descSize;        // import dir size
      PCardinal(@f[ddBase + DDIR_IAT * 8])^        := iatStart;        // IAT dir VA
      PCardinal(@f[ddBase + DDIR_IAT * 8 + 4])^    := iatEnd - iatStart;
      PCardinal(@f[ddBase + DDIR_BOUND * 8])^      := 0;               // clear bound imports
      PCardinal(@f[ddBase + DDIR_BOUND * 8 + 4])^  := 0;

      // ---- write out ----
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
