unit uDelphiVMT;

{
  uDelphiVMT - recovers the class list and hierarchy from a Delphi PE.

  How VMTs are found
  ------------------
  Every Delphi class has a VMT. The class *reference* (what an instance stores
  at offset 0, and what "TFoo" evaluates to) points into the middle of a block:
  negative offsets hold system fields, positive offsets hold the user's virtual
  methods. The lowest field, vmtSelfPtr, is self-referential: the pointer stored
  there points back at the class reference.

  So if a class reference is at VA C, then at address (C + SelfPtrOffset) the
  stored pointer equals C. We scan every pointer-aligned slot L, read its value
  V, and if V == (L - SelfPtrOffset) we have a candidate class at C = V.
  (We also accept V == L in case a build stores the field's own address; C is
  computed the same way, so validation decides either way.)

  SelfPtrOffset depends on version/bitness:
     -76  : Delphi 2..7        (x86, pre-Unicode layout)
     -88  : Delphi 2009..12    (x86, Equals/GetHashCode/ToString added)
    -176  : Delphi x64         (XE2+, always the Unicode layout, doubled)
  We try each and keep whichever finds the most valid classes.

  Validation (keeps false positives near zero)
  --------------------------------------------
    * vmtClassName -> a pointer to a ShortString that looks like an identifier
    * vmtInstanceSize -> a sane size (>= pointer size, < 16 MB)
  These two fields sit at fixed indices from vmtSelfPtr in *both* layouts
  (the extra Unicode methods are inserted after Parent), so one offset drives
  every field:  fieldOffset(idx) = SelfPtrOffset + idx * PointerSize.

  Parent links are resolved best-effort afterwards, trying a direct pointer and
  one level of indirection (D7 stores parent indirectly, newer Delphi directly).
}

interface

uses
  SysUtils, Classes, Generics.Collections, uPEFile;

type
  TDelphiClass = record
    ClassVA: UInt64;
    ClassRVA: Cardinal;
    Name: string;
    InstanceSize: Cardinal;
    ParentRaw: UInt64;      // raw value of the vmtParent field
    ParentVA: UInt64;       // resolved parent class VA (0 = none)
    ParentName: string;     // '' = root (TObject), '(external)' = not in image
    // table pointers, exposed for a later RTTI pass
    TypeInfoVA: UInt64;
    FieldTableVA: UInt64;
    MethodTableVA: UInt64;
    DynamicTableVA: UInt64;
    IntfTableVA: UInt64;
    InitTableVA: UInt64;
  end;

  TDelphiVMTScanner = class
  private
    FPE: TPEFile;
    FOwnsPE: Boolean;
    FSelfPtrOffset: Integer;
    FClasses: TArray<TDelphiClass>;
    function ValidName(const S: AnsiString): Boolean;
    function FieldVA(ClassVA: UInt64; Idx, SelfPtr, Ptr: Integer): UInt64;
    function TryReadClassAt(ClassVA: UInt64; SelfPtr: Integer;
      out Info: TDelphiClass): Boolean;
    function ScanWithOffset(SelfPtr: Integer): TArray<TDelphiClass>;
    procedure ResolveParents(var List: TArray<TDelphiClass>);
  public
    constructor Create(APE: TPEFile; AOwnsPE: Boolean = False);
    destructor Destroy; override;
    procedure Scan;
    function Count: Integer;
    function FindIndexByVA(VA: UInt64): Integer;
    property Classes: TArray<TDelphiClass> read FClasses;
    property SelfPtrOffset: Integer read FSelfPtrOffset;
  end;

implementation

const
  // field indices, counting up from vmtSelfPtr (index 0)
  IDX_SELFPTR      = 0;
  IDX_INTFTABLE    = 1;
  IDX_AUTOTABLE    = 2;
  IDX_INITTABLE    = 3;
  IDX_TYPEINFO     = 4;
  IDX_FIELDTABLE   = 5;
  IDX_METHODTABLE  = 6;
  IDX_DYNAMICTABLE = 7;
  IDX_CLASSNAME    = 8;
  IDX_INSTANCESIZE = 9;
  IDX_PARENT       = 10;

  MAX_INSTANCE_SIZE = $00FFFFFF;   // 16 MB sanity cap

constructor TDelphiVMTScanner.Create(APE: TPEFile; AOwnsPE: Boolean);
begin
  inherited Create;
  FPE := APE;
  FOwnsPE := AOwnsPE;
end;

destructor TDelphiVMTScanner.Destroy;
begin
  if FOwnsPE then
    FPE.Free;
  inherited Destroy;
end;

function TDelphiVMTScanner.ValidName(const S: AnsiString): Boolean;
var
  i: Integer;
  c: AnsiChar;
begin
  Result := False;
  if (Length(S) < 1) or (Length(S) > 255) then Exit;
  c := S[1];
  if not (c in ['A'..'Z', 'a'..'z', '_']) then Exit;  // identifiers start here
  for i := 1 to Length(S) do
  begin
    c := S[i];
    // printable ASCII; space allowed (generic names), controls rejected
    if ((Ord(c) < 33) or (Ord(c) > 126)) and (c <> ' ') then Exit;
  end;
  Result := True;
end;

function TDelphiVMTScanner.FieldVA(ClassVA: UInt64; Idx, SelfPtr, Ptr: Integer): UInt64;
begin
  // offset = SelfPtr (negative) + Idx * Ptr; can be negative overall
  Result := UInt64(Int64(ClassVA) + (SelfPtr + Idx * Ptr));
end;

function TDelphiVMTScanner.TryReadClassAt(ClassVA: UInt64; SelfPtr: Integer;
  out Info: TDelphiClass): Boolean;
var
  ptr: Integer;
  cnPtr: UInt64;
  name: AnsiString;
  isize: Cardinal;
  r: Int64;
begin
  Result := False;
  Info := Default(TDelphiClass);
  ptr := FPE.PointerSize;

  // vmtClassName: pointer -> ShortString
  if not FPE.ReadPtrVA(FieldVA(ClassVA, IDX_CLASSNAME, SelfPtr, ptr), cnPtr) then Exit;
  if not FPE.ReadShortStringVA(cnPtr, name) then Exit;
  if not ValidName(name) then Exit;

  // vmtInstanceSize
  if not FPE.ReadDWordVA(FieldVA(ClassVA, IDX_INSTANCESIZE, SelfPtr, ptr), isize) then Exit;
  if (isize < Cardinal(ptr)) or (isize > MAX_INSTANCE_SIZE) then Exit;

  Info.ClassVA := ClassVA;
  r := FPE.VAToRVA(ClassVA);
  if r >= 0 then Info.ClassRVA := Cardinal(r);
  Info.Name := string(name);
  Info.InstanceSize := isize;

  // remaining fields are best-effort (left 0 if unreadable)
  FPE.ReadPtrVA(FieldVA(ClassVA, IDX_PARENT,       SelfPtr, ptr), Info.ParentRaw);
  FPE.ReadPtrVA(FieldVA(ClassVA, IDX_TYPEINFO,     SelfPtr, ptr), Info.TypeInfoVA);
  FPE.ReadPtrVA(FieldVA(ClassVA, IDX_FIELDTABLE,   SelfPtr, ptr), Info.FieldTableVA);
  FPE.ReadPtrVA(FieldVA(ClassVA, IDX_METHODTABLE,  SelfPtr, ptr), Info.MethodTableVA);
  FPE.ReadPtrVA(FieldVA(ClassVA, IDX_DYNAMICTABLE, SelfPtr, ptr), Info.DynamicTableVA);
  FPE.ReadPtrVA(FieldVA(ClassVA, IDX_INTFTABLE,    SelfPtr, ptr), Info.IntfTableVA);
  FPE.ReadPtrVA(FieldVA(ClassVA, IDX_INITTABLE,    SelfPtr, ptr), Info.InitTableVA);

  Result := True;
end;

function TDelphiVMTScanner.ScanWithOffset(SelfPtr: Integer): TArray<TDelphiClass>;
var
  ptr: Integer;
  s: Integer;
  o, endOff, imgLen: NativeInt;
  rva: Cardinal;
  va, V, expectedC: UInt64;
  info: TDelphiClass;
  img: TBytes;
  list: TList<TDelphiClass>;
  seen: TDictionary<UInt64, Integer>;
begin
  ptr := FPE.PointerSize;
  img := FPE.Image;
  imgLen := Length(img);

  list := TList<TDelphiClass>.Create;
  seen := TDictionary<UInt64, Integer>.Create;
  try
    if imgLen = 0 then Exit(nil);

    for s := 0 to High(FPE.Sections) do
    begin
      if FPE.Sections[s].SizeOfRawData = 0 then Continue;

      o := FPE.Sections[s].PointerToRawData;
      endOff := NativeInt(FPE.Sections[s].PointerToRawData) +
                NativeInt(FPE.Sections[s].SizeOfRawData);
      if endOff > imgLen then endOff := imgLen;

      while o + ptr <= endOff do
      begin
        if ptr = 8 then
          V := PUInt64(@img[o])^
        else
          V := PCardinal(@img[o])^;

        rva := FPE.Sections[s].VirtualAddress +
               Cardinal(o - NativeInt(FPE.Sections[s].PointerToRawData));
        va := FPE.ImageBase + rva;
        expectedC := va + UInt64(Cardinal(-SelfPtr));  // C = L - SelfPtr

        if (V = expectedC) or (V = va) then
          if not seen.ContainsKey(expectedC) then
            if TryReadClassAt(expectedC, SelfPtr, info) then
            begin
              seen.Add(expectedC, list.Count);
              list.Add(info);
            end;

        Inc(o, ptr);
      end;
    end;

    Result := list.ToArray;
  finally
    seen.Free;
    list.Free;
  end;
end;

procedure TDelphiVMTScanner.ResolveParents(var List: TArray<TDelphiClass>);
var
  dict: TDictionary<UInt64, Integer>;
  i, j: Integer;
  raw, raw2: UInt64;
begin
  dict := TDictionary<UInt64, Integer>.Create;
  try
    for i := 0 to High(List) do
      dict.AddOrSetValue(List[i].ClassVA, i);

    for i := 0 to High(List) do
    begin
      raw := List[i].ParentRaw;
      if raw = 0 then
      begin
        List[i].ParentVA := 0;
        List[i].ParentName := '';                 // root of the hierarchy
        Continue;
      end;

      if dict.TryGetValue(raw, j) then             // direct pointer (modern)
      begin
        List[i].ParentVA := raw;
        List[i].ParentName := List[j].Name;
        Continue;
      end;

      if FPE.ReadPtrVA(raw, raw2) and (raw2 <> 0) and dict.TryGetValue(raw2, j) then
      begin                                        // one indirection (older Delphi)
        List[i].ParentVA := raw2;
        List[i].ParentName := List[j].Name;
        Continue;
      end;

      List[i].ParentVA := raw;                     // parent lives outside this image
      List[i].ParentName := '(external)';
    end;
  finally
    dict.Free;
  end;
end;

procedure TDelphiVMTScanner.Scan;
var
  cands: TArray<Integer>;
  best, cur: TArray<TDelphiClass>;
  bestOff, i: Integer;
begin
  if FPE.Is64Bit then
    cands := TArray<Integer>.Create(-176)
  else
    cands := TArray<Integer>.Create(-88, -76);

  best := nil;
  bestOff := cands[0];
  for i := 0 to High(cands) do
  begin
    cur := ScanWithOffset(cands[i]);
    if Length(cur) > Length(best) then
    begin
      best := cur;
      bestOff := cands[i];
    end;
  end;

  FSelfPtrOffset := bestOff;
  ResolveParents(best);
  FClasses := best;
end;

function TDelphiVMTScanner.Count: Integer;
begin
  Result := Length(FClasses);
end;

function TDelphiVMTScanner.FindIndexByVA(VA: UInt64): Integer;
var
  i: Integer;
begin
  Result := -1;
  for i := 0 to High(FClasses) do
    if FClasses[i].ClassVA = VA then Exit(i);
end;

end.
