unit uPackDetect;

{
  uPackDetect - decide whether a PE is packed/protected before you try to
  analyse it, and name the packer when the section layout gives it away.

  Signals used (each is weak alone, strong together):
    * Shannon entropy per section and for the whole file. Compressed or
      encrypted data sits near 8.0 bits/byte; normal code/data is well under 7.
    * Entry point living in the last section, or in a writable section, or in
      a high-entropy section - all classic stub tells.
    * A tiny import table (often just KERNEL32 with LoadLibrary/GetProcAddress),
      because the stub resolves everything else at runtime.
    * Known packer section names (UPX0/UPX1, .aspack, .vmp0, .themida, ...).

  This is pure static analysis on top of TPEFile - no code from the target is
  executed. It tells you "packed / probably packed / clean" and, when it can,
  which packer, so the analyzer can refuse the VMT scan or hand off to an
  unpacking step instead of reporting nonsense.
}

interface

uses
  SysUtils, Math, Generics.Collections, uPEFile;

type
  TSectionScan = record
    Name: string;
    Entropy: Double;
    Writable: Boolean;
    Executable: Boolean;
    RawSize: Cardinal;
    VirtualSize: Cardinal;
  end;

  TPackVerdict = record
    LikelyPacked: Boolean;
    Confidence: Integer;         // rough 0..100
    PackerName: string;          // '' when unknown
    FileEntropy: Double;
    EPSectionName: string;
    EPSectionEntropy: Double;
    EPInLastSection: Boolean;
    EPWritable: Boolean;
    ImportedDLLCount: Integer;
    Reasons: TArray<string>;
    Sections: TArray<TSectionScan>;
  end;

function AnalyzePacking(PE: TPEFile): TPackVerdict;

implementation

const
  IMAGE_SCN_CNT_CODE   = $00000020;
  IMAGE_SCN_MEM_EXECUTE= $20000000;
  IMAGE_SCN_MEM_WRITE  = $80000000;

type
  TPackSig = record
    Sect: string;
    Name: string;
  end;

const
  // matched case-insensitively; a section starting with Sect counts as a hit
  SIGS: array[0..21] of TPackSig = (
    (Sect: 'UPX0';     Name: 'UPX'),
    (Sect: 'UPX1';     Name: 'UPX'),
    (Sect: 'UPX2';     Name: 'UPX'),
    (Sect: '.aspack';  Name: 'ASPack'),
    (Sect: '.adata';   Name: 'ASPack'),
    (Sect: '.petite';  Name: 'Petite'),
    (Sect: 'pec1';     Name: 'PECompact'),
    (Sect: 'pec2';     Name: 'PECompact'),
    (Sect: 'PEC2';     Name: 'PECompact'),
    (Sect: '.MPRESS1'; Name: 'MPRESS'),
    (Sect: '.MPRESS2'; Name: 'MPRESS'),
    (Sect: '.themida'; Name: 'Themida/WinLicense'),
    (Sect: '.winlice'; Name: 'Themida/WinLicense'),
    (Sect: '.enigma1'; Name: 'Enigma'),
    (Sect: '.enigma2'; Name: 'Enigma'),
    (Sect: '.vmp0';    Name: 'VMProtect'),
    (Sect: '.vmp1';    Name: 'VMProtect'),
    (Sect: '.nsp0';    Name: 'NsPack'),
    (Sect: '.nsp1';    Name: 'NsPack'),
    (Sect: 'nsp0';     Name: 'NsPack'),
    (Sect: 'MEW';      Name: 'MEW'),
    (Sect: 'kkrunchy'; Name: 'kkrunchy')
  );

function ShannonEntropy(const Buf: TBytes; Start, Len: NativeInt): Double;
var
  counts: array[0..255] of Int64;
  i: NativeInt;
  c: Integer;
  p: Double;
  avail: Int64;
begin
  Result := 0;
  if (Start < 0) or (Start >= Length(Buf)) or (Len = 0) then Exit;
  // Measure the bytes actually present: a section whose raw extent overhangs the
  // file (or whose size truncated negative) must not read as entropy 0 and hide a
  // packed stub. Clamp to the remaining buffer instead of discarding the section.
  avail := Int64(Length(Buf)) - Start;
  if (Len < 0) or (Len > avail) then Len := avail;
  FillChar(counts, SizeOf(counts), 0);
  for i := Start to Start + Len - 1 do
    Inc(counts[Buf[i]]);
  for c := 0 to 255 do
    if counts[c] > 0 then
    begin
      p := counts[c] / Len;
      Result := Result - p * Log2(p);
    end;
end;

function ReadCString(PE: TPEFile; RVA: Cardinal): AnsiString;
var
  ofs: Int64;
  img: TBytes;
  n: NativeInt;
begin
  Result := '';
  ofs := PE.RVAToOffset(RVA);
  if ofs < 0 then Exit;
  img := PE.Image;
  n := 0;
  while (ofs + n < Length(img)) and (img[ofs + n] <> 0) and (n < 256) do
    Inc(n);
  if n > 0 then
  begin
    SetLength(Result, n);
    Move(img[ofs], Result[1], n);
  end;
end;

function CountImportDLLs(PE: TPEFile): Integer;
var
  dir: TImageDataDirectory;
  desc, nameRVA, ofth, fth: Cardinal;
  i: Integer;
begin
  Result := 0;
  dir := PE.DataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
  if dir.VirtualAddress = 0 then Exit;
  i := 0;
  while i < 4096 do
  begin
    desc := dir.VirtualAddress + Cardinal(i) * 20;   // IMAGE_IMPORT_DESCRIPTOR = 20 bytes
    if not PE.ReadDWordRVA(desc + 0,  ofth) then Break;
    if not PE.ReadDWordRVA(desc + 12, nameRVA) then Break;
    if not PE.ReadDWordRVA(desc + 16, fth) then Break;
    if (ofth = 0) and (nameRVA = 0) and (fth = 0) then Break;  // terminator
    if nameRVA <> 0 then
      Inc(Result);
    Inc(i);
    if Result > 512 then Break;
  end;
end;

function AnalyzePacking(PE: TPEFile): TPackVerdict;
var
  V: TPackVerdict;
  reasons: TList<string>;
  img: TBytes;
  i, j, epIdx: Integer;
  ss: TSectionScan;
  ch: Cardinal;
  hiEntropySections: Integer;
  upName: string;
begin
  V := Default(TPackVerdict);
  reasons := TList<string>.Create;
  try
    img := PE.Image;
    V.FileEntropy := ShannonEntropy(img, 0, Length(img));

    // ---- per section ----
    SetLength(V.Sections, Length(PE.Sections));
    hiEntropySections := 0;
    for i := 0 to High(PE.Sections) do
    begin
      ch := PE.Sections[i].Characteristics;
      ss.Name        := PE.Sections[i].Name;
      ss.RawSize     := PE.Sections[i].SizeOfRawData;
      ss.VirtualSize := PE.Sections[i].VirtualSize;
      ss.Writable    := (ch and IMAGE_SCN_MEM_WRITE) <> 0;
      ss.Executable  := (ch and IMAGE_SCN_MEM_EXECUTE) <> 0;
      ss.Entropy     := ShannonEntropy(img, PE.Sections[i].PointerToRawData,
                                            PE.Sections[i].SizeOfRawData);
      V.Sections[i] := ss;
      if (ss.RawSize >= 512) and (ss.Entropy >= 7.0) then
        Inc(hiEntropySections);
    end;

    // ---- known packer by section name ----
    for i := 0 to High(PE.Sections) do
    begin
      upName := UpperCase(PE.Sections[i].Name);
      for j := 0 to High(SIGS) do
        if (upName = UpperCase(SIGS[j].Sect)) or
           ((Length(upName) > 0) and
            (Pos(UpperCase(SIGS[j].Sect), upName) = 1)) then
        begin
          V.PackerName := SIGS[j].Name;
          reasons.Add('Section "' + PE.Sections[i].Name + '" matches ' + SIGS[j].Name);
          Break;
        end;
      if V.PackerName <> '' then Break;
    end;

    // ---- entry point analysis ----
    epIdx := PE.SectionIndexForRVA(PE.EntryPointRVA);
    if epIdx >= 0 then
    begin
      V.EPSectionName    := PE.Sections[epIdx].Name;
      V.EPSectionEntropy := V.Sections[epIdx].Entropy;
      V.EPInLastSection  := (epIdx = High(PE.Sections));
      V.EPWritable       := V.Sections[epIdx].Writable;
    end;

    // ---- imports ----
    V.ImportedDLLCount := CountImportDLLs(PE);

    // ---- score ----
    if V.PackerName <> '' then
      V.Confidence := 90;

    if V.FileEntropy >= 7.5 then
    begin
      Inc(V.Confidence, 40);
      reasons.Add(Format('Very high file entropy (%.2f)', [V.FileEntropy]));
    end
    else if V.FileEntropy >= 7.0 then
    begin
      Inc(V.Confidence, 25);
      reasons.Add(Format('High file entropy (%.2f)', [V.FileEntropy]));
    end;

    if V.EPInLastSection then
    begin
      Inc(V.Confidence, 20);
      reasons.Add('Entry point is in the last section');
    end;
    if V.EPWritable then
    begin
      Inc(V.Confidence, 25);
      reasons.Add('Entry point section is writable (self-modifying stub)');
    end;
    if V.EPSectionEntropy >= 7.0 then
    begin
      Inc(V.Confidence, 20);
      reasons.Add(Format('Entry point section entropy is high (%.2f)',
        [V.EPSectionEntropy]));
    end;

    if (V.ImportedDLLCount = 1) then
    begin
      Inc(V.Confidence, 20);
      reasons.Add('Only one imported DLL (imports likely resolved at runtime)');
    end
    else if (V.ImportedDLLCount = 2) then
    begin
      Inc(V.Confidence, 10);
      reasons.Add('Very small import table (2 DLLs)');
    end;

    if (Length(PE.Sections) <= 3) and (hiEntropySections >= 1) then
    begin
      Inc(V.Confidence, 10);
      reasons.Add('Few sections with high-entropy content');
    end;

    if V.Confidence > 100 then V.Confidence := 100;
    V.LikelyPacked := (V.PackerName <> '') or (V.Confidence >= 50);

    V.Reasons := reasons.ToArray;
    Result := V;
  finally
    reasons.Free;
  end;
end;

end.
