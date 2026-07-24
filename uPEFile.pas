unit uPEFile;

{
  uPEFile - minimal, self-contained PE (Portable Executable) reader.

  Parses 32-bit (PE32) and 64-bit (PE32+) images by reading raw bytes, so it
  works regardless of the OS it runs on (we are parsing a file, not loading it).

  It gives you:
    - basic headers (bitness, image base, entry point, sections)
    - RVA <-> file-offset <-> VA translation
    - bounds-checked reads at an RVA or VA (dword, pointer, ShortString, bytes)

  Assumption: the file is on disk at its *preferred* image base, so absolute
  pointers stored in initialised data equal ImageBase + RVA. (True for normal
  compiler output. A dumped/rebased image would need reloc fix-ups first.)

  Targets modern Delphi. Short unit names (SysUtils/Classes) are used so it also
  compiles on pre-namespace Delphi versions.
}

interface

uses
  SysUtils, Classes;

type
  EPEFile = class(Exception);

  TImageDataDirectory = record
    VirtualAddress: Cardinal;
    Size: Cardinal;
  end;

  TPESectionInfo = record
    Name: string;
    VirtualAddress: Cardinal;
    VirtualSize: Cardinal;
    PointerToRawData: Cardinal;
    SizeOfRawData: Cardinal;
    Characteristics: Cardinal;
  end;

  TPEFile = class
  private
    FImage: TBytes;
    FIs64: Boolean;
    FMachine: Word;
    FImageBase: UInt64;
    FEntryPointRVA: Cardinal;
    FSizeOfHeaders: Cardinal;
    FSectionAlignment: Cardinal;
    FFileAlignment: Cardinal;
    FNumberOfRvaAndSizes: Cardinal;
    FSections: TArray<TPESectionInfo>;
    FDataDirs: TArray<TImageDataDirectory>;
    function GetPointerSize: Integer;
    function ChkRange(Offset: Int64; Size: Integer): Boolean; inline;
    function RawWord(Offset: Cardinal): Word;
    function RawDWord(Offset: Cardinal): Cardinal;
    function RawQWord(Offset: Cardinal): UInt64;
    procedure Parse;
  public
    constructor Create;

    procedure LoadFromFile(const FileName: string);
    procedure LoadFromStream(Stream: TStream);
    procedure LoadFromBytes(const Bytes: TBytes);

    // ---- address translation ----
    function SectionIndexForRVA(RVA: Cardinal): Integer;
    function RVAToOffset(RVA: Cardinal): Int64;   // -1 if not backed by raw data
    function OffsetToRVA(Offset: Cardinal): Int64; // -1 if not inside a section
    function IsValidRVA(RVA: Cardinal): Boolean;
    function VAToRVA(VA: UInt64): Int64;          // -1 if below image base
    function RVAToVA(RVA: Cardinal): UInt64;

    // ---- reads by RVA (all return False on out-of-range) ----
    function ReadBytesRVA(RVA: Cardinal; var Buffer; Count: Integer): Boolean;
    function ReadDWordRVA(RVA: Cardinal; out Value: Cardinal): Boolean;
    function ReadPtrRVA(RVA: Cardinal; out Value: UInt64): Boolean; // 4 or 8 bytes
    function ReadShortStringRVA(RVA: Cardinal; out S: AnsiString): Boolean;

    // ---- reads by VA (convenience wrappers) ----
    function ReadDWordVA(VA: UInt64; out Value: Cardinal): Boolean;
    function ReadPtrVA(VA: UInt64; out Value: UInt64): Boolean;
    function ReadShortStringVA(VA: UInt64; out S: AnsiString): Boolean;

    function DataDirectory(Index: Integer): TImageDataDirectory;

    property Image: TBytes read FImage;
    property Is64Bit: Boolean read FIs64;
    property Machine: Word read FMachine;
    property ImageBase: UInt64 read FImageBase;
    property EntryPointRVA: Cardinal read FEntryPointRVA;
    property SizeOfHeaders: Cardinal read FSizeOfHeaders;
    property PointerSize: Integer read GetPointerSize;
    property Sections: TArray<TPESectionInfo> read FSections;
  end;

const
  IMAGE_DIRECTORY_ENTRY_EXPORT   = 0;
  IMAGE_DIRECTORY_ENTRY_IMPORT   = 1;
  IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;

  IMAGE_FILE_MACHINE_I386  = $014C;
  IMAGE_FILE_MACHINE_AMD64 = $8664;

implementation

constructor TPEFile.Create;
begin
  inherited Create;
end;

function TPEFile.GetPointerSize: Integer;
begin
  if FIs64 then Result := 8 else Result := 4;
end;

function TPEFile.ChkRange(Offset: Int64; Size: Integer): Boolean;
begin
  Result := (Offset >= 0) and (Size >= 0) and (Offset + Size <= Length(FImage));
end;

function TPEFile.RawWord(Offset: Cardinal): Word;
begin
  if not ChkRange(Offset, 2) then
    raise EPEFile.CreateFmt('Read out of bounds (word @ %u)', [Offset]);
  Result := PWord(@FImage[Offset])^;
end;

function TPEFile.RawDWord(Offset: Cardinal): Cardinal;
begin
  if not ChkRange(Offset, 4) then
    raise EPEFile.CreateFmt('Read out of bounds (dword @ %u)', [Offset]);
  Result := PCardinal(@FImage[Offset])^;
end;

function TPEFile.RawQWord(Offset: Cardinal): UInt64;
begin
  if not ChkRange(Offset, 8) then
    raise EPEFile.CreateFmt('Read out of bounds (qword @ %u)', [Offset]);
  Result := PUInt64(@FImage[Offset])^;
end;

procedure TPEFile.Parse;
var
  lfanew, optOfs, secOfs, ddStart, ddCount: Cardinal;
  magic, numSecs, sizeOpt: Word;
  i, j: Integer;
  nm: array[0..8] of AnsiChar;
begin
  FIs64 := False;
  FImageBase := 0;
  FSections := nil;
  FDataDirs := nil;

  if Length(FImage) < 64 then
    raise EPEFile.Create('File too small to be a PE image');
  if RawWord(0) <> $5A4D then                 // 'MZ'
    raise EPEFile.Create('Missing MZ signature');

  lfanew := RawDWord($3C);                     // e_lfanew
  if not ChkRange(lfanew, 24) then
    raise EPEFile.Create('Invalid e_lfanew');
  if RawDWord(lfanew) <> $00004550 then        // 'PE'#0#0
    raise EPEFile.Create('Missing PE signature');

  FMachine := RawWord(lfanew + 4);
  numSecs  := RawWord(lfanew + 6);
  sizeOpt  := RawWord(lfanew + 20);
  optOfs   := lfanew + 24;                      // optional header follows file header

  magic := RawWord(optOfs);
  case magic of
    $10B: FIs64 := False;                       // PE32
    $20B: FIs64 := True;                        // PE32+
  else
    raise EPEFile.CreateFmt('Unknown optional header magic $%x', [magic]);
  end;

  FEntryPointRVA    := RawDWord(optOfs + 16);
  FSectionAlignment := RawDWord(optOfs + 32);
  FFileAlignment    := RawDWord(optOfs + 36);
  FSizeOfHeaders    := RawDWord(optOfs + 60);   // same offset in PE32 and PE32+

  if FIs64 then
  begin
    FImageBase           := RawQWord(optOfs + 24);
    FNumberOfRvaAndSizes := RawDWord(optOfs + 108);
    ddStart              := optOfs + 112;
  end
  else
  begin
    FImageBase           := RawDWord(optOfs + 28);
    FNumberOfRvaAndSizes := RawDWord(optOfs + 92);
    ddStart              := optOfs + 96;
  end;

  ddCount := FNumberOfRvaAndSizes;
  if ddCount > 16 then ddCount := 16;
  SetLength(FDataDirs, ddCount);
  for i := 0 to Integer(ddCount) - 1 do
  begin
    FDataDirs[i].VirtualAddress := RawDWord(ddStart + Cardinal(i) * 8);
    FDataDirs[i].Size           := RawDWord(ddStart + Cardinal(i) * 8 + 4);
  end;

  secOfs := optOfs + sizeOpt;
  if not ChkRange(secOfs, Integer(numSecs) * 40) then
    raise EPEFile.Create('Section table runs past end of file');

  SetLength(FSections, numSecs);
  for i := 0 to numSecs - 1 do
  begin
    FillChar(nm, SizeOf(nm), 0);
    for j := 0 to 7 do
      nm[j] := AnsiChar(FImage[secOfs + Cardinal(i) * 40 + Cardinal(j)]);
    nm[8] := #0;
    FSections[i].Name             := string(AnsiString(PAnsiChar(@nm[0])));
    FSections[i].VirtualSize      := RawDWord(secOfs + Cardinal(i) * 40 + 8);
    FSections[i].VirtualAddress   := RawDWord(secOfs + Cardinal(i) * 40 + 12);
    FSections[i].SizeOfRawData    := RawDWord(secOfs + Cardinal(i) * 40 + 16);
    FSections[i].PointerToRawData := RawDWord(secOfs + Cardinal(i) * 40 + 20);
    FSections[i].Characteristics  := RawDWord(secOfs + Cardinal(i) * 40 + 36);
  end;
end;

procedure TPEFile.LoadFromBytes(const Bytes: TBytes);
begin
  FImage := Copy(Bytes, 0, Length(Bytes));
  Parse;
end;

procedure TPEFile.LoadFromStream(Stream: TStream);
var
  n: Int64;
begin
  n := Stream.Size - Stream.Position;
  if n < 0 then n := 0;                  // stream positioned past its end
  SetLength(FImage, n);
  if n > 0 then
    Stream.ReadBuffer(FImage[0], n);
  Parse;
end;

procedure TPEFile.LoadFromFile(const FileName: string);
var
  fs: TFileStream;
begin
  fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(fs);
  finally
    fs.Free;
  end;
end;

function TPEFile.SectionIndexForRVA(RVA: Cardinal): Integer;
var
  i: Integer;
  vsize: Cardinal;
begin
  Result := -1;
  for i := 0 to High(FSections) do
  begin
    vsize := FSections[i].VirtualSize;
    if vsize = 0 then
      vsize := FSections[i].SizeOfRawData;
    if (RVA >= FSections[i].VirtualAddress) and
       (UInt64(RVA) < UInt64(FSections[i].VirtualAddress) + UInt64(vsize)) then
      Exit(i);
  end;
end;

function TPEFile.RVAToOffset(RVA: Cardinal): Int64;
var
  idx: Integer;
  delta: Cardinal;
begin
  if RVA < FSizeOfHeaders then
    Exit(RVA);                                  // header region: RVA = file offset
  idx := SectionIndexForRVA(RVA);
  if idx < 0 then Exit(-1);
  delta := RVA - FSections[idx].VirtualAddress;
  if delta >= FSections[idx].SizeOfRawData then
    Exit(-1);                                   // in the zero-filled (BSS) tail
  Result := Int64(FSections[idx].PointerToRawData) + delta;
end;

function TPEFile.OffsetToRVA(Offset: Cardinal): Int64;
var
  i: Integer;
begin
  Result := -1;
  if Offset < FSizeOfHeaders then Exit(Offset);
  for i := 0 to High(FSections) do
    if (FSections[i].SizeOfRawData > 0) and
       (Offset >= FSections[i].PointerToRawData) and
       (Offset <  FSections[i].PointerToRawData + FSections[i].SizeOfRawData) then
      Exit(Int64(FSections[i].VirtualAddress) + (Offset - FSections[i].PointerToRawData));
end;

function TPEFile.IsValidRVA(RVA: Cardinal): Boolean;
begin
  Result := (RVA < FSizeOfHeaders) or (SectionIndexForRVA(RVA) >= 0);
end;

function TPEFile.VAToRVA(VA: UInt64): Int64;
begin
  if VA < FImageBase then Exit(-1);
  if (VA - FImageBase) > $FFFFFFFF then Exit(-1);
  Result := Int64(VA - FImageBase);
end;

function TPEFile.RVAToVA(RVA: Cardinal): UInt64;
begin
  Result := FImageBase + RVA;
end;

function TPEFile.ReadBytesRVA(RVA: Cardinal; var Buffer; Count: Integer): Boolean;
var
  ofs: Int64;
  idx: Integer;
  delta: Cardinal;
begin
  Result := False;
  if Count <= 0 then Exit;
  ofs := RVAToOffset(RVA);
  if ofs < 0 then Exit;
  if ofs + Count > Length(FImage) then Exit;
  // Do not let a read run past the resolved section's raw data into the next
  // section: a value spliced from two unrelated addresses would be silently wrong.
  if RVA >= FSizeOfHeaders then
  begin
    idx := SectionIndexForRVA(RVA);
    if idx >= 0 then
    begin
      delta := RVA - FSections[idx].VirtualAddress;
      if Int64(delta) + Count > FSections[idx].SizeOfRawData then Exit;
    end;
  end;
  Move(FImage[ofs], Buffer, Count);
  Result := True;
end;

function TPEFile.ReadDWordRVA(RVA: Cardinal; out Value: Cardinal): Boolean;
begin
  Value := 0;
  Result := ReadBytesRVA(RVA, Value, 4);
end;

function TPEFile.ReadPtrRVA(RVA: Cardinal; out Value: UInt64): Boolean;
var
  d: Cardinal;
begin
  Value := 0;
  if FIs64 then
    Result := ReadBytesRVA(RVA, Value, 8)
  else
  begin
    d := 0;
    Result := ReadBytesRVA(RVA, d, 4);
    if Result then Value := d;
  end;
end;

function TPEFile.ReadShortStringRVA(RVA: Cardinal; out S: AnsiString): Boolean;
var
  ofs: Int64;
  len: Byte;
begin
  S := '';
  Result := False;
  ofs := RVAToOffset(RVA);
  if ofs < 0 then Exit;
  if ofs + 1 > Length(FImage) then Exit;
  len := FImage[ofs];
  if len = 0 then Exit;
  if ofs + 1 + len > Length(FImage) then Exit;
  SetLength(S, len);
  Move(FImage[ofs + 1], S[1], len);
  Result := True;
end;

function TPEFile.ReadDWordVA(VA: UInt64; out Value: Cardinal): Boolean;
var
  r: Int64;
begin
  Value := 0;
  r := VAToRVA(VA);
  if r < 0 then Exit(False);
  Result := ReadDWordRVA(Cardinal(r), Value);
end;

function TPEFile.ReadPtrVA(VA: UInt64; out Value: UInt64): Boolean;
var
  r: Int64;
begin
  Value := 0;
  r := VAToRVA(VA);
  if r < 0 then Exit(False);
  Result := ReadPtrRVA(Cardinal(r), Value);
end;

function TPEFile.ReadShortStringVA(VA: UInt64; out S: AnsiString): Boolean;
var
  r: Int64;
begin
  S := '';
  r := VAToRVA(VA);
  if r < 0 then Exit(False);
  Result := ReadShortStringRVA(Cardinal(r), S);
end;

function TPEFile.DataDirectory(Index: Integer): TImageDataDirectory;
begin
  if (Index >= 0) and (Index <= High(FDataDirs)) then
    Result := FDataDirs[Index]
  else
  begin
    Result.VirtualAddress := 0;
    Result.Size := 0;
  end;
end;

end.
