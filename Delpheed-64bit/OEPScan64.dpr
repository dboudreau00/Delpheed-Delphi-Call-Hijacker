program OEPScan64;

{$APPTYPE CONSOLE}

{
  Usage:  OEPScan64 <packed.exe> [dump.exe] [/aad] [/iat]

    /aad   hide the debugger from the target (x64 PEB patch + ntdll hooks)
    /iat   after dumping, rebuild the import table (-> *_fixed.exe)

  Finds the OEP of a packed 64-bit PE by stripping execute from non-stub
  sections and catching the execute fault. Build 64-bit (dcc64). VM only.
}

uses
  SysUtils,
  uConsoleOut in 'uConsoleOut.pas',
  uOEPFinder64 in 'uOEPFinder64.pas';

var
  target, dumpPath, a: string;
  r: TOEP64Result;
  f: TOEPFinder64;
  i: Integer;
  aad, iat: Boolean;
begin
  if ParamCount < 1 then
  begin
    COUsage('OEPScan64', '<packed.exe> [dump.exe] [/aad] [/iat]',
      'Find the OEP of a packed 64-bit PE; optionally hide the debugger and rebuild imports.');
    Halt(EXIT_USAGE);
  end;

  target := ParamStr(1);
  dumpPath := '';
  aad := False;
  iat := False;
  for i := 2 to ParamCount do
  begin
    a := ParamStr(i);
    if SameText(a, '/aad') then aad := True
    else if SameText(a, '/iat') then iat := True
    else if (dumpPath = '') and (Copy(a, 1, 1) <> '/') then dumpPath := a
    else
    begin
      COErr('Unrecognised argument: ' + a);
      Halt(EXIT_USAGE);
    end;
  end;

  if iat and (dumpPath = '') then
    dumpPath := ChangeFileExt(target, '') + '_dump.exe';

  f := TOEPFinder64.Create(
    procedure(const m: string)
    begin
      CONote(m);
    end);
  try
    f.AntiAntiDebug := aad;
    f.RebuildImports := iat;
    r := f.Find(target, dumpPath);
  finally
    f.Free;
  end;

  COSection('Result');
  if r.Success then
  begin
    COField('OEP VA', '$' + IntToHex(Int64(r.OEPVA), 16));
    COField('OEP RVA', '$' + IntToHex(Int64(r.OEPRVA), 8));
    COField('Image base', '$' + IntToHex(Int64(r.ImageBase), 16));
    if r.DumpFile <> '' then
      COField('Dump', r.DumpFile);
    COOk(r.Message);
    Halt(EXIT_OK);
  end
  else
  begin
    COErr(r.Message);
    Halt(EXIT_PROCESSING);
  end;
end.
