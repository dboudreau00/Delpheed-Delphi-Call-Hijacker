program OEPScan;

{$APPTYPE CONSOLE}

{
  Usage:  OEPScan <packed.exe> [dump.exe] [/aad] [/iat]

    /aad   hide the debugger from the target (PEB patch + ntdll hooks)
    /iat   after dumping, rebuild the import table (-> *_fixed.exe)

  Finds the OEP of a packed 32-bit PE by stripping execute from non-stub
  sections and catching the execute fault. Build 32-bit. VM only.
}

uses
  SysUtils,
  uConsoleOut in 'uConsoleOut.pas',
  uOEPFinder in 'uOEPFinder.pas';

var
  target, dumpPath, a: string;
  r: TOEPResult;
  f: TOEPFinder;
  i: Integer;
  aad, iat: Boolean;
begin
  if ParamCount < 1 then
  begin
    COUsage('OEPScan', '<packed.exe> [dump.exe] [/aad] [/iat]',
      'Find the OEP of a packed 32-bit PE; optionally hide the debugger and rebuild imports.');
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

  // rebuilding imports needs a dump to work from
  if iat and (dumpPath = '') then
    dumpPath := ChangeFileExt(target, '') + '_dump.exe';

  f := TOEPFinder.Create(
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
    COField('OEP VA', '$' + IntToHex(Int64(r.OEPVA), 8));
    COField('OEP RVA', '$' + IntToHex(Int64(r.OEPRVA), 8));
    COField('Image base', '$' + IntToHex(Int64(r.ImageBase), 8));
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
