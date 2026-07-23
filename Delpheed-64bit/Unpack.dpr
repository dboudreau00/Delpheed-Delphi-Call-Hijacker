program Unpack;

{$APPTYPE CONSOLE}

{
  Usage:  Unpack <packed.exe> [output.exe]

  Unpacks a PUSHAD-stub 32-bit packer via the ESP trick. Build 32-bit. VM only.
  For non-PUSHAD stubs, or to hide the debugger and rebuild imports, use OEPScan.
}

uses
  SysUtils,
  uConsoleOut in 'uConsoleOut.pas',
  uUnpacker in 'uUnpacker.pas';

var
  outPath: string;
  r: TUnpackResult;
  u: TGenericUnpacker;
begin
  if ParamCount < 1 then
  begin
    COUsage('Unpack', '<packed.exe> [output.exe]',
      'Unpack a PUSHAD-stub 32-bit packer via the ESP trick.');
    Halt(EXIT_USAGE);
  end;

  if ParamCount >= 2 then
    outPath := ParamStr(2)
  else
    outPath := ChangeFileExt(ParamStr(1), '') + '_dump.exe';

  u := TGenericUnpacker.Create(
    procedure(const m: string)
    begin
      CONote(m);
    end);
  try
    r := u.Unpack(ParamStr(1), outPath);
  finally
    u.Free;
  end;

  COSection('Result');
  if r.Success then
  begin
    COField('OEP RVA', '$' + IntToHex(Int64(r.OEPRVA), 8));
    COField('Image base', '$' + IntToHex(Int64(r.ImageBase), 8));
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
