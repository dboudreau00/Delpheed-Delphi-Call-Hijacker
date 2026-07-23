unit uConsoleOut;

{
  uConsoleOut - one accessible output surface for all the command-line tools.

  Accessibility choices (this is a CLI, so "accessible" means works well with
  screen readers and text-only terminals):

    * Status is carried by WORDS, never colour - every line that means something
      is prefixed "OK:", "ERROR:", "WARNING:", or "INFO:". A screen reader speaks
      those; a colour-blind or monochrome user still gets the meaning.
    * Output is LINEAR and LABELLED - "Name: value", one fact per line - instead
      of aligned columns or tables that assistive tech reads out of order.
    * No box-drawing, ASCII-art, spinners, or cursor tricks; sections are marked
      with plain "== Title ==" text.
    * Errors and warnings go to STDERR, normal output to STDOUT, so they can be
      separated, redirected, or read by a different voice.
    * Quiet mode drops the decorative INFO/section chatter but always keeps the
      result line (OK/ERROR), so scripted and screen-reader use stays terse.
    * Every tool returns a MEANINGFUL exit code (constants below) so success and
      the kind of failure are detectable without parsing text.
}

interface

const
  EXIT_OK         = 0;   // completed successfully
  EXIT_USAGE      = 1;   // bad or missing command-line arguments
  EXIT_INPUT      = 2;   // input could not be read / was not valid
  EXIT_PROCESSING = 3;   // ran, but the operation failed

procedure COSetQuiet(Quiet: Boolean);

procedure COSection(const Title: string);           // "== Title =="
procedure COField(const Name, Value: string);       // "Name: Value"
procedure COLine(const Text: string);               // plain informational line
procedure CONote(const Msg: string);                // "INFO: ..."
procedure COWarn(const Msg: string);                // "WARNING: ..." (stderr)
procedure COErr(const Msg: string);                 // "ERROR: ..."   (stderr)
procedure COOk(const Msg: string);                  // "OK: ..."
procedure COUsage(const Prog, Args, Desc: string);  // usage help

implementation

var
  GQuiet: Boolean = False;

procedure COSetQuiet(Quiet: Boolean);
begin
  GQuiet := Quiet;
end;

procedure COSection(const Title: string);
begin
  if GQuiet then Exit;
  Writeln;
  Writeln('== ', Title, ' ==');
end;

procedure COField(const Name, Value: string);
begin
  if GQuiet then Exit;
  Writeln(Name, ': ', Value);
end;

procedure COLine(const Text: string);
begin
  if GQuiet then Exit;
  Writeln(Text);
end;

procedure CONote(const Msg: string);
begin
  if GQuiet then Exit;
  Writeln('INFO: ', Msg);
end;

procedure COWarn(const Msg: string);
begin
  Writeln(ErrOutput, 'WARNING: ', Msg);
end;

procedure COErr(const Msg: string);
begin
  Writeln(ErrOutput, 'ERROR: ', Msg);
end;

procedure COOk(const Msg: string);
begin
  Writeln('OK: ', Msg);
end;

procedure COUsage(const Prog, Args, Desc: string);
begin
  Writeln('Usage: ', Prog, ' ', Args);
  if Desc <> '' then
    Writeln(Desc);
end;

end.
