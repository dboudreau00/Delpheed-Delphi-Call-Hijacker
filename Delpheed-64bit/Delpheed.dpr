program Delpheed;

{$APPTYPE CONSOLE}

{
  Delpheed - one-shot pipeline over a Delphi PE.

    Usage:  Delpheed <target.exe> [/aad]

      /aad   hide the debugger from the target during unpacking

  Steps, in order:
    1. Parse the PE and print a summary.
    2. Analyse packing (entropy, entry point, imports, known packer names).
    3. If it looks packed (and is 32-bit): run the OEP finder to unpack, dump,
       and rebuild imports, then analyse the unpacked image.
    4. Recover and list the Delphi classes (name, size, parent).

  Ties together: uPEFile, uPackDetect, uOEPFinder (which pulls in uAntiAntiDebug
  and uIATRebuild), and uDelphiVMT. Build 32-bit. Unpacking runs the target's
  stub - untrusted samples in a VM only.
}

uses
  SysUtils,
  Generics.Collections,
  Generics.Defaults,
  uConsoleOut in 'uConsoleOut.pas',
  uPEFile in 'uPEFile.pas',
  uPackDetect in 'uPackDetect.pas',
  uDelphiVMT in 'uDelphiVMT.pas',
  uOEPFinder in 'uOEPFinder.pas';

function HexVA(V: UInt64; Is64: Boolean): string;
begin
  if Is64 then Result := IntToHex(Int64(V), 16) else Result := IntToHex(Int64(V), 8);
end;

function LayoutName(O: Integer): string;
begin
  case O of
    -76:  Result := 'Delphi 2-7 (x86)';
    -88:  Result := 'Delphi 2009+ (x86)';
    -176: Result := 'Delphi (x64)';
  else
    Result := 'unknown';
  end;
end;

procedure ScanClasses(const Path: string);
var
  PE: TPEFile;
  Sc: TDelphiVMTScanner;
  arr: TArray<TDelphiClass>;
  c: TDelphiClass;
  i: Integer;
begin
  PE := TPEFile.Create;
  try
    PE.LoadFromFile(Path);
    Sc := TDelphiVMTScanner.Create(PE);
    try
      Sc.Scan;
      arr := Sc.Classes;

      COSection('Classes');
      COField('Source', Path);
      COField('Layout', Format('selfptr %d (%s)', [Sc.SelfPtrOffset, LayoutName(Sc.SelfPtrOffset)]));
      COField('Classes found', IntToStr(Length(arr)));
      if Length(arr) = 0 then
      begin
        CONote('No Delphi VMTs recovered from this image.');
        Exit;
      end;

      TArray.Sort<TDelphiClass>(arr, TComparer<TDelphiClass>.Construct(
        function(const A, B: TDelphiClass): Integer
        begin
          Result := CompareText(A.Name, B.Name);
        end));

      for i := 0 to High(arr) do
      begin
        c := arr[i];
        if c.ParentName = '' then
          COLine(Format('class: %s; size=%d; parent=none (root TObject)', [c.Name, c.InstanceSize]))
        else if c.ParentName = '(external)' then
          COLine(Format('class: %s; size=%d; parent=external', [c.Name, c.InstanceSize]))
        else
          COLine(Format('class: %s; size=%d; parent=%s', [c.Name, c.InstanceSize, c.ParentName]));
      end;
    finally
      Sc.Free;
    end;
  finally
    PE.Free;
  end;
end;

var
  target, scanTarget, dump, bitness: string;
  PE: TPEFile;
  v: TPackVerdict;
  r: TOEPResult;
  f: TOEPFinder;
  i: Integer;
  aad: Boolean;
begin
  if ParamCount < 1 then
  begin
    COUsage('Delpheed', '<target.exe> [/aad]',
      'Detect packing, unpack if needed, and list recovered Delphi classes.');
    Halt(EXIT_USAGE);
  end;

  target := ParamStr(1);
  aad := False;
  for i := 2 to ParamCount do
    if SameText(ParamStr(i), '/aad') then
      aad := True
    else
    begin
      COErr('Unrecognised argument: ' + ParamStr(i));
      Halt(EXIT_USAGE);
    end;

  scanTarget := target;

  PE := TPEFile.Create;
  try
    try
      PE.LoadFromFile(target);
    except
      on E: Exception do
      begin
        COErr('Cannot read input: ' + E.Message);
        Halt(EXIT_INPUT);
      end;
    end;

    if PE.Is64Bit then bitness := '64-bit (x64)' else bitness := '32-bit (x86)';

    COSection('PE summary');
    COField('File', target);
    COField('Bitness', bitness);
    COField('Image base', '$' + HexVA(PE.ImageBase, PE.Is64Bit));
    COField('Entry point RVA', '$' + IntToHex(PE.EntryPointRVA, 8));
    COField('Sections', IntToStr(Length(PE.Sections)));

    COSection('Packing analysis');
    v := AnalyzePacking(PE);
    COField('File entropy', Format('%.2f (of 8.0)', [v.FileEntropy]));
    if v.PackerName <> '' then
      COField('Packer', v.PackerName);
    COField('Likely packed', BoolToStr(v.LikelyPacked, True));
    COField('Confidence', IntToStr(v.Confidence) + '/100');
    for i := 0 to High(v.Reasons) do
      COLine('reason: ' + v.Reasons[i]);

    if v.LikelyPacked and PE.Is64Bit then
      COWarn('Target looks packed but is 64-bit; the unpacker is 32-bit only. Scanning as-is.')
    else if v.LikelyPacked then
    begin
      dump := ChangeFileExt(target, '') + '_unpacked.exe';
      COSection('Unpacking');
      f := TOEPFinder.Create(
        procedure(const m: string)
        begin
          CONote(m);
        end);
      try
        f.AntiAntiDebug := aad;
        f.RebuildImports := True;
        r := f.Find(target, dump);
      finally
        f.Free;
      end;

      if r.Success and (r.DumpFile <> '') then
      begin
        COOk(r.Message);
        scanTarget := r.DumpFile;
      end
      else
        COWarn('Unpack did not complete (' + r.Message + '); scanning original, which may find little.');
    end;
  finally
    PE.Free;
  end;

  try
    ScanClasses(scanTarget);
    COOk('Analysis complete.');
    Halt(EXIT_OK);
  except
    on E: Exception do
    begin
      COErr(E.ClassName + ': ' + E.Message);
      Halt(EXIT_PROCESSING);
    end;
  end;
end.
