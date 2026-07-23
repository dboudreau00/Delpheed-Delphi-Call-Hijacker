# Delpheed

A small reverse-engineering toolkit for **Delphi PE executables**, written in Delphi.
It parses the binary, recovers the class model from Delphi's runtime metadata, and — for
packed samples — unpacks them via a debugger so the real class information becomes
readable. Think of it as a focused, Delphi-aware slice of what IDA + Scylla do.

> **Safety.** The unpacking tools *run the target's own unpacking stub* under a debugger.
> Only point them at binaries you are authorised to analyse, and run untrusted samples
> inside a disposable virtual machine. The tools freeze the target at its original entry
> point and terminate it without ever running its real code, but the stub does execute.

**New here?** See **`TUTORIAL.md`** for a hands-on, step-by-step walkthrough.

## What it does

- **Recover the class hierarchy** of a Delphi binary — every class name, instance size,
  and parent — by locating VMTs through their self-pointer and validating them against
  Delphi's fixed VMT field layout (no disassembly required).
- **Detect packing** statically — per-section Shannon entropy, entry-point placement,
  import-table size, and known packer section-name signatures.
- **Unpack** common compressors two ways: the **ESP trick** (for `PUSHAD` stubs) and a
  **guard-page OEP finder** (for stubs that don't use `PUSHAD`).
- **Rebuild the import table** of a dump so it loads again (Scylla-style).
- **Hide the debugger** from protectors that check for it (PEB/heap patching + ntdll
  inline hooks).

## Pipeline

```
  target.exe
      |
      v
  [uPEFile]        parse headers, RVA<->offset<->VA, safe reads
      |
      v
  [uPackDetect]    packed?  -- no --> ---------------------------.
      |                                                          |
     yes                                                         |
      v                                                          |
  [uOEPFinder]     run under debug:                              |
    [uAntiAntiDebug]  hide the debugger (optional)               |
    strip execute from non-stub sections, catch OEP fault        |
    dump the unpacked image                                      |
    [uIATRebuild]     reconstruct imports -> *_fixed.exe         |
      |                                                          |
      v                                                          v
  [uDelphiVMT]     recover classes  <--------------------- (scan directly)
      |
      v
  class list (name, size, parent)
```

`OEPScan` / `Delpheed` wire these together; `uUnpacker` is the alternative ESP-trick
unpacker for `PUSHAD` stubs.

## Files

| File | Role |
|------|------|
| `uPEFile.pas` | PE32/PE32+ parser: headers, sections, address translation, bounds-checked reads |
| `uDelphiVMT.pas` | VMT scanner: recovers classes + hierarchy from self-pointers and VMT layout |
| `uPackDetect.pas` | Packer detection: entropy, entry point, imports, known packer names |
| `uUnpacker.pas` | ESP-trick unpacker for `PUSHAD` stubs (Debug API + hardware breakpoint) |
| `uOEPFinder.pas` | Guard-page OEP finder; integrates anti-anti-debug + import rebuild |
| `uIATRebuild.pas` | Import-table reconstruction from the resolved IAT and live module exports |
| `uAntiAntiDebug.pas` | PEB/heap patching + ntdll inline hooks to hide the debugger |
| `uOEPFinder64.pas` | 64-bit guard-page OEP finder (PE32+, x64 CONTEXT) |
| `uIATRebuild64.pas` | 64-bit import reconstruction (PE32+, 8-byte thunks) |
| `uAntiAntiDebug64.pas` | 64-bit anti-anti-debug (x64 PEB offsets, x64 ntdll hooks) |
| `uConsoleOut.pas` | Accessible console output (labelled text, word-based status, exit codes) |
| `VMTScan.dpr` | Driver: list classes in a PE (32/64-bit) |
| `Unpack.dpr` | Driver: ESP-trick unpack (32-bit) |
| `OEPScan.dpr` | Driver: guard-page unpack, 32-bit (`/aad`, `/iat`) |
| `OEPScan64.dpr` | Driver: guard-page unpack, 64-bit (`/aad`, `/iat`) |
| `Delpheed.dpr` | Driver: one-shot detect -> unpack -> analyse (32-bit) |
| `build.bat` | Build the tools with `dcc32` (32-bit) and `dcc64` (64-bit) |

## Build

The 32-bit tools build with `dcc32`, the 64-bit unpacker (`OEPScan64`) with `dcc64` —
each debugger must match its target's bitness. With RAD Studio installed:

```
rsvars.bat            rem puts dcc32/dcc64 on PATH  (or use a RAD Studio Command Prompt)
build.bat             rem builds the 32-bit tools, then OEPScan64 (64-bit), into bin\
```

To build one by hand: `dcc32 -B Delpheed.dpr`, or `dcc64 -B OEPScan64.dpr`. Requires
Delphi 10.3+ (the code uses inline variables and generics). Short RTL unit names
(`SysUtils`, `Classes`) are used so the static units also compile on older, pre-namespace
Delphi.

## Usage

```
VMTScan       <target.exe|dll>
Unpack        <packed.exe> [output.exe]
OEPScan       <packed.exe> [dump.exe] [/aad] [/iat]    (32-bit target)
OEPScan64     <packed.exe> [dump.exe] [/aad] [/iat]    (64-bit target)
Delpheed      <target.exe> [/aad]
```

Typical one-shot run:

```
Delpheed suspicious.exe /aad
```

which detects packing, unpacks (hiding the debugger, rebuilding imports to
`suspicious_unpacked_fixed.exe`), and lists the recovered classes.

Manual, step by step:

```
OEPScan packed.exe packed_dump.exe /aad /iat
VMTScan packed_dump.exe
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | bad or missing arguments |
| 2 | input could not be read / not a valid PE |
| 3 | ran, but the operation failed |

## Accessibility

This is a command-line project, so "accessible" here means terminal/screen-reader
friendly, via `uConsoleOut`:

- status is carried by **words** (`OK:`, `ERROR:`, `WARNING:`, `INFO:`), never colour;
- output is **linear and labelled** (`Name: value`), not aligned columns or tables;
- no box-drawing, spinners, or cursor tricks;
- **errors and warnings go to stderr**, normal output to stdout;
- a quiet mode drops decorative output but keeps the result line;
- every tool returns a **meaningful exit code**.

## Scope and limits

- **Both bitnesses are supported.** The static tools handle PE32 and PE32+. For unpacking,
  32-bit targets use `OEPScan` / `Delpheed` / `Unpack` (built `dcc32`), and 64-bit targets
  use `OEPScan64` (built `dcc64`). The ESP-trick unpacker (`Unpack`) is 32-bit only —
  `PUSHAD`/`POPAD` don't exist on x64 — so x64 uses the guard-page finder. `Delpheed`'s
  one-shot pipeline currently drives the 32-bit unpacker; for a 64-bit target, run
  `OEPScan64` then `VMTScan` on the dump.
- **Plain compressors** (UPX, ASPack, MPRESS, older PECompact) unpack well. Strong
  protectors (Themida, VMProtect, Enigma) use anti-debug and virtualization that these
  methods do not defeat.
- The **guard-page finder needs DEP** enforced (the default for 32-bit processes on
  64-bit Windows).
- **Import reconstruction is heuristic** (longest run of module-pointers) and flags any
  unresolved thunks rather than guessing them.
- Dumps assume the target sits at its preferred/actual image base; a stub that manages
  its own page protections or unpacks outside the image can defeat the finder.

## Roadmap

- **Disassembly-from-OEP IAT search** — replace the heuristic IAT scan with a precise one
  that follows `call/jmp [mem]` from the OEP. Needs a small x86 length-disassembler; left
  out for now because a length decoder can't be validated without compiling, and a wrong
  one silently desyncs.
- **RTTI pass** — walk the TypeInfo/Field/Method tables (already exposed per class) to
  recover published properties, methods, and enum names.
- **x64 depth** — `OEPScan64` covers 64-bit unpacking + import rebuild; still to do are a
  64-bit path in the `Delpheed` one-shot and wider validation of the x64 ntdll hooks.
