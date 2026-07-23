# Delpheed — Step-by-step tutorial

This walks you from an empty machine to reading the class list out of a packed
Delphi binary. Follow it in order the first time.

---

## 0. What you need

- **Windows** — the unpacking tools use the Windows debug API.
- **Delphi / RAD Studio 10.3 Rio or newer** (the code uses inline variables and
  generics). The free Community Edition is fine.
- **A throwaway virtual machine with snapshots** if you'll analyse anything you
  don't fully trust. The unpackers **run the target's own unpacking stub** — treat
  every packed sample as live code.
- Targets you unpack must be **32-bit** (PE32). The static class scanner reads
  64-bit too, but the unpackers are 32-bit only.

> **Rule:** only analyse binaries you are authorised to. Unpack untrusted samples
> in a VM you can roll back.

---

## 1. Get the code onto your machine

Extract the zip. You'll get a `Delpheed/` folder containing the `.pas`/`.dpr`
sources, `build.bat`, `README.md`, and this tutorial.

To publish it on GitHub: create a new repository named **Delpheed**, copy these
files into it (the included `.gitignore` keeps build output out of the repo), then
commit and push.

---

## 2. Build the tools

1. Open a **RAD Studio Command Prompt** (Start menu), or open a normal command
   prompt and run `rsvars.bat` from your RAD Studio `bin` folder to put `dcc32` on
   the PATH.
2. `cd` into the `Delpheed` folder.
3. Run:

   ```
   build.bat
   ```

You should end up with four executables in `bin\`:

```
bin\VMTScan.exe      list classes in a PE
bin\Unpack.exe       unpack a PUSHAD-stub packer (ESP trick)
bin\OEPScan.exe      unpack via the guard-page OEP finder
bin\Delpheed.exe     one-shot: detect -> unpack -> analyse
```

To build a single tool by hand: `dcc32 -B Delpheed.dpr`.

---

## 3. Tutorial A — list the classes in a normal Delphi program

Pick any Delphi-built `.exe` you have (or compile a small VCL app). Run:

```
bin\VMTScan.exe C:\path\to\App.exe
```

Read the output top to bottom:

- **PE summary** — bitness, image base, entry point, section count.
- **VMT scan → Layout** — e.g. `selfptr -88 (Delphi 2009+ (x86))`. This is how
  Delpheed dates the binary from its VMT shape.
- **Classes** — one line each: `class: TButton; size=272; parent=TWinControl`.
  A root class shows `parent=none (root TObject)`; a class whose parent lives
  outside this exe (in the RTL/VCL) shows `parent=external`.

What just happened: Delpheed located each class's VMT by its self-pointer and read
the name/size/parent straight out of Delphi's metadata — no disassembly involved.

---

## 4. Tutorial B — make a packed sample and detect it

Download **UPX** (https://upx.github.io). Pack a *copy* of your test exe:

```
copy App.exe Packed.exe
upx Packed.exe
```

Now run the one-shot analyzer and read just its detection stage:

```
bin\Delpheed.exe Packed.exe
```

Under **Packing analysis** you'll see a high **file entropy** (compressed data sits
near 8.0), the **packer name** (`UPX`), **Likely packed: True**, a **confidence**
score, and the **reasons** that fired (entry point in the last section, tiny import
table, etc.).

For contrast, run `bin\VMTScan.exe Packed.exe` directly — it finds few or no
classes, because the real code is still compressed.

---

## 5. Tutorial C — unpack it

**The easy way (one-shot):**

```
bin\Delpheed.exe Packed.exe
```

Because it detected packing, Delpheed launches the target under the debugger, finds
the original entry point, dumps the unpacked image to `Packed_unpacked.exe`, rebuilds
its imports to `Packed_unpacked_fixed.exe`, then scans the dump and prints the
classes — which now match the original program.

**The manual way (more control):**

```
bin\OEPScan.exe Packed.exe Packed_dump.exe /iat
bin\VMTScan.exe Packed_dump.exe
```

- `/iat` rebuilds the import table, producing `Packed_dump_fixed.exe`.
- The first command produces the unpacked dump; the second reads its classes.

If the packer uses a `PUSHAD` prologue (UPX does), the ESP-trick unpacker also works
and is a good cross-check:

```
bin\Unpack.exe Packed.exe Packed_dump.exe
```

---

## 6. Tutorial D — a target that detects debuggers

If a protected sample **times out** or **exits before the OEP**, it is probably
detecting the debugger. Add `/aad` to hide it:

```
bin\OEPScan.exe Protected.exe dump.exe /aad /iat
```

`/aad` patches the target's PEB (`BeingDebugged`, `NtGlobalFlag`), clears the heap
debug flags, and hooks `NtSetInformationThread` / `NtQueryInformationProcess` so the
target can neither see the debugger nor detach its thread from it. This defeats the
common checks. Heavy virtualizing protectors (Themida, VMProtect, Enigma) use
anti-debug and code virtualization these methods do **not** beat — that's expected.

---

## 7. How to read the results

- **VMT layout line** — `-88` = Delphi 2009+ (x86), `-76` = Delphi 2–7 (x86),
  `-176` = Delphi (x64). Delpheed picks whichever recovers the most classes.
- **"unresolved" in the import step** — some IAT pointers didn't match a known
  export (a hooked or redirected thunk). Those are reported, not guessed. The dump
  is still perfectly good for *static* analysis; only re-running the fixed exe would
  need manual fixups for the unresolved entries.
- **Exit codes** (useful in scripts): `0` success, `1` bad arguments, `2` input
  could not be read, `3` ran but the operation failed.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Not a 32-bit PE32 image` | Target is 64-bit. The unpackers are 32-bit only; `VMTScan` still reads it statically. |
| `Timed out` / `exited before OEP` | Anti-debug (add `/aad`); or DEP is disabled (the guard-page method needs DEP — on by default for 32-bit on 64-bit Windows); or the stub unpacks outside the image. |
| `No IAT found` | The import scan found no run of module pointers — try without `/iat`, or the sample resolves imports lazily. |
| `No room in PE header for an extra section` | The dump's headers are full, so the rebuild can't append an import section. Rare. |
| `CreateProcess failed` | Wrong path, or you built 64-bit — rebuild 32-bit. |
| Empty/garbage class list after unpack | Dump may be incomplete; try `Unpack.exe` (ESP trick) if the stub uses `PUSHAD`, or re-run with `/aad`. |

---

## 9. Recommended first run (smoke test)

1. Take a Delphi exe you can already read with `VMTScan` (Tutorial A).
2. UPX-pack a copy (Tutorial B).
3. Run `bin\Delpheed.exe Packed.exe`.
4. Confirm the post-unpack class list **matches** what `VMTScan` showed on the
   original unpacked exe.

If they match, your build and the whole pipeline are working end to end.

---

## Safety, one more time

The unpackers execute the target's stub. Analyse only what you're authorised to,
and keep untrusted samples inside a VM with a snapshot you can restore.
