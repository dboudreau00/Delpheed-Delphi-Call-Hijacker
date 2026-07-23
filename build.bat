@echo off
rem ---------------------------------------------------------------------------
rem Build all Delpheed tools 32-bit with dcc32 (Delphi's command-line
rem compiler). dcc32 must be on PATH - the easiest way is to run the RAD Studio
rem "rsvars.bat" first, or open a "RAD Studio Command Prompt", then run this.
rem
rem All tools are 32-bit on purpose: the debugger-based unpacker and the
rem anti-anti-debug hooks target 32-bit processes (the PUSHAD/ESP trick, the
rem syscall-stub prologue, and the PEB/heap offsets are all x86).
rem ---------------------------------------------------------------------------
setlocal
set OUT=bin
if not exist "%OUT%" mkdir "%OUT%"

where dcc32 >nul 2>nul
if errorlevel 1 (
  echo dcc32 not found on PATH. Run rsvars.bat first, or use a RAD Studio Command Prompt.
  exit /b 1
)

for %%T in (VMTScan Unpack OEPScan Delpheed) do (
  echo Building %%T ...
  dcc32 -B -Q -E"%OUT%" -NU"%OUT%" %%T.dpr
  if errorlevel 1 goto :err
)

echo.
echo Done. Binaries are in "%OUT%\".
goto :eof

:err
echo.
echo Build FAILED.
exit /b 1
