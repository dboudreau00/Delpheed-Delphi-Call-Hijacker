@echo off
rem ---------------------------------------------------------------------------
rem Build all Delpheed tools. dcc32/dcc64 must be on PATH - run RAD Studio's
rem "rsvars.bat" first, or open a "RAD Studio Command Prompt", then run this.
rem
rem 32-bit tools (dcc32): the x86 debugger-based unpacker, anti-anti-debug, and
rem the static/analysis tools.
rem 64-bit tools (dcc64): the x64 guard-page unpacker and its helpers.
rem ---------------------------------------------------------------------------
setlocal
set OUT=bin
if not exist "%OUT%" mkdir "%OUT%"

where dcc32 >nul 2>nul
if errorlevel 1 (
  echo dcc32 not found on PATH. Run rsvars.bat first, or use a RAD Studio Command Prompt.
  exit /b 1
)

echo === 32-bit tools (dcc32) ===
for %%T in (VMTScan Unpack OEPScan Delpheed) do (
  echo Building %%T ...
  dcc32 -B -Q -E"%OUT%" -NU"%OUT%" %%T.dpr
  if errorlevel 1 goto :err
)

echo.
echo === 64-bit tools (dcc64) ===
where dcc64 >nul 2>nul
if errorlevel 1 (
  echo dcc64 not found on PATH - skipping 64-bit tools.
  goto :done
)
for %%T in (OEPScan64) do (
  echo Building %%T ...
  dcc64 -B -Q -E"%OUT%" -NU"%OUT%" %%T.dpr
  if errorlevel 1 goto :err
)

:done
echo.
echo Done. Binaries are in "%OUT%\".
goto :eof

:err
echo.
echo Build FAILED.
exit /b 1
