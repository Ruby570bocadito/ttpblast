@echo off
rem Demo completa en Windows (cmd o PowerShell): compila, genera telemetria
rem sintetica y busca la cadena de ejemplo. Los argumentos extra van a
rem "ttpblast search" (p. ej. demo --null gumbel).
setlocal
set "rc=0"
pushd "%~dp0"

where cargo >nul 2>nul
if errorlevel 1 (
  echo No se encuentra cargo. Instala Rust desde https://rustup.rs y abre una terminal nueva.
  set "rc=1"
  goto :end
)

cargo build --release --quiet
if errorlevel 1 ( set "rc=1" & goto :end )

target\release\ttpblast.exe synth --out data\demo
if errorlevel 1 ( set "rc=1" & goto :end )

echo.
target\release\ttpblast.exe search --query queries\phishing-lateral.txt --events data\demo\events.ndjson %*
if errorlevel 1 set "rc=1"

:end
popd
exit /b %rc%
