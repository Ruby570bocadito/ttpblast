@echo off
rem Demo guiada en Windows (cmd o PowerShell): compila y ejecuta "ttpblast demo",
rem que genera telemetria sintetica, busca dos cadenas de ataque y se pone nota
rem frente a la verdad. Los argumentos extra van a la demo (p. ej. demo --lang en).
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

target\release\ttpblast.exe demo %*
if errorlevel 1 set "rc=1"

:end
popd
exit /b %rc%
