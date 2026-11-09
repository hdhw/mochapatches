@echo off
cd /d "%~dp0"
dotnet build -c Release -t:Obfuscate
if errorlevel 1 (
    echo.
    echo my shit failed sob
    exit /b 1
)
echo.
echo done: dist\MochaPatches.dll
