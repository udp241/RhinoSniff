@echo off
echo ========================================
echo  RhinoSniff Build + Installer Pipeline
echo ========================================
echo.

:: Step 1: Clean
echo [1/4] Cleaning old build...
if exist RhinoSniff\bin rmdir /s /q RhinoSniff\bin
if exist RhinoSniff\obj rmdir /s /q RhinoSniff\obj
if exist installer_output rmdir /s /q installer_output

:: Step 2: Publish
echo [2/4] Building RhinoSniff...
dotnet publish RhinoSniff.sln -c Release -r win-x64 --self-contained true
if %errorlevel% neq 0 (
    echo BUILD FAILED!
    pause
    exit /b 1
)
echo Build OK.
echo.

:: Step 3: Find and rename npcap installer
echo [3/4] Looking for Npcap installer...
if exist "npcap.exe" del "npcap.exe"

:: Copy first matching npcap-*.exe to npcap.exe
for %%f in (npcap-*.exe) do (
    echo Found: %%f
    copy "%%f" "npcap.exe" >nul
    goto :npcap_check
)

:npcap_check
if not exist "npcap.exe" (
    echo.
    echo ERROR: No Npcap installer found!
    echo.
    echo Download it from https://npcap.com/#download
    echo Save the file in this folder next to build_installer.bat
    echo It should be named something like npcap-1.87.exe
    echo.
    pause
    exit /b 1
)
echo Npcap installer ready.
echo.

:: Step 4: Build installer
echo [4/4] Building installer...
set ISCC=
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"

if "%ISCC%"=="" (
    echo.
    echo ERROR: Inno Setup not found!
    echo Download from https://jrsoftware.org/isdl.php
    echo Install it, then run this script again.
    pause
    exit /b 1
)

"%ISCC%" installer.iss
if %errorlevel% neq 0 (
    echo INSTALLER BUILD FAILED!
    pause
    exit /b 1
)

if exist "npcap.exe" del "npcap.exe"

echo.
echo ========================================
echo  SUCCESS!
echo  Installer: installer_output\RhinoSniff_Setup_v3.0.1.exe
echo ========================================
echo.
pause
