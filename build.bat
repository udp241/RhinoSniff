@echo off
echo ========================================
echo  RhinoSniff Build Script
echo ========================================
echo.

cd /d "%~dp0"

echo Cleaning old build artifacts...
if exist RhinoSniff\bin rmdir /s /q RhinoSniff\bin
if exist RhinoSniff\obj rmdir /s /q RhinoSniff\obj
echo Done.
echo.

echo Restoring NuGet packages...
dotnet restore RhinoSniff.sln
if errorlevel 1 (
    echo ERROR: Restore failed!
    pause
    exit /b 1
)
echo.

echo Building RhinoSniff...
dotnet publish RhinoSniff.sln -c Release -r win-x64 --self-contained true
if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)
echo.

echo ========================================
echo  BUILD SUCCESSFUL
echo ========================================
echo.
echo Your exe is in:
echo   RhinoSniff\bin\Release\net6.0-windows10.0.19041.0\win-x64\publish\
echo.
echo To run it:
echo   RhinoSniff\bin\Release\net6.0-windows10.0.19041.0\win-x64\publish\RhinoSniff.exe
echo.
echo To copy the whole thing somewhere else, copy the ENTIRE publish folder.
echo Do NOT copy just the exe - it needs the DLLs next to it.
echo.
pause
