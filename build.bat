@echo off
setlocal EnableDelayedExpansion
chcp 65001 > nul

echo.
echo ============================================================
echo   NetLogic Build Pipeline
echo   Produces: NetLogic-%APP_VERSION%-Setup.exe
echo ============================================================
echo.

:: ── Config ──────────────────────────────────────────────────
set APP_NAME="NetLogic"
set APP_VERSION=2.0.0
set PYTHON=python
set PIP=pip

:: ── Step 1: Check Python ────────────────────────────────────
echo [1/5] Checking Python...
%PYTHON% --version > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause & exit /b 1
)
for /f "tokens=*" %%i in ('%PYTHON% --version') do echo       Found: %%i

:: ── Step 2: Install Python dependencies ─────────────────────
echo.
echo [2/5] Installing Python dependencies...
%PIP% install --quiet --upgrade pyinstaller
if errorlevel 1 (
    echo [ERROR] Failed to install PyInstaller
    pause & exit /b 1
)
echo       PyInstaller ready.

:: Install optional UPX for smaller exe (silently skip if unavailable)
where upx > nul 2>&1
if errorlevel 1 (
    echo       UPX not found - exe will be larger but still functional.
    echo       Optional: Download UPX from https://upx.github.io and add to PATH.
) else (
    echo       UPX found - exe will be compressed.
)

:: ── Step 3: Clean previous build ────────────────────────────
echo.
echo [3/5] Cleaning previous build...
if exist dist\netlogic.exe (
    del /f /q dist\netlogic.exe
    echo       Removed old dist\netlogic.exe
)
if exist build (
    rmdir /s /q build
    echo       Removed build\
)

:: ── Step 4: PyInstaller build ───────────────────────────────
echo.
echo [4/5] Building executable with PyInstaller...
echo       This takes 30-90 seconds...
echo.

%PYTHON% -m PyInstaller ^
    --onefile ^
    --console ^
    --name netlogic ^
    --add-data "src;src" ^
    --hidden-import src.scanner ^
    --hidden-import src.cve_correlator ^
    --hidden-import src.nvd_lookup ^
    --hidden-import src.osint ^
    --hidden-import src.reporter ^
    --hidden-import src.tls_analyzer ^
    --hidden-import src.header_audit ^
    --hidden-import src.takeover ^
    --hidden-import src.stack_fingerprint ^
    --hidden-import src.dns_security ^
    --hidden-import src.json_bridge ^
    --hidden-import ssl ^
    --hidden-import _ssl ^
    --hidden-import socket ^
    --hidden-import concurrent.futures ^
    --hidden-import ipaddress ^
    --hidden-import hashlib ^
    --hidden-import threading ^
    --exclude-module tkinter ^
    --exclude-module matplotlib ^
    --exclude-module numpy ^
    --exclude-module pandas ^
    --exclude-module PIL ^
    --version-file version_info.txt ^
    netlogic.py

if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build failed. Check output above.
    pause & exit /b 1
)

:: Verify the exe was created
if not exist dist\netlogic.exe (
    echo [ERROR] dist\netlogic.exe not found after build.
    pause & exit /b 1
)

:: Quick smoke test
echo.
echo       Running smoke test...
dist\netlogic.exe --version
if errorlevel 1 (
    echo [WARN] Smoke test failed - exe may have issues.
) else (
    echo       Smoke test passed.
)

:: Print exe size
for %%A in (dist\netlogic.exe) do (
    set /a SIZE_MB=%%~zA / 1048576
    echo       Size: !SIZE_MB! MB
)

:: ── Step 5: NSIS Installer ──────────────────────────────────
echo.
echo [5/5] Building installer with NSIS...

:: Check if NSIS is installed
where makensis > nul 2>&1
if errorlevel 1 (
    :: Try common install paths
    set MAKENSIS=
    if exist "C:\Program Files (x86)\NSIS\makensis.exe" set MAKENSIS="C:\Program Files (x86)\NSIS\makensis.exe"
    if exist "C:\Program Files\NSIS\makensis.exe"       set MAKENSIS="C:\Program Files\NSIS\makensis.exe"
    
    if "!MAKENSIS!"=="" (
        echo.
        echo [WARN] NSIS not found. Skipping installer creation.
        echo       To build the installer:
        echo         1. Download NSIS from https://nsis.sourceforge.io/Download
        echo         2. Install it
        echo         3. Run this script again, OR run manually:
        echo            makensis installer.nsi
        echo.
        echo [OK] Standalone EXE is ready at: dist\netlogic.exe
        echo      You can distribute this file directly without an installer.
        goto :SkipNSIS
    )
) else (
    set MAKENSIS=makensis
)

echo       Found NSIS. Building setup wizard...
!MAKENSIS! installer.nsi

if errorlevel 1 (
    echo [ERROR] NSIS build failed.
    pause & exit /b 1
)

if exist "NetLogic-%APP_VERSION%-Setup.exe" (
    for %%A in ("NetLogic-%APP_VERSION%-Setup.exe") do (
        set /a INST_MB=%%~zA / 1048576
    )
    echo.
    echo ============================================================
    echo   BUILD COMPLETE
    echo ============================================================
    echo   Installer : NetLogic-%APP_VERSION%-Setup.exe  (!INST_MB! MB)
    echo   Standalone: dist\netlogic.exe
    echo ============================================================
) else (
    echo [WARN] Installer not found after NSIS build.
)
goto :Done

:SkipNSIS
echo.
echo ============================================================
echo   BUILD COMPLETE (no installer - NSIS not installed)
echo ============================================================
echo   Standalone EXE: dist\netlogic.exe
echo   To add installer: install NSIS and re-run build.bat
echo ============================================================

:Done
echo.
pause
