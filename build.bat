@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  NetRecon — Windows Build Script
REM  Produces:
REM    dist/NetRecon-1.0.0-Setup.exe      (NSIS installer)
REM    dist/NetRecon-1.0.0-portable.exe   (single-file portable)
REM ═══════════════════════════════════════════════════════════════════

echo [1/5] Checking prerequisites...
where node >nul 2>&1 || (echo ERROR: Node.js not found. Install from nodejs.org && exit /b 1)
where python >nul 2>&1 || where python3 >nul 2>&1 || (echo WARNING: Python not found - bundled engine won't be built)

echo [2/5] Installing Node dependencies...
call npm install
if %errorlevel% neq 0 (echo ERROR: npm install failed && exit /b 1)

echo [3/5] Building Python engine (requires PyInstaller)...
pip show pyinstaller >nul 2>&1
if %errorlevel% equ 0 (
    pip install pyinstaller --quiet
    pyinstaller netrecon_engine.spec --distpath python_dist --workpath build_tmp --noconfirm
    echo [+] Python engine built → python_dist/netrecon_engine.exe
) else (
    echo [!] PyInstaller not found — app will use system Python.
    echo     Install with: pip install pyinstaller
)

echo [4/5] Building Electron app...
call npm run build
if %errorlevel% neq 0 (echo ERROR: Electron build failed && exit /b 1)

echo [5/5] Done!
echo.
echo Output:
dir /b dist\*.exe 2>nul
echo.
echo ✓ Build complete. Installers are in the dist\ folder.
