@echo off
REM ============================================================================
REM  NetSentinel - One-Click Setup Script for Windows
REM ============================================================================
REM  This script will:
REM    1. Check for Python installation
REM    2. Install all dependencies
REM    3. Create a desktop shortcut
REM    4. Optionally build a standalone .exe
REM ============================================================================

echo.
echo  ========================================
echo     NETSENTINEL - Setup Installer
echo     Network Monitor ^& IDS v1.0
echo  ========================================
echo.

REM --- Check Python ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version
echo.

REM --- Check pip ---
pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip is not available. Reinstall Python with pip enabled.
    pause
    exit /b 1
)

REM --- Install dependencies ---
echo [*] Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt
echo.

if errorlevel 1 (
    echo [WARNING] Some packages failed to install. The app may run with limited features.
) else (
    echo [OK] All dependencies installed successfully.
)
echo.

REM --- Remind about Npcap ---
echo ============================================================
echo  IMPORTANT: Npcap is required for full packet capture.
echo  If not already installed, download from:
echo    https://npcap.com/
echo  During install, check "Install in WinPcap API-compatible mode"
echo ============================================================
echo.

REM --- Create desktop shortcut ---
echo [*] Creating desktop shortcut...
set SCRIPT_DIR=%~dp0
set SHORTCUT_PATH=%USERPROFILE%\Desktop\NetSentinel.bat

(
    echo @echo off
    echo cd /d "%SCRIPT_DIR%"
    echo echo Starting NetSentinel...
    echo python main.py
    echo pause
) > "%SHORTCUT_PATH%"

echo [OK] Desktop shortcut created: %SHORTCUT_PATH%
echo.

REM --- Ask about building exe ---
set /p BUILD_EXE="Build standalone .exe? (Recommended for easy use) [y/N]: "
if /i "%BUILD_EXE%"=="y" (
    echo.
    echo [*] Building standalone executable with PyInstaller...
    echo     This may take a few minutes...
    echo.
    call build_exe.bat
) else (
    echo.
    echo [*] Skipping .exe build. You can run with: python main.py
)

echo.
echo  ========================================
echo     Setup Complete!
echo  ========================================
echo.
echo  To run NetSentinel:
echo    Option 1: Double-click the desktop shortcut
echo    Option 2: Run "python main.py" from this folder
echo    Option 3: Run NetSentinel.exe (if built)
echo.
echo  NOTE: Run as Administrator for full packet capture.
echo.
pause
