@echo off
REM ============================================================================
REM  NetSentinel - Build Standalone Windows Executable
REM ============================================================================

echo [*] Building NetSentinel.exe with PyInstaller...
echo.

REM Check PyInstaller
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo [*] Installing PyInstaller...
    pip install pyinstaller>=6.0.0
)

REM Build the executable
pyinstaller ^
    --name "NetSentinel" ^
    --onefile ^
    --windowed ^
    --add-data "src;src" ^
    --add-data "rules;rules" ^
    --add-data "assets;assets" ^
    --hidden-import "sklearn" ^
    --hidden-import "sklearn.ensemble" ^
    --hidden-import "sklearn.ensemble._iforest" ^
    --hidden-import "sklearn.preprocessing" ^
    --hidden-import "sklearn.utils._typedefs" ^
    --hidden-import "sklearn.neighbors._partition_nodes" ^
    --hidden-import "scapy" ^
    --hidden-import "scapy.all" ^
    --hidden-import "psutil" ^
    --hidden-import "numpy" ^
    --hidden-import "cryptography" ^
    --hidden-import "plyer.platforms.win.notification" ^
    --icon "assets\netsentinel.ico" ^
    --uac-admin ^
    --clean ^
    main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. Check the output above for errors.
    echo Common fix: pip install --upgrade pyinstaller
) else (
    echo.
    echo [OK] Build successful!
    echo     Executable: dist\NetSentinel.exe
    echo.
    echo     Copy NetSentinel.exe anywhere and run it.
    echo     It will request Administrator privileges automatically.
    
    REM Copy to project root for convenience
    if exist "dist\NetSentinel.exe" (
        copy "dist\NetSentinel.exe" "NetSentinel.exe" >nul
        echo     Also copied to: NetSentinel.exe
    )
)

echo.
pause
