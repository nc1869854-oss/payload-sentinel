@echo off
:: =============================================================================
:: build.bat — Payload Capture Suite complete build script
::
:: Run this from the PayloadCaptureSuite project root on a Windows machine.
:: It will:
::   1. Check that all prerequisites are installed
::   2. Install/upgrade required Python packages
::   3. Run PyInstaller to compile the exe
::   4. Run NSIS to produce the final installer
::
:: Prerequisites (install these once before running this script):
::   - Python 3.10+         https://python.org
::   - NSIS 3.x             https://nsis.sourceforge.io/Download
::   - Npcap OEM installer  https://npcap.com/dist/npcap-1.79-oem.exe
::     → place it at:  installer\npcap-1.79-oem.exe
::
:: Output:  PayloadCaptureSuite_Setup.exe
:: =============================================================================

setlocal EnableDelayedExpansion
title Payload Capture Suite — Build

echo.
echo  ========================================================
echo   PAYLOAD CAPTURE SUITE — BUILD SCRIPT
echo  ========================================================
echo.

:: ── Step 0: Make sure we are in the right directory ──────────────────────────
if not exist "main.py" (
    echo  ERROR: Run this script from the PayloadCaptureSuite project root.
    echo         Expected to find main.py in the current directory.
    pause
    exit /b 1
)

:: ── Step 1: Check Python ─────────────────────────────────────────────────────
echo  [1/6] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: Python not found.
    echo  Download Python 3.10+ from https://python.org
    echo  Make sure "Add Python to PATH" is ticked during install.
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo         Found Python %PY_VER%

:: ── Step 2: Check NSIS ───────────────────────────────────────────────────────
echo  [2/6] Checking NSIS...
where makensis >nul 2>&1
if errorlevel 1 (
    :: Try common install path
    if exist "C:\Program Files (x86)\NSIS\makensis.exe" (
        set MAKENSIS="C:\Program Files (x86)\NSIS\makensis.exe"
    ) else if exist "C:\Program Files\NSIS\makensis.exe" (
        set MAKENSIS="C:\Program Files\NSIS\makensis.exe"
    ) else (
        echo.
        echo  ERROR: NSIS not found.
        echo  Download NSIS 3.x from https://nsis.sourceforge.io/Download
        echo  Install it, then re-run this script.
        pause
        exit /b 1
    )
) else (
    set MAKENSIS=makensis
)
echo         NSIS found: %MAKENSIS%

:: ── Step 3: Check Npcap installer ────────────────────────────────────────────
echo  [3/6] Checking Npcap installer...
if not exist "installer\npcap-1.79-oem.exe" (
    echo.
    echo  ERROR: Npcap OEM installer not found at installer\npcap-1.79-oem.exe
    echo.
    echo  Download it from:  https://npcap.com/dist/npcap-1.79-oem.exe
    echo  Then place it at:  installer\npcap-1.79-oem.exe
    echo.
    echo  The OEM version allows silent installation inside an installer.
    echo  The standard free version works too for personal/testing use.
    pause
    exit /b 1
)
echo         Npcap installer found.

:: ── Step 4: Install/upgrade Python packages ───────────────────────────────────
echo  [4/6] Installing Python packages...
echo.
python -m pip install --upgrade pip --quiet
python -m pip install --upgrade pyinstaller scapy reportlab --quiet
if errorlevel 1 (
    echo.
    echo  ERROR: pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo         pyinstaller, scapy, reportlab — installed/up to date.

:: ── Step 5: Run PyInstaller ──────────────────────────────────────────────────
echo.
echo  [5/6] Building exe with PyInstaller...
echo         (This takes 1–3 minutes — compiling all Python files)
echo.

:: Clean previous build
if exist "dist\PayloadCaptureSuite" rmdir /s /q "dist\PayloadCaptureSuite"
if exist "build\PayloadCaptureSuite" rmdir /s /q "build\PayloadCaptureSuite"

python -m PyInstaller PayloadCaptureSuite.spec --noconfirm
if errorlevel 1 (
    echo.
    echo  ERROR: PyInstaller failed.
    echo  Check the output above for details.
    echo  Common causes:
    echo    - Missing hidden import: add it to PayloadCaptureSuite.spec
    echo    - Antivirus blocking the build: temporarily disable it
    pause
    exit /b 1
)

:: Verify the exe was actually created
if not exist "dist\PayloadCaptureSuite\PayloadCaptureSuite.exe" (
    echo.
    echo  ERROR: Expected exe not found at dist\PayloadCaptureSuite\PayloadCaptureSuite.exe
    pause
    exit /b 1
)

echo.
echo         exe built successfully.

:: ── Step 6: Run NSIS ─────────────────────────────────────────────────────────
echo.
echo  [6/6] Building installer with NSIS...
echo.

:: Create the installer staging directory if it doesn't exist
if not exist "installer" mkdir installer

%MAKENSIS% PayloadCaptureSuite.nsi
if errorlevel 1 (
    echo.
    echo  ERROR: NSIS failed.
    echo  Check the output above for details.
    pause
    exit /b 1
)

if not exist "PayloadCaptureSuite_Setup.exe" (
    echo.
    echo  ERROR: Expected installer not found.
    pause
    exit /b 1
)

:: ── Done ─────────────────────────────────────────────────────────────────────
echo.
echo  ========================================================
echo   BUILD COMPLETE
echo  ========================================================
echo.
echo   Installer: PayloadCaptureSuite_Setup.exe
for %%F in ("PayloadCaptureSuite_Setup.exe") do echo   Size:      %%~zF bytes
echo.
echo   The installer:
echo     - Installs all application files to Program Files
echo     - Silently installs Npcap (packet capture driver)
echo     - Creates Start Menu and Desktop shortcuts
echo     - Registers in Add/Remove Programs
echo     - Creates an uninstaller
echo.
echo   The end user needs NOTHING else — just run the installer.
echo.
pause
