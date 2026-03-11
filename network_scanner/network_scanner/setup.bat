@echo off
title NetVulnScanner - Windows Setup
color 0A

echo.
echo  =====================================================
echo   NetVulnScanner - Windows Setup Script
echo   Run this as Administrator (which you already are)
echo  =====================================================
echo.

:: ── Step 1: Check Python ──────────────────────────────
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found!
    echo  Please install Python from https://python.org
    echo  Make sure to tick "Add Python to PATH" during install.
    pause
    exit /b 1
)
python --version
echo  [OK] Python found.
echo.

:: ── Step 2: Upgrade pip ───────────────────────────────
echo [2/5] Upgrading pip...
python -m pip install --upgrade pip --quiet
echo  [OK] pip upgraded.
echo.

:: ── Step 3: Install Python packages ──────────────────
echo [3/5] Installing Python packages (scapy + python-nmap)...
pip install scapy python-nmap --quiet
if %errorlevel% neq 0 (
    echo  [WARN] Some packages may have failed. Retrying...
    pip install scapy
    pip install python-nmap
)
echo  [OK] Python packages installed.
echo.

:: ── Step 4: Check Nmap ────────────────────────────────
echo [4/5] Checking Nmap installation...
nmap --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ACTION REQUIRED] Nmap is NOT installed.
    echo  -----------------------------------------------
    echo  Please install Nmap manually:
    echo  1. Go to: https://nmap.org/download.html
    echo  2. Download "Latest stable release self-installer"
    echo  3. Run the installer (keep default options)
    echo  4. Re-run this setup script after installing.
    echo  -----------------------------------------------
    echo.
) else (
    nmap --version | findstr /i "nmap"
    echo  [OK] Nmap is installed.
)
echo.

:: ── Step 5: Check Npcap ───────────────────────────────
echo [5/5] Checking Npcap (required for Scapy ARP scans)...
sc query npcap >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ACTION REQUIRED] Npcap is NOT detected.
    echo  -----------------------------------------------
    echo  Please install Npcap manually:
    echo  1. Go to: https://npcap.com/#download
    echo  2. Download the latest Npcap installer
    echo  3. During install: tick "WinPcap API-compatible Mode"
    echo  4. Do NOT install old WinPcap - Npcap only
    echo  5. Re-run this setup script after installing.
    echo  -----------------------------------------------
    echo.
) else (
    echo  [OK] Npcap service detected.
)
echo.

:: ── Final Check ───────────────────────────────────────
echo  =====================================================
echo   Setup Summary:
echo  =====================================================
echo.

python -c "import nmap; print('  [OK] python-nmap:', nmap.__version__)" 2>nul || echo   [WARN] python-nmap not importable
python -c "import scapy; print('  [OK] scapy installed')" 2>nul || echo   [WARN] scapy not importable
nmap --version >nul 2>&1 && echo   [OK] nmap binary: found || echo   [MISSING] nmap binary - install from nmap.org

echo.
echo  =====================================================
echo   To run the scanner:
echo     python main.py
echo  (Always run CMD as Administrator for ARP scanning)
echo  =====================================================
echo.
pause
