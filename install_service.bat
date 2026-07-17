@echo off
:: AriaSecurity Windows Service Installer
:: Run as Administrator

echo ============================================
echo  Aria Security - Service Installer
echo ============================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Please run as Administrator.
    pause
    exit /b 1
)

:: Find Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found in PATH.
    pause
    exit /b 1
)

echo Installing required packages...
python -m pip install pywin32 watchdog psutil wmi requests winotify pydivert --quiet

echo.
echo Installing Aria Security as a Windows Service...
cd /d "%~dp0"
python Main_Unit\Engine\Service\SentinelWindowsService.py install

if %errorlevel% neq 0 (
    echo ERROR: Service installation failed.
    pause
    exit /b 1
)

echo.
echo Configuring service auto-start and recovery...
sc config AriaSecurity start= auto
sc failure AriaSecurity reset= 60 actions= restart/5000/restart/5000/restart/10000

echo.
echo Starting service...
net start AriaSecurity

if %errorlevel% equ 0 (
    echo.
    echo ============================================
    echo  Aria Security Service INSTALLED and RUNNING
    echo  Protection is now active in the background.
    echo ============================================
) else (
    echo.
    echo WARNING: Service installed but could not start automatically.
    echo Try: net start AriaSecurity
)

echo.
pause
