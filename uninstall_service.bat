@echo off
:: AriaSecurity Windows Service Uninstaller
:: Run as Administrator

echo ============================================
echo  Aria Security - Service Uninstaller
echo ============================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Please run as Administrator.
    pause
    exit /b 1
)

echo Stopping service...
net stop AriaSecurity 2>nul

echo Removing service...
cd /d "%~dp0"
python Main_Unit\Engine\Service\SentinelWindowsService.py remove

echo.
echo Aria Security service removed.
pause
