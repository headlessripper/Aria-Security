@echo off
rem ============================================================================
rem  build.bat -- hand-rolled WDK build for AriaFilter.sys
rem
rem  Compiles + links the minifilter against the installed WDK headers/libs using
rem  cl.exe/link.exe from Visual Studio 2022, WITHOUT the WDK's Visual-Studio
rem  MSBuild integration (which isn't installed on this box). Run from a normal
rem  shell; it bootstraps the x64 build environment itself.
rem
rem  Output: AriaFilter.sys (unsigned). See ..\README.md for test-signing + load.
rem ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem --- locate Visual Studio C++ tools ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" ( echo ERROR: vswhere.exe not found & exit /b 1 )
set "VSPATH="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH ( echo ERROR: VS2022 with C++ x64 tools not found & exit /b 1 )
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if errorlevel 1 ( echo ERROR: vcvarsall x64 failed & exit /b 1 )

rem --- locate newest WDK version that has the minifilter headers ---
set "KITROOT=%ProgramFiles(x86)%\Windows Kits\10"
set "WDKVER="
rem pushd into Include so the paren-containing KITROOT path never appears inside
rem the for-do block (the ")" in "Program Files (x86)" would close it early).
pushd "%KITROOT%\Include" 2>nul
if errorlevel 1 ( echo ERROR: "%KITROOT%\Include" not found & exit /b 1 )
for /f "delims=" %%v in ('dir /b /ad /o-n') do (
  if not defined WDKVER if exist "%%v\km\fltKernel.h" set "WDKVER=%%v"
)
popd
if not defined WDKVER ( echo ERROR: WDK km\fltKernel.h not found under "%KITROOT%\Include" & exit /b 1 )
echo [build] WDK version: %WDKVER%

set "INC=%KITROOT%\Include\%WDKVER%"
set "LIBK=%KITROOT%\Lib\%WDKVER%\km\x64"

rem --- compile (kernel mode) ---
echo [build] compiling AriaFilter.c ...
cl /nologo /c /Zi /W4 /WX- /Od /GS- /kernel ^
   /D_AMD64_ /DAMD64 /D_WIN64 /DNTDDI_VERSION=0x0A000000 ^
   /I"%INC%\km" /I"%INC%\shared" /I"%INC%\km\crt" /I"%INC%\um" ^
   AriaFilter.c
if errorlevel 1 ( echo [build] COMPILE FAILED & exit /b 1 )

rem --- link (kernel driver) ---
echo [build] linking AriaFilter.sys ...
link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /MACHINE:X64 ^
   /LIBPATH:"%LIBK%" ^
   fltMgr.lib ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowFastFailK.lib ^
   AriaFilter.obj /OUT:AriaFilter.sys
if errorlevel 1 ( echo [build] LINK FAILED & exit /b 1 )

echo [build] OK: %~dp0AriaFilter.sys
endlocal
