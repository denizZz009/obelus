@echo off
setlocal enabledelayedexpansion

:: Check if cl is already in PATH
where cl >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Visual Studio environment not detected. Attempting to initialize...
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
    
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" (
        echo Found vcvarsall.bat at "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat"
        call "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else (
        echo [ERROR] Could not find vcvarsall.bat. Please ensure Visual Studio C++ build tools are installed.
        exit /b 1
    )
)

if not exist build mkdir build
echo Assembling Syscall Stubs...
ml64 /c /nologo /Fo build\syscalls.obj src\syscalls\syscalls.asm
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

echo Compiling C++...
cl /EHsc /nologo /std:c++17 src\main.cpp src\logger\logger.cpp src\utils\obfuscation.cpp src\syscalls\sys_sim.cpp src\syscalls\native_syscalls.cpp src\runner\shellcode_runner.cpp src\bits\bits_sim.cpp src\loader\pe_loader.cpp src\persistence\hijack_sim.cpp build\syscalls.obj /Fe:build\Obelus.exe /I src shell32.lib ole32.lib
if %ERRORLEVEL% EQU 0 (
    echo Build Successful!
    build\Obelus.exe
) else (
    echo Build Failed!
)
