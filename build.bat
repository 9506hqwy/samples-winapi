@ECHO OFF

if "%1" == "" (
    echo usage:
    echo     "build.bat <directory>"
    exit /B 1
)

if not exist "%1" (
    echo Not found "%1"
    exit /B 1
)

rmdir /q /s build
mkdir build

pushd build

cl.exe /O2 /c /nologo /Wall "..\common\console.c"
if errorlevel 1 (
    popd
    exit /B %ERRORLEVEL%
)

rc.exe /v /w /nologo "..\%1\%1.rc"
if errorlevel 1 (
    popd
    exit /B %ERRORLEVEL%
)

cl.exe /O2 /nologo /Wall /Fe"%1.exe" ".\console.obj"  "..\%1\%1.res" "..\%1\%1.c"
if errorlevel 1 (
    popd
    exit /B %ERRORLEVEL%
)

popd
