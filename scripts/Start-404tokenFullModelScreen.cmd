@echo off
setlocal

set "SCRIPT=%~dp0Run-404tokenFullModelScreen.ps1"
if not exist "%SCRIPT%" (
    echo Full-screen model screening script was not found:
    echo "%SCRIPT%"
    set "RESULT=2"
    goto finish
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "RESULT=%ERRORLEVEL%"

:finish
echo.
echo Full-screen model screening launcher exit code: %RESULT%
pause
exit /b %RESULT%
