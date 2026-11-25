@echo off
rem EmberScan installer (Windows wrapper). install.py creates/repairs .\venv itself,
rem so always start it with the system Python, never with the (possibly broken) venv.
setlocal
set "HERE=%~dp0"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 "%HERE%install.py" %*
) else (
  python "%HERE%install.py" %*
)
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo INSTALLATION FAILED -- see the messages above.
endlocal & exit /b %RC%
