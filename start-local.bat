@echo off
REM ============================================================
REM Local start script (ASCII only to avoid CMD garbled Chinese)
REM Opens: http://127.0.0.1:PORT/
REM MongoDB / Nginx are optional
REM ============================================================
cd /d "%~dp0backend"

if not exist "node_modules\" (
  echo [1/2] Installing npm packages...
  call npm install
  if errorlevel 1 (
    echo ERROR: npm install failed.
    pause
    exit /b 1
  )
) else (
  echo [1/2] node_modules exists, skip npm install
)

REM Free port 3000 if an old node instance is still listening
echo [2/3] Checking port 3000...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":3000" ^| findstr "LISTENING"') do (
  echo Found PID %%P on port 3000, stopping it...
  taskkill /F /PID %%P >nul 2>&1
)
timeout /t 1 /nobreak >nul

echo [3/3] Starting server...
set PORT=3000
set ATTCK_PATH=%~dp0data\ATTCK.json
echo.
echo Open browser: http://127.0.0.1:3000/
echo Press Ctrl+C to stop. If port busy, app will try 3001+.
echo.

node app.js
if errorlevel 1 (
  echo.
  echo Server exited with error. See messages above.
)

echo.
pause
