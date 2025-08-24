@echo off
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed. Please install Python 3.8+ before continuing.
    pause
    exit /b
)

python -m pip install --upgrade pip

python -m pip install -r requirements.txt

echo Please use start.bat now.
pause
