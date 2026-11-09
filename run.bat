@echo off
setlocal
cd /d "%~dp0"

set "VENV_PY=%~dp0.venv\Scripts\python.exe"
if not exist "%VENV_PY%" (
    where py >nul 2>&1
    if not errorlevel 1 (
        py -3 -m venv "%~dp0.venv"
    ) else (
        python -m venv "%~dp0.venv"
    )
    if errorlevel 1 (
        echo Failed to create the virtual environment.
        pause
        exit /b 1
    )
)

"%VENV_PY%" -c "import PyQt6, cryptography" >nul 2>&1
if errorlevel 1 (
    "%VENV_PY%" -m pip install --upgrade pip
    if errorlevel 1 exit /b 1
    "%VENV_PY%" -m pip install -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo Failed to install dependencies.
        pause
        exit /b 1
    )
)

set "VENV_PYW=%~dp0.venv\Scripts\pythonw.exe"
if not exist "%VENV_PYW%" set "VENV_PYW=%VENV_PY%"

rem Run the GUI and its tray-resident service without keeping a console window.
start "" "%VENV_PYW%" "%~dp0password_manager.py" %*
exit /b 0
