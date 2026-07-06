@echo off
rem ---------------------------------------------------------------------------
rem Builds a standalone, no-Python-needed IcarusUnfollower.exe using PyInstaller.
rem Run this ONCE on a machine that has Python; hand the resulting exe to anyone.
rem ---------------------------------------------------------------------------
cd /d "%~dp0"

echo Installing build tooling (pyinstaller + runtime deps)...
python -m pip install --upgrade pyinstaller frida msgpack curl_cffi pycryptodome
if errorlevel 1 goto err

rem Use the winged logo as the exe icon if it's been converted (see make_icon.py)
set ICON=
if exist "assets\icarus.ico" set ICON=--icon assets\icarus.ico

echo.
echo Building IcarusUnfollower.exe  (first build can take a few minutes)...
python -m PyInstaller --noconfirm --onefile --noconsole --name IcarusUnfollower %ICON% ^
  --collect-all frida --collect-all curl_cffi --collect-all Crypto ^
  --hidden-import msgpack ^
  --hidden-import unfollower_bot --hidden-import uma_client --hidden-import auth_capture ^
  --add-data "assets;assets" ^
  launcher.py
if errorlevel 1 goto err

echo.
echo ============================================================
echo  Done. Your standalone app is:  dist\IcarusUnfollower.exe
echo  Copy it anywhere and double-click. follower_data\ is written
echo  next to the exe. No Python or pip required.
echo ============================================================
pause
exit /b 0

:err
echo.
echo Build failed - see the messages above.
pause
exit /b 1
