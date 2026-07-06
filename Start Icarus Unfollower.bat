@echo off
rem Plug-and-play launch for Icarus Un-follower (fallback if the .vbs is blocked).
cd /d "%~dp0"
where pythonw >nul 2>nul && (
    start "" pythonw "%~dp0launcher.py"
) || (
    where python >nul 2>nul && (
        start "" python "%~dp0launcher.py"
    ) || (
        echo Python not found. Install it from https://python.org and tick "Add to PATH".
        pause
    )
)
