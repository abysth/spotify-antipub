@echo off
chcp 65001 >nul
set PYTHONUTF8=1
title Spotify Anti-Pub - Installation
cd /d "%~dp0"
python antipub.py
pause
