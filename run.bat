@echo off
setlocal EnableDelayedExpansion
title CyberForge Lite - Interactive Launcher
cd /d "%~dp0"

:MENU
cls
echo ==============================================================================
echo                      CYBERFORGE LITE - CONTROL CENTER                         
echo ==============================================================================
echo.
echo   [1] Run All Unit Tests (pytest - 17 tests)
echo   [2] Inspect Sample Dataset (inspect_sample.py)
echo   [3] Run Quick Simulation Pipeline (Single Seed = 42)
echo   [4] Run Full 10-Seed Scientific Evaluation + Charts (--evaluate)
echo   [5] Run Red Team Evasion Report (Stage A Automated 10-Seeds)
echo.
echo   --- STAGE B: INTERACTIVE RED TEAM VS BLUE TEAM DEMOS ---
echo   [6] Demo: Caught Attack (baseline_brute_force on user_17)
echo   [7] Demo: Evasive Attack (slow_brute_force on user_17)
echo   [8] Demo: Password Spraying Attack (50 users)
echo   [9] Demo: Delayed Takeover Attack (delayed_takeover on user_17)
echo   [A] Demo: Low and Slow Takeover (low_and_slow_takeover on user_17)
echo.
echo   --- UTILITIES ---
echo   [O] Open Generated Charts Folder
echo   [C] Clean / Reset Generated Output Data (data\output)
echo   [Q] Quit
echo.
echo ==============================================================================
set /p "CHOICE=Select an option [1-9, A, O, C, Q] and press Enter: "

if /i "%CHOICE%"=="1" goto TEST
if /i "%CHOICE%"=="2" goto INSPECT
if /i "%CHOICE%"=="3" goto RUN_SINGLE
if /i "%CHOICE%"=="4" goto EVAL_FULL
if /i "%CHOICE%"=="5" goto EVASION_REPORT
if /i "%CHOICE%"=="6" goto DEMO_BASELINE
if /i "%CHOICE%"=="7" goto DEMO_SLOW
if /i "%CHOICE%"=="8" goto DEMO_SPRAY
if /i "%CHOICE%"=="9" goto DEMO_DELAYED
if /i "%CHOICE%"=="A" goto DEMO_LOWSLOW
if /i "%CHOICE%"=="O" goto OPEN_CHARTS
if /i "%CHOICE%"=="C" goto CLEAN_DATA
if /i "%CHOICE%"=="Q" goto QUIT

echo.
echo Invalid option selected. Press any key to try again...
pause >nul
goto MENU

:TEST
cls
echo [RUNNING ALL PYTEST SUITES]...
echo.
set "PYTHONPATH=%CD%;%PYTHONPATH%"
pytest -v
echo.
pause
goto MENU

:INSPECT
cls
echo [INSPECTING SAMPLE EVENTS]...
echo.
python scripts/inspect_sample.py
echo.
pause
goto MENU

:RUN_SINGLE
cls
echo [RUNNING SINGLE SEED SIMULATION (Seed = 42)]...
echo.
python scripts/run_pipeline.py
echo.
pause
goto MENU

:EVAL_FULL
cls
echo [RUNNING FULL 10-SEED EVALUATION + CHARTS]...
echo (Simulating 10 seeds, sensitivity check, generating charts...)
echo.
python scripts/run_pipeline.py --evaluate
echo.
pause
goto MENU

:EVASION_REPORT
cls
echo [RUNNING STAGE A: AUTOMATED EVASION REPORT (10 SEEDS)]...
echo.
python cli.py evasion-report
echo.
pause
goto MENU

:DEMO_BASELINE
cls
echo [STAGE B DEMO: BASELINE BRUTE FORCE ATTACK]...
echo.
python cli.py redteam --strategy baseline_brute_force --user user_17
echo.
pause
goto MENU

:DEMO_SLOW
cls
echo [STAGE B DEMO: SLOW BRUTE FORCE EVASIVE ATTACK]...
echo.
python cli.py redteam --strategy slow_brute_force --user user_17
echo.
pause
goto MENU

:DEMO_SPRAY
cls
echo [STAGE B DEMO: PASSWORD SPRAYING ATTACK (50 USERS)]...
echo.
python cli.py redteam --strategy password_spraying --users 50
echo.
pause
goto MENU

:DEMO_DELAYED
cls
echo [STAGE B DEMO: DELAYED TAKEOVER ATTACK]...
echo.
python cli.py redteam --strategy delayed_takeover --user user_17
echo.
pause
goto MENU

:DEMO_LOWSLOW
cls
echo [STAGE B DEMO: LOW AND SLOW TAKEOVER ATTACK]...
echo.
python cli.py redteam --strategy low_and_slow_takeover --user user_17
echo.
pause
goto MENU

:OPEN_CHARTS
explorer "data\output\charts"
goto MENU

:CLEAN_DATA
cls
echo ==============================================================================
echo                CLEAN / RESET GENERATED OUTPUT DATA                            
echo ==============================================================================
echo.
echo WARNING: This will delete all generated outputs in 'data\output':
echo   - Simulation runs (seed_0 to seed_9)
echo   - Evaluation results and metrics CSVs
echo   - Generated charts (PNGs)
echo   - Manual red team demo logs
echo.
echo Note: 'data\sample_events.csv' and 'data\sample_labels.csv' will NOT be touched.
echo.
set /p "CONFIRM=Are you sure you want to delete all generated data? (Y/N): "
if /i "%CONFIRM%"=="Y" (
    echo.
    echo Cleaning 'data\output'...
    if exist "data\output" (
        rd /s /q "data\output"
        echo Done! 'data\output' has been completely cleared.
    ) else (
        echo 'data\output' is already clean!
    )
) else (
    echo.
    echo Cleaning canceled. No data was deleted.
)
echo.
pause
goto MENU

:QUIT
echo.
echo Exiting CyberForge Lite. Goodbye!
exit /b

