@echo off
cd /d C:\xampp\htdocs\Final_AI

:: 啟動虛擬環境
call venv\Scripts\activate

:: 啟動 FastAPI
python -m uvicorn detect_api:app --host 127.0.0.1 --port 8000

pause
