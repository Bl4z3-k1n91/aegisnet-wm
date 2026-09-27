$ErrorActionPreference = 'Stop'
$python = 'D:\deep\python.exe'
$app = Join-Path $PSScriptRoot 'app.py'
& $python -m streamlit run $app --server.address 0.0.0.0 --server.port 8501
