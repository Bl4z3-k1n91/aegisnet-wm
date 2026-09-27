# Prototype cyber model and SOC UI

## Train

```powershell
& 'D:\deep\python.exe' .\models\train_clean_traffic.py
```

Artifacts are written to `models/artifacts/ntro-clean-traffic-v1/`.

The current model is a prototype trained on the small clean seed release under
`dataset/releases/ntro-clean-traffic-v1`. The reported stratified CV metrics
are provisional and must not be treated as final run-level generalisation
results.

## Run the UI

```powershell
& 'D:\deep\python.exe' -m pip install -r .\requirements.txt
.\ui\run_ui.ps1
```

Open `http://localhost:8501`.

The dashboard reads `outputs/telemetry.db`, builds the latest 10-second
traffic-only cyber state, and displays model probabilities, cyber risk,
feature evidence, temporal predictions, model diagnostics and dataset details.
