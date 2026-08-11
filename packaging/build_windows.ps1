# Build both desktop demos on Windows (run from repo root).
$ErrorActionPreference = "Stop"

Write-Host "==> Building buyer UI (Rust/egui)"
Push-Location client-ui
cargo build --release
Pop-Location

Write-Host "==> Building artist UI (PySide6)"
python -m pip install --upgrade PySide6 cryptography pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed `
  --name ModelLockArtist `
  --paths . `
  artist-ui/main.py

Write-Host "==> Collecting artifacts"
New-Item -ItemType Directory -Force -Path packaging\output | Out-Null
Copy-Item client-ui\target\release\modelock-client-ui.exe packaging\output\
Copy-Item dist\ModelLockArtist.exe packaging\output\
Write-Host "Artifacts in packaging\output:"
Get-ChildItem packaging\output | Select-Object Name, Length
