# Deploy Codex Cross-Platform

Installer script for provisioning Codex CLI dependencies and environment tweaks on Windows (PowerShell), with support for profile configuration and font setup.

## Requirements
- Windows 10 or later
- PowerShell 5.1 or PowerShell 7+
- Administrator privileges recommended for installing fonts and system-wide components

## Quick Start
Run the installer directly from GitHub (PowerShell prompt):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/Baphomet480/deploy-codex-crossplatform/main/install-codex.ps1 -UseBasicParsing | iex"
```

> The script modifies your PowerShell profile to enable completion helpers and may install fonts; review `install-codex.ps1` before running if you need to audit changes.

## Local Usage
1. Clone the repository: `git clone https://github.com/Baphomet480/deploy-codex-crossplatform.git`
2. Inspect or customize `install-codex.ps1`
3. Execute locally: `pwsh -File install-codex.ps1` (or `powershell -File install-codex.ps1`)

## Contributing
Pull requests are welcome. Please open an issue to discuss significant changes before submitting a PR.

## License
Distributed under the MIT License; see `LICENSE` if present or include one before publishing.
