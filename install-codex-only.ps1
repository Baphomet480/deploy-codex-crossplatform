[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Ensure TLS 1.2 for old PowerShell builds.
if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12 -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$GITHUB_HEADERS = @{ 'User-Agent' = 'codex-lite-installer' }

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-CpuArchitecture {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { return 'aarch64' }
        default { return 'x86_64' }
    }
}

function Set-UserPathEntry {
    param([Parameter(Mandatory)][string]$InstallRoot)

    $currentUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $currentUserPath) { $currentUserPath = '' }

    $pathEntries = $currentUserPath -split ';' | Where-Object { $_ -and $_.Trim() }
    if ($pathEntries -contains $InstallRoot) {
        return
    }

    $newUserPath = if ($currentUserPath) { $currentUserPath.TrimEnd(';') + ';' + $InstallRoot } else { $InstallRoot }
    [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')

    $processPath = $env:PATH -split ';'
    if ($processPath -notcontains $InstallRoot) {
        $env:PATH = ($processPath + $InstallRoot | Where-Object { $_ } | Select-Object -Unique) -join ';'
    }

    Write-Host "Added $InstallRoot to PATH for the current user."
}

function Get-LatestCodexRelease {
    $apiUrl = 'https://api.github.com/repos/openai/codex/releases/latest'
    Write-Host "Fetching latest Codex release metadata..."
    return Invoke-RestMethod -Uri $apiUrl -Headers $GITHUB_HEADERS
}

function Install-Codex {
    $release    = Get-LatestCodexRelease
    $version    = if ($release.name) { $release.name } elseif ($release.tag_name) { $release.tag_name } else { 'unknown' }
    $arch       = Get-CpuArchitecture
    $assetName  = "codex-$arch-pc-windows-msvc*.zip"
    $asset      = $release.assets | Where-Object { $_.name -like $assetName } | Select-Object -First 1

    if (-not $asset) {
        throw "No Windows asset matching $assetName found in latest release."
    }

    $cacheRoot   = Join-Path -Path $env:TEMP -ChildPath 'codex-lite-cache'
    Ensure-Directory -Path $cacheRoot
    $archivePath = Join-Path -Path $cacheRoot -ChildPath $asset.name

    Write-Host "Downloading $($asset.name)..."
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -Headers $GITHUB_HEADERS -UseBasicParsing -ErrorAction Stop

    $extractPath = Join-Path -Path $cacheRoot -ChildPath 'extracted'
    if (Test-Path -Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force
    }
    Expand-Archive -Path $archivePath -DestinationPath $extractPath -Force

    $downloadedExe = Get-ChildItem -Path $extractPath -Filter '*.exe' -Recurse | Select-Object -First 1
    if (-not $downloadedExe) {
        throw 'Codex executable not found in the downloaded archive.'
    }

    $installRoot = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Programs\\Codex'
    Ensure-Directory -Path $installRoot
    $exePath = Join-Path -Path $installRoot -ChildPath 'codex.exe'
    Copy-Item -Path $downloadedExe.FullName -Destination $exePath -Force

    $versionFile = Join-Path -Path $installRoot -ChildPath 'codex-version.txt'
    Set-Content -Path $versionFile -Value $version -Encoding Ascii

    Set-UserPathEntry -InstallRoot $installRoot
    Write-Host "Codex $version installed to $exePath."

    return @{ Version = $version; InstallRoot = $installRoot; Executable = $exePath }
}

function Write-CodexConfig {
    $configDir  = Join-Path -Path $env:USERPROFILE -ChildPath '.codex'
    $configPath = Join-Path -Path $configDir -ChildPath 'config.toml'
    Ensure-Directory -Path $configDir

    $existing = ''
    if (Test-Path -Path $configPath) {
        $existing = Get-Content -Path $configPath -Raw -ErrorAction SilentlyContinue
    }

    $markerName  = 'codex-lite-installer managed settings'
    $markerStart = "# >>> $markerName >>>"
    $markerEnd   = "# <<< $markerName <<<"

    if ($existing) {
        $pattern = "(?ms)^\s*" + [regex]::Escape($markerStart) + ".*?" + [regex]::Escape($markerEnd) + "\s*"
        $existing = [regex]::Replace($existing, $pattern, '').Trim()
    }

    $managedBody = @'
model = "gpt-5-codex"
approval_policy = "never"
sandbox_mode = "danger-full-access"
model_reasoning_effort = "medium"

skip_git_repo_check = true

profile = "deep"
[features]
web_search_request = true
rmcp_client = true
unified_exec = false
streamable_shell = true
apply_patch_freeform = true
experimental_sandbox_command_assessment = false
ghost_commit = true

[profiles.fast]
approval_policy = "never"
sandbox_mode = "danger-full-access"
skip_git_repo_check = true

[profiles.fast.features]
web_search_request = true
rmcp_client = true
ghost_commit = true
unified_exec = false
streamable_shell = false
apply_patch_freeform = false
experimental_sandbox_command_assessment = false

[profiles.deep]
approval_policy = "never"
sandbox_mode = "danger-full-access"
skip_git_repo_check = true
model_reasoning_effort = "high"
model = "gpt-5-codex"

[profiles.deep.features]
web_search_request = true
rmcp_client = true
unified_exec = false
streamable_shell = true
apply_patch_freeform = true
experimental_sandbox_command_assessment = false
ghost_commit = true

[profiles.deep-experimental]
approval_policy = "never"
sandbox_mode = "danger-full-access"
skip_git_repo_check = true
model_reasoning_effort = "medium"

[profiles.deep-experimental.features]
web_search_request = true
rmcp_client = true
unified_exec = false
streamable_shell = true
apply_patch_freeform = true
experimental_sandbox_command_assessment = true
ghost_commit = true
'@.Trim()

    $newContent = $markerStart + "`r`n" + $managedBody + "`r`n" + $markerEnd
    if ($existing) {
        $newContent += "`r`n`r`n" + $existing
    }

    Set-Content -Path $configPath -Value $newContent -Encoding UTF8
    Write-Host "Codex config written to $configPath."
}

Write-Host '--- Installing Codex (lite) ---'
$install = Install-Codex
Write-Host '--- Updating config ---'
Write-CodexConfig
Write-Host ''
Write-Host "Done. Launch a new terminal or run 'codex --help' to verify. (Installed $($install.Version))"
