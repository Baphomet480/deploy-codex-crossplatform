[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Ensure TLS 1.2 for old PowerShell builds.
if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12 -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$GITHUB_HEADERS = @{ 'User-Agent' = 'codex-lite-installer' }
$CACHE_ROOT     = Join-Path -Path $env:TEMP -ChildPath 'codex-lite-cache'

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Ensure-ArchiveModule {
    # On older Windows/PowerShell (e.g., Server 2016), Expand-Archive may not be preloaded.
    if (-not (Get-Command Expand-Archive -ErrorAction SilentlyContinue)) {
        Import-Module Microsoft.PowerShell.Archive -ErrorAction Stop
    }
}

function Assert-MinimumPSVersion {
    $min = [version]'5.1'
    if ($PSVersionTable.PSVersion -lt $min) {
        throw "PowerShell $($PSVersionTable.PSVersion) detected; Codex installer requires $min or newer (present by default on Windows Server 2016+)."
    }
}

function Assert-WindowsHost {
    # $IsWindows is not present on some Windows PowerShell builds; fall back to environment check.
    $isWindows = $false
    if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
        $isWindows = [bool]$IsWindows
    }
    if (-not $isWindows) {
        $isWindows = ($env:OS -eq 'Windows_NT')
    }
    if (-not $isWindows) {
        throw "This installer targets Windows. Please run on Windows PowerShell 5.1+ or PowerShell (pwsh) on Windows."
    }
}

function Get-CpuArchitecture {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { return 'aarch64' }
        default { return 'x86_64' }
    }
}

function Compare-VersionStrings {
    param(
        [Parameter(Mandatory)][string]$A,
        [Parameter(Mandatory)][string]$B
    )

    $parse = {
        param($s)
        $match = [regex]::Match($s, '(\d+(\.\d+)+)')
        if (-not $match.Success) { return $null }
        return [version]$match.Groups[1].Value
    }

    $va = & $parse $A
    $vb = & $parse $B
    if (-not $va -or -not $vb) { return 0 }
    return $va.CompareTo($vb)
}

function Get-CacheRoot {
    Ensure-Directory -Path $CACHE_ROOT
    return $CACHE_ROOT
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

function Download-WithRetry {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [int]$MaxAttempts = 4,
        [int]$DelaySeconds = 3
    )

    if (Test-Path -LiteralPath $OutFile) {
        Write-Host "Using cached $OutFile"
        return
    }

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            Write-Host "Downloading $Uri (attempt $i/$MaxAttempts)..."
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $GITHUB_HEADERS -UseBasicParsing -ErrorAction Stop
            return
        } catch {
            if ($i -eq $MaxAttempts) { throw }
            $wait = [Math]::Pow(2, $i - 1) * $DelaySeconds
            Write-Warning "Download failed: $($_.Exception.Message). Retrying in $wait seconds..."
            Start-Sleep -Seconds $wait
        }
    }
}

function Install-NerdFont {
    param([string]$FontName = 'Meslo')

    Ensure-ArchiveModule

    $fontDir = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\\Windows\\Fonts'
    Ensure-Directory -Path $fontDir

    if (Get-ChildItem -Path $fontDir -Filter "$FontName* Nerd Font*.ttf" -ErrorAction SilentlyContinue | Select-Object -First 1) {
        Write-Host "$FontName Nerd Font already present; skipping."
        return
    }

    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/ryanoasis/nerd-fonts/releases/latest' -Headers $GITHUB_HEADERS

    $candidates = @($FontName, 'Meslo', 'JetBrainsMono', 'CascadiaCode')
    $asset = $null
    foreach ($name in $candidates) {
        $asset = $release.assets | Where-Object { $_.name -ieq "$name.zip" } | Select-Object -First 1
        if ($asset) {
            if ($name -ne $FontName) {
                Write-Warning "Requested font '$FontName' not found; falling back to '$name'."
            }
            break
        }
    }
    if (-not $asset) {
        throw "No suitable Nerd Font asset found (tried: $($candidates -join ', '))."
    }

    $cacheRoot   = Get-CacheRoot
    $archivePath = Join-Path -Path $cacheRoot -ChildPath $asset.name
    $extractPath = Join-Path -Path $cacheRoot -ChildPath 'nerd-fonts-extracted'
    if (Test-Path -Path $extractPath) { Remove-Item -Path $extractPath -Recurse -Force }

    Download-WithRetry -Uri $asset.browser_download_url -OutFile $archivePath
    Expand-Archive -Path $archivePath -DestinationPath $extractPath -Force

    $ttfFiles = Get-ChildItem -Path $extractPath -Filter '*.ttf' -Recurse
    if (-not $ttfFiles) { throw "No TTF files found in $FontName package." }

    if (-not ('Win32.FontUtil' -as [type])) {
        Add-Type -Namespace Win32 -Name FontUtil -MemberDefinition @"
using System;
using System.Runtime.InteropServices;
public static class FontUtil {
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int AddFontResourceEx(string lpszFilename, uint fl, IntPtr pdv);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern int SendMessageTimeout(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam, uint fuFlags, uint uTimeout, out IntPtr lpdwResult);
}
"@
    }

    foreach ($file in $ttfFiles) {
        $dest = Join-Path -Path $fontDir -ChildPath $file.Name
        Copy-Item -Path $file.FullName -Destination $dest -Force
        [Win32.FontUtil]::AddFontResourceEx($dest, 0, [IntPtr]::Zero) | Out-Null
    }

    [Win32.FontUtil]::SendMessageTimeout([IntPtr]0xffff, 0x001D, [IntPtr]0, [IntPtr]0, 0, 1000, [ref]([IntPtr]::Zero)) | Out-Null
    Write-Host "$FontName Nerd Font installed for current user."
}

function Install-Git {
    $arch        = Get-CpuArchitecture
    $assetPattern = if ($arch -eq 'aarch64') { 'Git-*-arm64.exe' } else { 'Git-*-64-bit.exe' }
    $release     = Invoke-RestMethod -Uri 'https://api.github.com/repos/git-for-windows/git/releases/latest' -Headers $GITHUB_HEADERS
    $asset       = $release.assets | Where-Object { $_.name -like $assetPattern } | Select-Object -First 1
    if (-not $asset) { throw "No Git installer matching $assetPattern found in latest release." }

    $current = $null
    if (Get-Command git.exe -ErrorAction SilentlyContinue) {
        $current = (git --version 2>$null | Select-Object -First 1)
    }
    $latestTag = $release.tag_name
    if (-not $Force -and $current -and $latestTag) {
        if ((Compare-VersionStrings -A $current -B $latestTag) -ge 0) {
            Write-Host "Git already at $current (latest $latestTag); skipping."
            return
        }
        Write-Host "Git present ($current) but outdated vs $latestTag; updating..."
    }

    $installerPath = Join-Path -Path (Get-CacheRoot) -ChildPath $asset.name
    Download-WithRetry -Uri $asset.browser_download_url -OutFile $installerPath

    Write-Host 'Installing Git silently...'
    $proc = Start-Process -FilePath $installerPath -ArgumentList '/VERYSILENT','/NORESTART','/SP-' -Wait -PassThru -WindowStyle Hidden
    if ($proc.ExitCode -ne 0) { throw "Git installer failed with exit code $($proc.ExitCode)." }
    Write-Host 'Git installed.'
}

function Install-GitHubCli {
    $arch        = Get-CpuArchitecture
    $assetPattern = if ($arch -eq 'aarch64') { 'gh_*_windows_arm64.msi' } else { 'gh_*_windows_amd64.msi' }
    $release     = Invoke-RestMethod -Uri 'https://api.github.com/repos/cli/cli/releases/latest' -Headers $GITHUB_HEADERS
    $asset       = $release.assets | Where-Object { $_.name -like $assetPattern } | Select-Object -First 1
    if (-not $asset) { throw "No GitHub CLI installer matching $assetPattern found in latest release." }

    $current = $null
    if (Get-Command gh.exe -ErrorAction SilentlyContinue) {
        $current = (gh --version 2>$null | Select-Object -First 1)
    }
    $latestTag = $release.tag_name
    if (-not $Force -and $current -and $latestTag) {
        if ((Compare-VersionStrings -A $current -B $latestTag) -ge 0) {
            Write-Host "GitHub CLI already at $current (latest $latestTag); skipping."
            return
        }
        Write-Host "GitHub CLI present ($current) but outdated vs $latestTag; updating..."
    }

    $installerPath = Join-Path -Path (Get-CacheRoot) -ChildPath $asset.name
    Download-WithRetry -Uri $asset.browser_download_url -OutFile $installerPath

    Write-Host 'Installing GitHub CLI silently...'
    $args = @('/i', $installerPath, '/qn', '/norestart', 'ALLUSERS=2', 'MSIINSTALLPERUSER=1')
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if ($proc.ExitCode -ne 0) { throw "GitHub CLI installer failed with exit code $($proc.ExitCode)." }
    Write-Host 'GitHub CLI installed.'
}

function Test-VCRuntimeInstalled {
    param([string]$Arch)

    $keyName = switch ($Arch) {
        'aarch64' { 'Arm64' }
        default   { 'x64' }
    }
    $regPath = "HKLM:\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\$keyName"
    try {
        $key = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($key -and $key.Installed -eq 1 -and $key.MinimumVersion -gt 0) {
            return $true
        }
    } catch { }

    # Fallback: look for vcruntime140.dll in system folders.
    $dllName = 'vcruntime140.dll'
    $systemPaths = @("$env:SystemRoot\\System32", "$env:SystemRoot\\SysWOW64")
    foreach ($p in $systemPaths) {
        $candidate = Join-Path -Path $p -ChildPath $dllName
        if (Test-Path -Path $candidate) { return $true }
    }
    return $false
}

function Install-VCRuntime {
    $arch = Get-CpuArchitecture
    if (Test-VCRuntimeInstalled -Arch $arch) {
        Write-Host "VC++ Runtime already present for $arch; skipping."
        return
    }

    $assetUrl = if ($arch -eq 'aarch64') { 'https://aka.ms/vs/17/release/vc_redist.arm64.exe' } else { 'https://aka.ms/vs/17/release/vc_redist.x64.exe' }
    $fileName = Split-Path -Leaf $assetUrl
    $outFile  = Join-Path -Path (Get-CacheRoot) -ChildPath $fileName

    Write-Host "Downloading VC++ Runtime for $arch..."
    Download-WithRetry -Uri $assetUrl -OutFile $outFile

    Write-Host "Installing VC++ Runtime silently..."
    $args = '/install','/quiet','/norestart'
    $proc = Start-Process -FilePath $outFile -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if ($proc.ExitCode -ne 0) {
        throw "VC++ Runtime installer failed with exit code $($proc.ExitCode)."
    }
    Write-Host "VC++ Runtime installed."
}

function Install-Codex {
    Ensure-ArchiveModule

    $release     = Get-LatestCodexRelease
    $version     = if ($release.name) { $release.name } elseif ($release.tag_name) { $release.tag_name } else { 'unknown' }
    $arch        = Get-CpuArchitecture
    $assetName   = "codex-$arch-pc-windows-msvc*.zip"
    $asset       = $release.assets | Where-Object { $_.name -like $assetName } | Select-Object -First 1
    $installRoot = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Programs\\Codex'
    $exePath     = Join-Path -Path $installRoot -ChildPath 'codex.exe'

    if (-not $asset) {
        throw "No Windows asset matching $assetName found in latest release."
    }

    $currentVersion = $null

    try {
        # Prefer a real executable on PATH for truth.
        $currentVersion = (codex --version 2>$null | Select-Object -First 1)
    } catch { }

    if (-not $currentVersion) {
        $installedFile = Join-Path -Path $installRoot -ChildPath 'codex-version.txt'
        if (Test-Path -Path $installedFile) {
            $currentVersion = Get-Content -Path $installedFile -ErrorAction SilentlyContinue | Select-Object -First 1
        }
    }

    # If a version marker exists but the exe is gone, force reinstall.
    if ($currentVersion -and -not (Test-Path -Path $exePath)) {
        Write-Host "Codex version marker found but executable missing; reinstalling..."
        $currentVersion = $null
    }

    if (-not $Force -and $currentVersion) {
        if ((Compare-VersionStrings -A $currentVersion -B $version) -ge 0) {
            Write-Host "Codex already at $currentVersion (latest $version); ensuring PATH entry and skipping download."
            Set-UserPathEntry -InstallRoot $installRoot
            return @{ Version = $currentVersion; InstallRoot = $installRoot; Executable = $exePath }
        }
        Write-Host "Codex present ($currentVersion) but outdated vs $version; updating..."
    }

    $cacheRoot   = Get-CacheRoot
    $archivePath = Join-Path -Path $cacheRoot -ChildPath $asset.name

    Download-WithRetry -Uri $asset.browser_download_url -OutFile $archivePath

    $extractPath = Join-Path -Path $cacheRoot -ChildPath 'extracted'
    if (Test-Path -Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force
    }
    Expand-Archive -Path $archivePath -DestinationPath $extractPath -Force

    $downloadedExe = Get-ChildItem -Path $extractPath -Filter '*.exe' -Recurse | Select-Object -First 1
    if (-not $downloadedExe) {
        throw 'Codex executable not found in the downloaded archive.'
    }

    Ensure-Directory -Path $installRoot
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
Assert-WindowsHost
Assert-MinimumPSVersion
Write-Host '--- Ensuring VC++ Runtime ---'
Install-VCRuntime
$install = Install-Codex
Write-Host '--- Updating config ---'
Write-CodexConfig
Write-Host '--- Ensuring Git ---'
Install-Git
Write-Host '--- Ensuring GitHub CLI ---'
Install-GitHubCli
Write-Host '--- Installing Nerd Font (Menlo) ---'
try {
    Install-NerdFont -FontName 'Menlo'
} catch {
    Write-Warning "Nerd Font install failed: $($_.Exception.Message). Continuing without font."
}
Write-Host ''
Write-Host "Done. Launch a new terminal or run 'codex --help' to verify. (Installed $($install.Version))"
