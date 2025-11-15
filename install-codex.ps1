[CmdletBinding()]
param(
    [switch]$SkipFontSetup,
    [string]$CacheRoot
)

$ErrorActionPreference = 'Stop'

# ==================== CACHE CONFIGURATION ====================
function Test-CachePathWritable {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        return $false
    }

    try {
        if (-not (Test-Path -LiteralPath $fullPath)) {
            [System.IO.Directory]::CreateDirectory($fullPath) | Out-Null
        }
        $probe = Join-Path -Path $fullPath -ChildPath (".__probe_{0}.tmp" -f ([Guid]::NewGuid().ToString('N')))
        [System.IO.File]::WriteAllText($probe, 'ok')
        [System.IO.File]::Delete($probe)
        return $true
    }
    catch {
        return $false
    }
}

function Resolve-InstallerCacheRoot {
    param([Parameter(Mandatory)][string[]]$Candidates)

    foreach ($candidate in $Candidates | Where-Object { $_ } | Select-Object -Unique) {
        $resolvedCandidate = $candidate
        try {
            $resolvedCandidate = (Resolve-Path -Path $candidate -ErrorAction Stop).ProviderPath
        }
        catch {
            try {
                $resolvedCandidate = [System.IO.Path]::GetFullPath($candidate)
            }
            catch {
                continue
            }
        }

        if (Test-CachePathWritable -Path $resolvedCandidate) {
            return $resolvedCandidate
        }
    }

    return $null
}

$script:InstallerHttpClient = $null
$script:InstallerHttpClientHandler = $null

$scriptDirectory = $null
$scriptFromMemory = $false
if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    $scriptDirectory = Split-Path -Path $PSCommandPath -Parent
}
elseif (-not [string]::IsNullOrWhiteSpace($MyInvocation.MyCommand.Path)) {
    $scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
}
else {
    $scriptDirectory = (Get-Location).Path
    $scriptFromMemory = $true
}
if ($scriptFromMemory) {
    $downloadsDirectory = $null
    try {
        $downloadsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Downloads)
    }
    catch {
        $downloadsDirectory = $null
    }
    if (-not $downloadsDirectory -or -not (Test-Path -Path $downloadsDirectory)) {
        $userProfile = $null
        try { $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile) } catch { $userProfile = $env:USERPROFILE }
        if ($userProfile) {
            $downloadsDirectory = Join-Path -Path $userProfile -ChildPath 'Downloads'
        }
    }
    if ($downloadsDirectory) {
        try {
            if (-not (Test-Path -Path $downloadsDirectory)) {
                New-Item -ItemType Directory -Path $downloadsDirectory -Force | Out-Null
            }
        }
        catch {
            $downloadsDirectory = $null
        }
    }
    if ($downloadsDirectory -and (Test-Path -Path $downloadsDirectory)) {
        $scriptDirectory = $downloadsDirectory
    }
}
if ([string]::IsNullOrWhiteSpace($scriptDirectory)) {
    $scriptDirectory = [System.IO.Path]::GetTempPath()
}
$cacheRootCandidates = @()
if (-not [string]::IsNullOrWhiteSpace($CacheRoot)) {
    $cacheRootCandidates += $CacheRoot
}
if (-not [string]::IsNullOrWhiteSpace($env:CODEX_INSTALLER_CACHE)) {
    $cacheRootCandidates += $env:CODEX_INSTALLER_CACHE
}
$cacheRootCandidates += (Join-Path -Path $scriptDirectory -ChildPath 'cache')
$tempRoot = $env:TEMP
if ([string]::IsNullOrWhiteSpace($tempRoot)) {
    $tempRoot = [System.IO.Path]::GetTempPath()
}
$cacheRootCandidates += (Join-Path -Path $tempRoot -ChildPath 'codex-installer-cache')

$CACHE_ROOT = Resolve-InstallerCacheRoot -Candidates $cacheRootCandidates
if (-not $CACHE_ROOT) {
    throw 'Unable to determine a writable cache directory for the installer.'
}

$CACHE_DOWNLOAD_ROOT = Join-Path -Path $CACHE_ROOT -ChildPath 'downloads'
$DOWNLOAD_ROOT = Join-Path -Path $CACHE_ROOT -ChildPath 'workspace'
$CODEX_DOWNLOAD_ROOT = Join-Path -Path $DOWNLOAD_ROOT -ChildPath 'codex'
$FONT_DOWNLOAD_ROOT = Join-Path -Path $DOWNLOAD_ROOT -ChildPath 'font'
$EnableFontSetup = -not $SkipFontSetup

$GITHUB_HEADERS = @{
    'Accept'     = 'application/vnd.github+json'
    'User-Agent' = 'codex-installer-script'
}

# ==================== VALIDATION ====================
function Test-Prerequisites {
    if (-not $env:OS -or $env:OS.ToUpperInvariant() -ne 'WINDOWS_NT') {
        throw 'This installer must be run on Windows.'
    }
    if ([IntPtr]::Size -lt 8) {
        throw 'Codex requires a 64-bit Windows environment.'
    }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required to configure system defaults for Codex. Please re-run this script in an elevated PowerShell session.'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ==================== UTILITY FUNCTIONS ====================
function Initialize-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Get-CacheSafeSegment {
    param([Parameter(Mandatory)][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return 'default'
    }

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $builder = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        if ($invalidChars -contains $ch) {
            [void]$builder.Append('_')
        }
        else {
            [void]$builder.Append($ch)
        }
    }

    $result = $builder.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($result)) {
        return 'default'
    }

    return $result
}

function Get-InstallerHttpClient {
    if (-not $script:InstallerHttpClient) {
        $httpAssemblyLoaded = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'System.Net.Http' }
        if (-not $httpAssemblyLoaded) {
            Add-Type -AssemblyName System.Net.Http
        }
        $script:InstallerHttpClientHandler = [System.Net.Http.HttpClientHandler]::new()
        $script:InstallerHttpClientHandler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $script:InstallerHttpClient = [System.Net.Http.HttpClient]::new($script:InstallerHttpClientHandler)
        $script:InstallerHttpClient.Timeout = [TimeSpan]::FromMinutes(15)
        if (-not $script:InstallerHttpClient.DefaultRequestHeaders.UserAgent) {
            $script:InstallerHttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('codex-installer-script')
        }
    }
    return $script:InstallerHttpClient
}

function Get-DownloadCachePath {
    param([Parameter(Mandatory)][string]$CacheKey)

    $relative = $CacheKey -replace '^[\\/]+', ''
    return Join-Path -Path $CACHE_DOWNLOAD_ROOT -ChildPath $relative
}

function Test-CachedDownload {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ExpectedHash
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $hashFile = $Path + '.sha256'
    $expected = $ExpectedHash
    if (-not $expected -and (Test-Path -LiteralPath $hashFile)) {
        $expected = (Get-Content -Path $hashFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    }

    try {
        $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    }
    catch {
        return $false
    }

    if ($expected) {
        if ($actual -ne $expected) {
            try { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { }
            if (Test-Path -LiteralPath $hashFile) {
                try { Remove-Item -LiteralPath $hashFile -Force -ErrorAction Stop } catch { }
            }
            return $false
        }
    }
    else {
        try {
            Set-Content -Path $hashFile -Value $actual -Encoding ascii -Force
        }
        catch {
            Write-Verbose ("Unable to persist hash for cache entry {0}: {1}" -f $Path, $_.Exception.Message)
        }
    }

    return $true
}

function Remove-DownloadCacheEntry {
    param([Parameter(Mandatory)][string]$CacheKey)

    if ([string]::IsNullOrWhiteSpace($CacheKey)) {
        return
    }

    $cachePath = Get-DownloadCachePath -CacheKey $CacheKey
    if (-not $cachePath) {
        return
    }

    foreach ($entry in @($cachePath, "$cachePath.sha256")) {
        if ($entry -and (Test-Path -LiteralPath $entry)) {
            try {
                Remove-Item -LiteralPath $entry -Force -ErrorAction Stop
            }
            catch {
                Write-Verbose ("Unable to remove cache entry {0}: {1}" -f $entry, $_.Exception.Message)
            }
        }
    }
}

function Invoke-Download {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Destination,
        [string]$CacheKey,
        [object]$ExpectedHash
    )

    $destinationDirectory = Split-Path -Path $Destination -Parent
    if ($destinationDirectory) {
        Initialize-Directory -Path $destinationDirectory
    }

    $cachePath = $null
    if ($CacheKey) {
        $cachePath = Get-DownloadCachePath -CacheKey $CacheKey
        $cacheDirectory = Split-Path -Path $cachePath -Parent
        if ($cacheDirectory) {
            Initialize-Directory -Path $cacheDirectory
        }
        $hashValue = $null
        if ($PSBoundParameters.ContainsKey('ExpectedHash') -and $null -ne $ExpectedHash) {
            $hashValue = [string]$ExpectedHash
            if ([string]::IsNullOrWhiteSpace($hashValue)) {
                $hashValue = $null
            }
        }
        if (Test-CachedDownload -Path $cachePath -ExpectedHash $hashValue) {
            Copy-Item -LiteralPath $cachePath -Destination $Destination -Force
            return
        }
    }

    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        Write-Verbose "Downloading $Uri -> $Destination"
        $client = Get-InstallerHttpClient
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
        $response = $null
        try {
            $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $response.EnsureSuccessStatusCode()

            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $fileStream = [System.IO.File]::Open($tempFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 81920
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $fileStream.Write($buffer, 0, $read)
                }
            }
            finally {
                $fileStream.Dispose()
                $stream.Dispose()
            }
        }
        finally {
            if ($response) { $response.Dispose() }
            $request.Dispose()
        }
    }
    catch {
        if (Test-Path -LiteralPath $tempFile) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
        throw
    }

    $hashInfo = $null
    try {
        $hashInfo = Get-FileHash -Path $tempFile -Algorithm SHA256
    }
    catch {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        throw
    }

    $hashValueToEnforce = $null
    if ($PSBoundParameters.ContainsKey('ExpectedHash') -and $null -ne $ExpectedHash) {
        $hashValueToEnforce = [string]$ExpectedHash
        if ([string]::IsNullOrWhiteSpace($hashValueToEnforce)) {
            $hashValueToEnforce = $null
        }
    }

    if ($hashValueToEnforce -and $hashInfo.Hash -ne $hashValueToEnforce) {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        throw "Downloaded file hash mismatch for $Uri."
    }

    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }
    Copy-Item -LiteralPath $tempFile -Destination $Destination -Force

    if ($cachePath) {
        Copy-Item -LiteralPath $tempFile -Destination $cachePath -Force
        try {
            Set-Content -Path ($cachePath + '.sha256') -Value $hashInfo.Hash -Encoding ascii -Force
        }
        catch {
            Write-Verbose ("Unable to persist hash for cache entry {0}: {1}" -f $cachePath, $_.Exception.Message)
        }
    }

    Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
}

function Get-ReleaseAssetExpectedHash {
    param(
        [Parameter(Mandatory)][object]$Release,
        [Parameter(Mandatory)][object]$Asset,
        [Parameter(Mandatory)][string]$CacheKeyBase,
        [Parameter(Mandatory)][string]$WorkspaceDirectory
    )

    $expectedHash = $null

    $sha256Name = $Asset.name + '.sha256'
    $hashAsset = $Release.assets | Where-Object { $_.name -eq $sha256Name } | Select-Object -First 1
    if ($hashAsset) {
        $hashCacheKey = Join-Path -Path $CacheKeyBase -ChildPath (Get-CacheSafeSegment $sha256Name)
        $hashPath = Join-Path -Path $WorkspaceDirectory -ChildPath $sha256Name
        Invoke-Download -Uri $hashAsset.browser_download_url -Destination $hashPath -CacheKey $hashCacheKey
        $rawContent = Get-Content -Path $hashPath -Raw -ErrorAction SilentlyContinue
        if ($rawContent) {
            $match = [Regex]::Match($rawContent, '[0-9a-fA-F]{64}')
            if ($match.Success) {
                $expectedHash = $match.Value.ToUpperInvariant()
            }
        }
    }

    if (-not $expectedHash) {
        $checksumsAsset = $Release.assets | Where-Object { $_.name -eq 'checksums.txt' } | Select-Object -First 1
        if ($checksumsAsset) {
            $checksumsCacheKey = Join-Path -Path $CacheKeyBase -ChildPath 'checksums.txt'
            $checksumsPath = Join-Path -Path $WorkspaceDirectory -ChildPath 'checksums.txt'
            Invoke-Download -Uri $checksumsAsset.browser_download_url -Destination $checksumsPath -CacheKey $checksumsCacheKey
            $lines = Get-Content -Path $checksumsPath -ErrorAction SilentlyContinue
            if ($lines) {
                $pattern = "{0}$" -f [Regex]::Escape($Asset.name)
                $line = $lines | Where-Object { $_ -match $pattern } | Select-Object -First 1
                if ($line) {
                    $match = [Regex]::Match($line, '[0-9a-fA-F]{64}')
                    if ($match.Success) {
                        $expectedHash = $match.Value.ToUpperInvariant()
                    }
                }
            }
        }
    }

    return $expectedHash
}

function Get-GitHubLatestRelease {
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repo
    )
    $apiUrl = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    Write-Verbose "Fetching latest release metadata from $apiUrl"
    return Invoke-RestMethod -Uri $apiUrl -Headers $GITHUB_HEADERS
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
    if (-not $currentUserPath) {
        $currentUserPath = ''
    }
    $pathEntries = $currentUserPath -split ';' | Where-Object { $_ -and $_.Trim() }
    if ($pathEntries -notcontains $InstallRoot) {
        $newUserPath = if ($currentUserPath) { $currentUserPath.TrimEnd(';') + ';' + $InstallRoot } else { $InstallRoot }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')

        $processPathEntries = $env:PATH -split ';'
        if ($processPathEntries -notcontains $InstallRoot) {
            $env:PATH = ($processPathEntries + $InstallRoot | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique) -join ';'
        }

        Write-Host "Added $InstallRoot to the current user's PATH."
    }
    else {
        $processPathEntries = $env:PATH -split ';'
        if ($processPathEntries -notcontains $InstallRoot) {
            $env:PATH = ($processPathEntries + $InstallRoot | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique) -join ';'
            Write-Verbose "$InstallRoot already present in user PATH. Added to the current session PATH."
        }
        else {
            Write-Verbose "$InstallRoot already present in user PATH."
        }
    }
}

function Clear-InstallerDownloads {
    param([string[]]$Paths)

    foreach ($path in $Paths | Where-Object { $_ -and (Test-Path -Path $_) }) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Warning ("Unable to remove temporary download directory '{0}': {1}" -f $path, $_.Exception.Message)
        }
    }
}

# ==================== WINGET MANAGEMENT ====================
function Get-WingetInstallerPath {
    $candidateDirs = @(
        Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Scripts'
        Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Scripts'
        Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\PowerShell\Scripts'
        Join-Path $env:ProgramFiles 'WindowsPowerShell\Scripts'
        Join-Path ${env:ProgramFiles(x86)} 'WindowsPowerShell\Scripts'
    ) | Where-Object { $_ }

    foreach ($dir in $candidateDirs) {
        $candidate = Join-Path -Path $dir -ChildPath 'winget-install.ps1'
        if (Test-Path -Path $candidate) {
            return $candidate
        }
    }

    $command = Get-Command winget-install.ps1 -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    return $null
}

function Install-NuGetProvider {
    $provider = Get-PackageProvider -Name 'NuGet' -ListAvailable -ErrorAction SilentlyContinue
    if (-not $provider) {
        Write-Host 'Installing NuGet package provider...'
        Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Force
    }
}

function Set-PSGalleryTrust {
    try {
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
        if ($repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop
        }
    }
    catch {
        Write-Host 'Registering PowerShell Gallery repository...'
        Register-PSRepository -Name 'PSGallery' -SourceLocation 'https://www.powershellgallery.com/api/v2/' -InstallationPolicy Trusted -ErrorAction Stop
    }
}

function Install-WingetIfMissing {
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
        Write-Host 'winget already installed.'
        return
    }

    Write-Host 'winget not found - installing prerequisites...'
    Install-NuGetProvider
    Set-PSGalleryTrust
    Import-Module PowerShellGet -ErrorAction SilentlyContinue | Out-Null

    $installerPath = Get-WingetInstallerPath
    if ($installerPath) {
        Write-Host 'Updating existing winget-install helper script...'
        & $installerPath -SelfUpdate
    }
    else {
        Write-Host 'Downloading winget-install helper script from PowerShell Gallery...'
        Install-Script -Name 'winget-install' -Scope CurrentUser -Force -ErrorAction Stop
        $installerPath = Get-WingetInstallerPath
    }

    if (-not $installerPath) {
        throw 'Unable to locate winget-install.ps1 after installation.'
    }

    Write-Host 'Running winget-install helper script...'
    & $installerPath

    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'winget installation failed - review the output above.'
    }

    Write-Host 'winget installed successfully.'
}

function Install-WingetPackage {
    param(
        [Parameter(Mandatory)][string]$PackageId,
        [Parameter(Mandatory)][string]$DisplayName,
        [string]$CommandName,
        [string[]]$PathCandidates = @()
    )

    $wingetCmd = Get-Command winget.exe -ErrorAction Stop
    $wingetExe = $wingetCmd.Path
    Write-Host "Ensuring $DisplayName is installed via winget..."
    $arguments = @(
        'install',
        '--id', $PackageId,
        '--exact',
        '--source', 'winget',
        '--accept-source-agreements',
        '--accept-package-agreements'
    )

    & $wingetExe @arguments
    $exitCode = $LASTEXITCODE

    $command = $null
    if ($CommandName) {
        $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    }

    if (-not $command -and $PathCandidates) {
        foreach ($candidate in $PathCandidates) {
            if ($candidate -and (Test-Path -Path $candidate)) {
                Set-UserPathEntry -InstallRoot $candidate
            }
        }
        if ($CommandName) {
            $command = Get-Command $CommandName -ErrorAction SilentlyContinue
        }
    }

    if ($exitCode -ne 0) {
        if ($command) {
            Write-Warning "winget returned exit code $exitCode while installing $DisplayName, but the command '$CommandName' is already available. Continuing."
        }
        else {
            throw "winget failed to install $DisplayName (exit code $exitCode)."
        }
    }
    elseif ($CommandName -and -not $command) {
        Write-Warning "$DisplayName installed, but '$CommandName' is not yet on PATH - start a new session to use it."
    }
}

function Test-VcRuntimeInstalled {
    $winDir = $env:WINDIR
    if (-not $winDir) {
        return $false
    }

    $system32Candidates = @(
        Join-Path -Path $winDir -ChildPath 'System32\vcruntime140.dll'
        Join-Path -Path $winDir -ChildPath 'System32\vcruntime140_1.dll'
    ) | Where-Object { $_ }

    foreach ($candidate in $system32Candidates) {
        if (Test-Path -Path $candidate) {
            return $true
        }
    }

    if ([Environment]::Is64BitOperatingSystem) {
        $sysWowCandidates = @(
            Join-Path -Path $winDir -ChildPath 'SysWOW64\vcruntime140.dll'
            Join-Path -Path $winDir -ChildPath 'SysWOW64\vcruntime140_1.dll'
        ) | Where-Object { $_ }

        foreach ($candidate in $sysWowCandidates) {
            if (Test-Path -Path $candidate) {
                return $true
            }
        }
    }

    return $false
}

function Install-VcRuntimeDirect {
    Write-Host 'Downloading Microsoft Visual C++ Redistributable (x64)...'
    $installerName = 'vc_redist.x64.exe'
    $downloadPath = Join-Path -Path $CODEX_DOWNLOAD_ROOT -ChildPath $installerName
    $cacheKey = Join-Path -Path 'vcredist' -ChildPath $installerName

    Invoke-Download -Uri 'https://aka.ms/vs/17/release/vc_redist.x64.exe' -Destination $downloadPath -CacheKey $cacheKey

    Write-Host 'Installing Microsoft Visual C++ Redistributable (x64)...'
    $process = Start-Process -FilePath $downloadPath -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru -ErrorAction Stop
    if ($process.ExitCode -ne 0) {
        throw ("vc_redist.x64.exe returned exit code {0}." -f $process.ExitCode)
    }
}

function Ensure-VcRuntime {
    if (Test-VcRuntimeInstalled) {
        Write-Verbose 'Microsoft Visual C++ runtime already present.'
        return
    }

    Write-Host 'Microsoft Visual C++ runtime not detected - attempting installation...'
    $installed = $false
    try {
        Install-WingetPackage -PackageId 'Microsoft.VCRedist.2015+.x64' -DisplayName 'Microsoft Visual C++ Redistributable 2015-2022 (x64)'
        $installed = Test-VcRuntimeInstalled
    }
    catch {
        Write-Warning ("winget installation of Microsoft Visual C++ Redistributable failed: {0}" -f $_.Exception.Message)
    }

    if (-not $installed) {
        try {
            Install-VcRuntimeDirect
            $installed = Test-VcRuntimeInstalled
        }
        catch {
            throw ("Unable to install Microsoft Visual C++ Redistributable (x64): {0}" -f $_.Exception.Message)
        }
    }

    if ($installed) {
        Write-Host 'Microsoft Visual C++ runtime is installed.'
    }
    else {
        throw 'Microsoft Visual C++ runtime installation could not be verified.'
    }
}

function Install-OhMyPoshPortable {
    Write-Verbose 'Installing Oh My Posh via portable release...'

    $archToken = switch ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { 'arm64' }
        default { 'amd64' }
    }

    $assetName = "posh-windows-$archToken.exe"
    Initialize-Directory -Path $CODEX_DOWNLOAD_ROOT
    $downloadPath = $null
    $cacheKeyBase = $null
    $cacheKey = $null
    $hashCacheKey = $null
    $checksumsCacheKey = $null

    $attempt = 0
    $maxAttempts = 2
    while ($attempt -lt $maxAttempts) {
        $release = Get-GitHubLatestRelease -Owner 'JanDeDobbeleer' -Repo 'oh-my-posh'
        $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
        if (-not $asset) {
            throw "Suitable Oh My Posh release asset '$assetName' not found."
        }

        $downloadPath = Join-Path -Path $CODEX_DOWNLOAD_ROOT -ChildPath $asset.name
        $releaseTag = if (-not [string]::IsNullOrWhiteSpace($release.tag_name)) { $release.tag_name } elseif (-not [string]::IsNullOrWhiteSpace($release.name)) { $release.name } else { 'latest' }
        $cacheKeyBase = Join-Path -Path 'oh-my-posh' -ChildPath (Get-CacheSafeSegment $releaseTag)
        $cacheKey = Join-Path -Path $cacheKeyBase -ChildPath (Get-CacheSafeSegment $asset.name)
        $sha256Name = $asset.name + '.sha256'
        $hashCacheKey = Join-Path -Path $cacheKeyBase -ChildPath (Get-CacheSafeSegment $sha256Name)
        $checksumsCacheKey = Join-Path -Path $cacheKeyBase -ChildPath 'checksums.txt'
        $expectedHash = Get-ReleaseAssetExpectedHash -Release $release -Asset $asset -CacheKeyBase $cacheKeyBase -WorkspaceDirectory $CODEX_DOWNLOAD_ROOT

        try {
            Invoke-Download -Uri $asset.browser_download_url -Destination $downloadPath -CacheKey $cacheKey -ExpectedHash $expectedHash
            break
        }
        catch {
            $attempt++
            $message = $_.Exception.Message
            if ($attempt -ge $maxAttempts -or $message -notmatch 'hash mismatch') {
                throw
            }

            Write-Warning 'Hash verification failed for Oh My Posh portable release; purging cache and retrying with fresh metadata.'
            Remove-DownloadCacheEntry -CacheKey $cacheKey
            Remove-DownloadCacheEntry -CacheKey $hashCacheKey
            Remove-DownloadCacheEntry -CacheKey $checksumsCacheKey
            Start-Sleep -Seconds 1
        }
    }

    $installRoot = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Programs\oh-my-posh'
    Initialize-Directory -Path $installRoot

    $exePath = Join-Path -Path $installRoot -ChildPath 'oh-my-posh.exe'
    try {
        Copy-Item -Path $downloadPath -Destination $exePath -Force -ErrorAction Stop
    }
    catch {
        throw ("Unable to install Oh My Posh executable to {0}: {1}" -f $exePath, $_.Exception.Message)
    }

    Set-UserPathEntry -InstallRoot $installRoot

    return [pscustomobject]@{
        InstallRoot    = $installRoot
        ExecutablePath = $exePath
    }
}

function Install-OhMyPosh {
    Write-Host 'Ensuring Oh My Posh is installed...'

    $wingetAttempted = $false
    $wingetSucceeded = $false
    try {
        $wingetAttempted = $true
        Install-WingetPackage -PackageId 'JanDeDobbeleer.OhMyPosh' -DisplayName 'Oh My Posh' -CommandName 'oh-my-posh'
        $wingetSucceeded = $true
    }
    catch {
        Write-Warning ("winget installation of Oh My Posh failed: {0}. Falling back to portable install." -f $_.Exception.Message)
    }

    $ompCommand = Get-Command oh-my-posh -ErrorAction SilentlyContinue
    if (-not $ompCommand) {
        Write-Host 'Installing Oh My Posh via portable release...'
        $portableInstall = $null
        try {
            $portableInstall = Install-OhMyPoshPortable
        }
        catch {
            throw ("Unable to install Oh My Posh via portable release: {0}" -f $_.Exception.Message)
        }

        $ompCommand = Get-Command oh-my-posh -ErrorAction SilentlyContinue
        if (-not $ompCommand -and $portableInstall -and $portableInstall.ExecutablePath) {
            $ompCommand = Get-Command -LiteralPath $portableInstall.ExecutablePath -ErrorAction SilentlyContinue
        }
        if (-not $ompCommand) {
            $fallbackReason = if ($wingetAttempted -or $wingetSucceeded) { 'winget and portable installs were attempted' } else { 'portable install completed but the command is still missing' }
            throw "Oh My Posh installation failed: $fallbackReason."
        }
    }

    $displayLocation = $null
    if ($ompCommand -and $ompCommand.PSObject.Properties['Definition'] -and -not [string]::IsNullOrWhiteSpace($ompCommand.Definition)) {
        $displayLocation = $ompCommand.Definition
    }
    elseif ($ompCommand -and $ompCommand.PSObject.Properties['Path'] -and -not [string]::IsNullOrWhiteSpace($ompCommand.Path)) {
        $displayLocation = $ompCommand.Path
    }
    elseif ($ompCommand -and $ompCommand.PSObject.Properties['Source'] -and -not [string]::IsNullOrWhiteSpace($ompCommand.Source)) {
        $displayLocation = $ompCommand.Source
    }
    else {
        $displayLocation = $ompCommand.Name
    }

    Write-Host ("Oh My Posh available at {0}" -f $displayLocation)
}

function Install-WindowsTerminal {
    Write-Host 'Ensuring Windows Terminal is installed...'

    $osVersion = [Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 18362)) {
        Write-Host "Windows Terminal not supported on OS build $($osVersion.ToString()). Skipping installation."
        return
    }

    $existingCommand = Get-Command wt.exe -ErrorAction SilentlyContinue
    if ($existingCommand) {
        Write-Host ("Windows Terminal already available at {0}" -f $existingCommand.Source)
        return
    }

    try {
        Install-WingetPackage -PackageId 'Microsoft.WindowsTerminal' -DisplayName 'Windows Terminal' -CommandName 'wt'
    }
    catch {
        Write-Warning ("Unable to install Windows Terminal via winget: {0}" -f $_.Exception.Message)
    }

    $updatedCommand = Get-Command wt.exe -ErrorAction SilentlyContinue
    if ($updatedCommand) {
        Write-Host ("Windows Terminal installed at {0}" -f $updatedCommand.Source)
    }
    else {
        Write-Warning 'Windows Terminal is still unavailable. You may need to install it manually from the Microsoft Store.'
    }
}

function Install-Nano {
    Write-Host 'Ensuring GNU nano is installed...'

    try {
        Install-WingetPackage -PackageId 'GNU.Nano' -DisplayName 'GNU nano' -CommandName 'nano'
    }
    catch {
        Write-Warning ("Unable to install GNU nano via winget: {0}" -f $_.Exception.Message)
    }

    $nanoCommand = Get-Command nano.exe -ErrorAction SilentlyContinue
    if (-not $nanoCommand) {
        $nanoCommand = Get-Command nano -ErrorAction SilentlyContinue
    }

    if ($nanoCommand) {
        Write-Host ("GNU nano available at {0}" -f $nanoCommand.Source)
    }
    else {
        Write-Warning 'GNU nano is still unavailable. Install it manually if you need the editor.'
    }
}

function Publish-ModuleToModulePaths {
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSModuleInfo]$ModuleInfo
    )

    $documentsPath = [Environment]::GetFolderPath('MyDocuments')
    if (-not $documentsPath) {
        return
    }

    $moduleName = $ModuleInfo.Name
    $versionString = $ModuleInfo.Version.ToString()
    $sourceVersionPath = $ModuleInfo.ModuleBase

    if (-not (Test-Path -Path $sourceVersionPath)) {
        return
    }

    $targetRoots = @(
        Join-Path -Path $documentsPath -ChildPath 'PowerShell\Modules'
        Join-Path -Path $documentsPath -ChildPath 'WindowsPowerShell\Modules'
    ) | Where-Object { $_ }

    foreach ($root in $targetRoots) {
        Initialize-Directory -Path $root
        $destRoot = Join-Path -Path $root -ChildPath $moduleName
        Initialize-Directory -Path $destRoot
        $destPath = Join-Path -Path $destRoot -ChildPath $versionString

        try {
            $sourceResolved = (Resolve-Path -Path $sourceVersionPath -ErrorAction Stop).ProviderPath
            $destResolved = $null
            if (Test-Path -Path $destPath) {
                $destResolved = (Resolve-Path -Path $destPath -ErrorAction Stop).ProviderPath
            }

            if ($destResolved -and $destResolved -eq $sourceResolved) {
                continue
            }

            if ($destResolved) {
                Remove-Item -Path $destPath -Recurse -Force -ErrorAction Stop
            }

            Copy-Item -Path $sourceVersionPath -Destination $destPath -Recurse -Force
        }
        catch {
            Write-Warning ("Unable to synchronize module {0} {1} to {2}: {3}" -f $moduleName, $versionString, $destPath, $_.Exception.Message)
        }
    }
}

function Set-PSReadLineSupport {
    $targetVersion = [Version]'2.3.4'
    $installed = Get-Module -ListAvailable -Name PSReadLine | Sort-Object Version -Descending | Select-Object -First 1
    if ($installed -and $installed.Version -ge $targetVersion) {
        Publish-ModuleToModulePaths -ModuleInfo $installed
        Write-Host ("PSReadLine {0} already available." -f $installed.Version)
        return
    }

    Write-Host ("Installing PSReadLine >= {0}..." -f $targetVersion)
    try {
        $loadedPsReadLine = Get-Module -Name PSReadLine -ErrorAction SilentlyContinue
        if ($loadedPsReadLine) {
            try {
                Remove-Module -Name PSReadLine -Force -ErrorAction Stop
            }
            catch {
                Write-Verbose ("Unable to unload existing PSReadLine module before upgrade: {0}" -f $_.Exception.Message)
            }
        }

        Install-Module -Name PSReadLine -MinimumVersion $targetVersion.ToString() -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        $updated = Get-Module -ListAvailable -Name PSReadLine | Sort-Object Version -Descending | Select-Object -First 1
        if ($updated -and $updated.Version -ge $targetVersion) {
            try {
                Import-Module -Name PSReadLine -RequiredVersion $updated.Version -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Verbose ("Unable to import PSReadLine {0} into current session: {1}" -f $updated.Version, $_.Exception.Message)
            }
            Publish-ModuleToModulePaths -ModuleInfo $updated
            Write-Host ("PSReadLine {0} installed." -f $updated.Version)
        }
        else {
            Write-Warning "PSReadLine installation completed, but the expected version could not be verified."
        }
    }
    catch {
        Write-Warning ("Unable to install PSReadLine module: {0}" -f $_.Exception.Message)
    }
}

# ==================== TOOL INSTALLATION ====================
function Install-RipgrepPortable {
    Write-Warning 'winget did not provide a ripgrep installer - falling back to the portable release.'
    $arch = Get-CpuArchitecture
    $pattern = switch ($arch) {
        'aarch64' { '^ripgrep-.*-aarch64-pc-windows-msvc\.zip$' }
        default { '^ripgrep-.*-x86_64-pc-windows-msvc\.zip$' }
    }

    $archivePath = $null
    $cacheKeyBase = $null
    $cacheKey = $null
    $hashCacheKey = $null
    $checksumsCacheKey = $null

    $attempt = 0
    $maxAttempts = 2
    while ($attempt -lt $maxAttempts) {
        $release = Get-GitHubLatestRelease -Owner 'BurntSushi' -Repo 'ripgrep'
        $asset = $release.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if (-not $asset) {
            throw 'Suitable ripgrep asset not found.'
        }

        $archivePath = Join-Path -Path $CODEX_DOWNLOAD_ROOT -ChildPath $asset.name
        $releaseTag = if (-not [string]::IsNullOrWhiteSpace($release.tag_name)) { $release.tag_name } elseif (-not [string]::IsNullOrWhiteSpace($release.name)) { $release.name } else { 'latest' }
        $cacheKeyBase = Join-Path -Path 'ripgrep' -ChildPath (Get-CacheSafeSegment $releaseTag)
        $cacheKey = Join-Path -Path $cacheKeyBase -ChildPath (Get-CacheSafeSegment $asset.name)
        $sha256Name = $asset.name + '.sha256'
        $hashCacheKey = Join-Path -Path $cacheKeyBase -ChildPath (Get-CacheSafeSegment $sha256Name)
        $checksumsCacheKey = Join-Path -Path $cacheKeyBase -ChildPath 'checksums.txt'
        $expectedHash = Get-ReleaseAssetExpectedHash -Release $release -Asset $asset -CacheKeyBase $cacheKeyBase -WorkspaceDirectory $CODEX_DOWNLOAD_ROOT

        try {
            Invoke-Download -Uri $asset.browser_download_url -Destination $archivePath -CacheKey $cacheKey -ExpectedHash $expectedHash
            break
        }
        catch {
            $attempt++
            $message = $_.Exception.Message
            if ($attempt -ge $maxAttempts -or $message -notmatch 'hash mismatch') {
                throw
            }

            Write-Warning 'Hash verification failed for ripgrep portable release; purging cache and retrying with fresh metadata.'
            Remove-DownloadCacheEntry -CacheKey $cacheKey
            Remove-DownloadCacheEntry -CacheKey $hashCacheKey
            Remove-DownloadCacheEntry -CacheKey $checksumsCacheKey
            Start-Sleep -Seconds 1
        }
    }

    $extractRoot = Join-Path -Path $CODEX_DOWNLOAD_ROOT -ChildPath 'ripgrep'
    if (Test-Path -Path $extractRoot) {
        Remove-Item -Path $extractRoot -Recurse -Force
    }
    Expand-Archive -Path $archivePath -DestinationPath $extractRoot -Force

    $executable = Get-ChildItem -Path $extractRoot -Filter 'rg.exe' -Recurse | Select-Object -First 1
    if (-not $executable) {
        throw 'rg.exe not found inside the extracted archive.'
    }

    $installRoot = Join-Path -Path ${env:ProgramFiles} -ChildPath 'ripgrep'
    Initialize-Directory -Path $installRoot
    Copy-Item -Path (Join-Path -Path $executable.Directory.FullName -ChildPath '*') -Destination $installRoot -Recurse -Force

    Set-UserPathEntry -InstallRoot $installRoot
    $rgPath = Join-Path -Path $installRoot -ChildPath 'rg.exe'
    if (-not (Test-Path -Path $rgPath)) {
        Copy-Item -Path $executable.FullName -Destination $rgPath -Force
    }

    $command = Get-Command rg -ErrorAction SilentlyContinue
    if ($command) {
        Write-Host 'ripgrep available via PATH.'
    }
    else {
        Write-Warning ("ripgrep installed at {0}, but the current session may need to be restarted before 'rg' is available on PATH." -f ($installRoot -replace '\\', '/'))
    }

    return [pscustomobject]@{
        InstallRoot      = $installRoot
        ExecutablePath   = $rgPath
        CommandAvailable = [bool]$command
    }
}

function Install-CodexBinary {
    Write-Host 'Fetching latest Codex release from GitHub...'
    $release = Get-GitHubLatestRelease -Owner 'openai' -Repo 'codex'
    $version = if (![string]::IsNullOrWhiteSpace($release.name)) { $release.name } else { $release.tag_name }

    $arch = Get-CpuArchitecture
    $pattern = "codex-$arch-pc-windows-msvc*.zip"
    $asset = $release.assets | Where-Object { $_.name -like $pattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No Windows asset matches $pattern."
    }

    $installRoot = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Programs\Codex'
    Initialize-Directory -Path $installRoot
    $exePath = Join-Path -Path $installRoot -ChildPath 'codex.exe'
    $versionFile = Join-Path -Path $installRoot -ChildPath 'codex-version.txt'

    $existingVersion = $null
    if (Test-Path -Path $versionFile) {
        $existingVersion = (Get-Content -Path $versionFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    }

    if ((Test-Path -Path $exePath) -and $existingVersion -eq $version) {
        Write-Host "Codex $version already installed - skipping download."
        return @{ Version = $version; InstallRoot = $installRoot; Installed = $false }
    }

    Write-Host "Downloading Codex $version..."
    $archivePath = Join-Path -Path $CODEX_DOWNLOAD_ROOT -ChildPath $asset.name
    $cacheKeyBase = Join-Path -Path 'codex' -ChildPath (Get-CacheSafeSegment $version)
    $cacheKey = Join-Path -Path $cacheKeyBase -ChildPath (Get-CacheSafeSegment $asset.name)
    $expectedHash = Get-ReleaseAssetExpectedHash -Release $release -Asset $asset -CacheKeyBase $cacheKeyBase -WorkspaceDirectory $CODEX_DOWNLOAD_ROOT
    Invoke-Download -Uri $asset.browser_download_url -Destination $archivePath -CacheKey $cacheKey -ExpectedHash $expectedHash

    $extractRoot = Join-Path -Path $CODEX_DOWNLOAD_ROOT -ChildPath 'extracted'
    if (Test-Path -Path $extractRoot) {
        Remove-Item -Path $extractRoot -Recurse -Force
    }
    Expand-Archive -Path $archivePath -DestinationPath $extractRoot -Force

    $downloadedExe = Get-ChildItem -Path $extractRoot -Filter '*.exe' -Recurse | Select-Object -First 1
    if (-not $downloadedExe) {
        throw 'Codex executable not found in the downloaded archive.'
    }

    Copy-Item -Path $downloadedExe.FullName -Destination $exePath -Force
    Set-Content -Path $versionFile -Value $version -Encoding Ascii
    Write-Host "Codex $version installed to $exePath."

    return @{ Version = $version; InstallRoot = $installRoot; Installed = $true }
}

# ==================== CONFIGURATION ====================
function Update-CodexConfig {
    $configDir = Join-Path -Path $env:USERPROFILE -ChildPath '.codex'
    $configPath = Join-Path -Path $configDir -ChildPath 'config.toml'
    Initialize-Directory -Path $configDir

    $existingContent = ''
    if (Test-Path -Path $configPath) {
        $existingContent = Get-Content -Path $configPath -Raw -ErrorAction SilentlyContinue
    }

    if (-not $existingContent) {
        $existingContent = ''
    }

    $markerName = 'codex-installer managed settings'
    $markerStart = "# >>> $markerName >>>"
    $markerEnd = "# <<< $markerName <<<"

    $preservedPrefix = ''

    if ($existingContent) {
        $blockPattern = "(?ms)^\s*" + [regex]::Escape($markerStart) + ".*?" + [regex]::Escape($markerEnd) + "\s*"
        $existingContent = [regex]::Replace($existingContent, $blockPattern, '')

        $firstSectionMatch = [regex]::Match($existingContent, "(?m)^\s*\[")
        if ($firstSectionMatch.Success) {
            $preservedPrefix = $existingContent.Substring(0, $firstSectionMatch.Index)
            $existingContent = $existingContent.Substring($firstSectionMatch.Index)
        }
        else {
            $preservedPrefix = $existingContent
            $existingContent = ''
        }

        $managedSections = @(
            'features',
            'profiles.fast',
            'profiles.fast.features',
            'profiles.deep',
            'profiles.deep.features',
            'profiles.deep-experimental',
            'profiles.deep-experimental.features'
        )
        foreach ($section in $managedSections) {
            $escaped = [regex]::Escape($section)
            $sectionPattern = "(?ms)^\s*\[$escaped\]\s*\r?\n.*?(?=^\s*\[|\z)"
            $existingContent = [regex]::Replace($existingContent, $sectionPattern, '')
        }

        $toolsSectionPattern = "(?ms)(^\s*\[tools\]\s*\r?\n)(.*?)(?=^\s*\[|\z)"
        $existingContent = [regex]::Replace(
            $existingContent,
            $toolsSectionPattern,
            {
                param($match)
                $body = $match.Groups[2].Value
                $stripped = [regex]::Replace($body, "(?m)^\s*web_search\s*=\s*.*(\r?\n)?", '')
                if ($stripped.Trim()) {
                    return $match.Groups[1].Value + $stripped
                }
                else {
                    return ''
                }
            }
        )

        $existingContent = $existingContent.Trim()

        if ($preservedPrefix) {
            $prefixContent = $preservedPrefix.Trim()
            if ($prefixContent) {
                if ($existingContent) {
                    $existingContent = $prefixContent + "`r`n`r`n" + $existingContent
                }
                else {
                    $existingContent = $prefixContent
                }
            }
        }
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
unified_exec = false                       # disabled on Windows: triggers DLL errors
streamable_shell = true
apply_patch_freeform = true
experimental_sandbox_command_assessment = false # default: false in 0.57 (temporarily disabled; see deep-experimental profile)
ghost_commit = true
# view_image_tool default is true; left unset to keep default

# --- Profiles --------------------------------------------------------------
[profiles.fast]
# Minimal, speedy: web search + RMCP + ghost commits, dangerous sandbox
approval_policy = "never"                 # keep non-interactive
sandbox_mode = "danger-full-access"       # allow filesystem/network freely
skip_git_repo_check = true                 # skip repo root checks

[profiles.fast.features]
web_search_request = true                  # enable web.run requests
rmcp_client = true                         # enable HTTP MCP clients
ghost_commit = true                        # default: false in 0.57 (override -> true)
# Explicitly disable heavy features for speed (defaults are already false)
unified_exec = false                       # default: false in 0.57
streamable_shell = false                   # default: false in 0.57
apply_patch_freeform = false               # default: false in 0.57
experimental_sandbox_command_assessment = false  # default: false in 0.57
# view_image_tool default is true; left unset

[profiles.deep]
# Mirrors current feature-rich setup (this session)
approval_policy = "never"
sandbox_mode = "danger-full-access"
skip_git_repo_check = true
model_reasoning_effort = "high"
model = "gpt-5-codex"

[profiles.deep.features]
web_search_request = true
rmcp_client = true
unified_exec = false                       # disabled on Windows: triggers DLL errors
streamable_shell = true                    # default: false in 0.57 (override)
apply_patch_freeform = true                # default: false in 0.57 (override)
experimental_sandbox_command_assessment = false  # default: false in 0.57 (temporarily disabled; use deep-experimental)
ghost_commit = true                        # default: false in 0.57 (override)
# view_image_tool default is true; left unset

[profiles.deep-experimental]
# Same as deep but re-enables experimental sandbox risk assessments
approval_policy = "never"
sandbox_mode = "danger-full-access"
skip_git_repo_check = true
model_reasoning_effort = "medium"

[profiles.deep-experimental.features]
web_search_request = true
rmcp_client = true
unified_exec = false                       # disabled on Windows: triggers DLL errors
streamable_shell = true
apply_patch_freeform = true
experimental_sandbox_command_assessment = true   # default: false in 0.57 (override)
ghost_commit = true
# view_image_tool default is true; left unset
'@.Trim()

    $managedBlock = $markerStart + "`r`n" + $managedBody + "`r`n" + $markerEnd + "`r`n"
    if ($existingContent) {
        $managedBlock += "`r`n" + $existingContent + "`r`n"
    }

    Set-Content -Path $configPath -Value $managedBlock -Encoding UTF8
    Write-Host "Codex configuration updated at $configPath."
}

# ==================== PROFILE & FONT MANAGEMENT ====================
function Install-NerdFont {
    $fontFamily = 'IntoneMono NFM'
    $fontRegistryName = "$fontFamily (TrueType)"
    $primaryFontFileName = 'IntoneMonoNerdFontMono-Regular.ttf'
    $fontsDirectory = Join-Path -Path $env:WINDIR -ChildPath 'Fonts'
    $fontsRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'

    $existingFontValue = (Get-ItemProperty -Path $fontsRegistryPath -Name $fontRegistryName -ErrorAction SilentlyContinue).$fontRegistryName
    if ($existingFontValue) {
        if (Test-Path -Path (Join-Path -Path $fontsDirectory -ChildPath $existingFontValue)) {
            Write-Host "$fontFamily already installed."
            return $fontFamily
        }
    }

    $existingFontFile = Get-ChildItem -Path $fontsDirectory -Filter $primaryFontFileName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existingFontFile) {
        Write-Host "$fontFamily already installed."
        if (-not $existingFontValue) {
            New-ItemProperty -Path $fontsRegistryPath -Name $fontRegistryName -Value $existingFontFile.Name -PropertyType String -Force | Out-Null
        }
        return $fontFamily
    }

    Write-Host "Downloading $fontFamily..."
    $release = Get-GitHubLatestRelease -Owner 'ryanoasis' -Repo 'nerd-fonts'
    $asset = $release.assets | Where-Object { $_.name -eq 'IntelOneMono.zip' } | Select-Object -First 1
    if (-not $asset) {
        throw 'Unable to locate IntelOneMono.zip in the Nerd Fonts release assets.'
    }

    Initialize-Directory -Path $FONT_DOWNLOAD_ROOT
    $fontArchive = Join-Path -Path $FONT_DOWNLOAD_ROOT -ChildPath $asset.name
    $releaseTag = if (-not [string]::IsNullOrWhiteSpace($release.tag_name)) { $release.tag_name } elseif (-not [string]::IsNullOrWhiteSpace($release.name)) { $release.name } else { 'latest' }
    $cacheKeyBase = Join-Path -Path 'nerd-fonts' -ChildPath (Get-CacheSafeSegment $releaseTag)
    $cacheKey = Join-Path -Path $cacheKeyBase -ChildPath (Get-CacheSafeSegment $asset.name)
    $expectedHash = Get-ReleaseAssetExpectedHash -Release $release -Asset $asset -CacheKeyBase $cacheKeyBase -WorkspaceDirectory $FONT_DOWNLOAD_ROOT
    try {
        Invoke-Download -Uri $asset.browser_download_url -Destination $fontArchive -CacheKey $cacheKey -ExpectedHash $expectedHash
    }
    catch {
        Write-Warning ("Unable to download {0} via release asset: {1}. Falling back to latest download endpoint." -f $fontFamily, $_.Exception.Message)
        $fallbackUrl = 'https://github.com/ryanoasis/nerd-fonts/releases/latest/download/IntelOneMono.zip'
        Invoke-Download -Uri $fallbackUrl -Destination $fontArchive -CacheKey $cacheKey
    }

    $extractDir = Join-Path -Path $FONT_DOWNLOAD_ROOT -ChildPath 'extracted'
    if (Test-Path -Path $extractDir) {
        Remove-Item -Path $extractDir -Recurse -Force
    }
    Expand-Archive -Path $fontArchive -DestinationPath $extractDir -Force

    $fontFiles = Get-ChildItem -Path $extractDir -Filter '*.ttf' -Recurse
    if (-not $fontFiles) {
        throw 'No font files extracted from IntelOneMono archive.'
    }

    foreach ($fontFile in $fontFiles) {
        Copy-Item -Path $fontFile.FullName -Destination (Join-Path -Path $fontsDirectory -ChildPath $fontFile.Name) -Force
    }

    $primaryFontPath = Get-ChildItem -Path $fontsDirectory -Filter $primaryFontFileName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $primaryFontPath) {
        throw 'Primary IntelOneMono font file not found after installation.'
    }

    if (-not ([System.Management.Automation.PSTypeName]'Win32.FontInterop').Type) {
        Add-Type -Namespace Win32 -Name FontInterop -MemberDefinition @"
    [System.Runtime.InteropServices.DllImport("gdi32.dll", SetLastError = true)]
    public static extern int AddFontResourceEx(string lpszFilename, uint fl, System.IntPtr pdv);

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    public static extern System.IntPtr SendMessage(System.IntPtr hWnd, int Msg, System.IntPtr wParam, System.IntPtr lParam);
"@
    }

    $result = [Win32.FontInterop]::AddFontResourceEx($primaryFontPath.FullName, 0, [IntPtr]::Zero)
    if ($result -eq 0) {
        Write-Warning 'Font registration may have failed. You may need to log off and back on for the font to appear.'
    }
    else {
        [Win32.FontInterop]::SendMessage([IntPtr]0xffff, 0x001D, [IntPtr]0, [IntPtr]0) | Out-Null
    }

    New-ItemProperty -Path $fontsRegistryPath -Name $fontRegistryName -Value $primaryFontFileName -PropertyType String -Force | Out-Null
    Write-Host "$fontFamily installed."
    return $fontFamily
}

function Set-ConsoleDefaults {
    param([Parameter(Mandatory)][string]$FontFamily)

    $trueTypeKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\TrueTypeFont'
    $trueTypeProps = Get-ItemProperty -Path $trueTypeKey -ErrorAction SilentlyContinue
    if (-not $trueTypeProps) {
        throw "Unable to access $trueTypeKey."
    }

    $fontAlreadyListed = $trueTypeProps.PSObject.Properties | Where-Object { $_.Value -eq $FontFamily }
    if (-not $fontAlreadyListed) {
        $existingNumericNames = $trueTypeProps.PSObject.Properties |
        Where-Object { $_.Name -match '^[0-9]+$' } |
        ForEach-Object { [int]$_.Name } |
        Sort-Object
        $nextIndex = if ($existingNumericNames.Count -gt 0) { $existingNumericNames[-1] + 1 } else { 0 }
        $propertyName = "{0:D3}" -f $nextIndex
        New-ItemProperty -Path $trueTypeKey -Name $propertyName -Value $FontFamily -PropertyType String | Out-Null
        Write-Host "Registered $FontFamily as a console TrueType font."
    }
    else {
        Write-Host "$FontFamily already registered as a console TrueType font."
    }

    $consoleKeys = @(
        'HKCU:\Console',
        'HKCU:\Console\%SystemRoot%_system32_cmd.exe',
        'HKCU:\Console\%SystemRoot%_system32_WindowsPowerShell_v1.0_powershell.exe'
    )

    foreach ($keyPath in $consoleKeys) {
        if (-not (Test-Path -Path $keyPath)) {
            New-Item -Path $keyPath -Force | Out-Null
        }
        $existingFaceName = (Get-ItemProperty -Path $keyPath -Name 'FaceName' -ErrorAction SilentlyContinue).FaceName
        if ($existingFaceName -and $existingFaceName -eq $FontFamily) {
            Write-Verbose ("Font already configured for {0}." -f $keyPath)
        }
        else {
            Write-Verbose ("Setting console font for {0}." -f $keyPath)
        }
        New-ItemProperty -Path $keyPath -Name 'FaceName' -Value $FontFamily -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $keyPath -Name 'FontFamily' -Value 54 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $keyPath -Name 'FontWeight' -Value 400 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $keyPath -Name 'FontSize' -Value 0x00100000 -PropertyType DWord -Force | Out-Null
    }

    Write-Host "Set $FontFamily as the default console font for Command Prompt and Windows PowerShell."
}

function Get-PowerShellProfilePath {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return $profile.CurrentUserAllHosts
    }

    $documentsPath = [Environment]::GetFolderPath('MyDocuments')
    $profileDir = Join-Path -Path $documentsPath -ChildPath 'WindowsPowerShell'
    Initialize-Directory -Path $profileDir
    return Join-Path -Path $profileDir -ChildPath 'Microsoft.PowerShell_profile.ps1'
}

function Get-AllPowerShellProfilePaths {
    $paths = @()
    $primary = Get-PowerShellProfilePath
    if ($primary) {
        $paths += $primary
    }

    $documentsPath = [Environment]::GetFolderPath('MyDocuments')
    if ($documentsPath) {
        $legacyProfile = Join-Path -Path $documentsPath -ChildPath 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
        $modernProfile = Join-Path -Path $documentsPath -ChildPath 'PowerShell\Microsoft.PowerShell_profile.ps1'
        $paths += $legacyProfile
        $paths += $modernProfile
    }

    return $paths | Where-Object { $_ } | Select-Object -Unique
}

function Remove-ProfileBlockContent {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$MarkerStart,
        [Parameter(Mandatory)][string]$MarkerEnd,
        [Parameter()][AllowEmptyCollection()][string[]]$ContentLinesForCleanup = @(),
        [Parameter()][string]$LineSeparator = "`r`n"
    )

    $splitLines = if ([string]::IsNullOrEmpty($Content)) { @() } else { $Content -split "`r?\n", -1 }
    $remainingLines = New-Object System.Collections.Generic.List[string]
    $insertIndex = $null

    $lineCount = $splitLines.Length
    $index = 0
    while ($index -lt $lineCount) {
        $currentLine = $splitLines[$index]
        $currentLineValue = if ($null -ne $currentLine) { $currentLine } else { '' }
        $matchesStart = [string]::Equals($currentLineValue.TrimEnd(), $MarkerStart, [System.StringComparison]::Ordinal)
        if ($matchesStart) {
            $endIndex = -1
            for ($j = $index + 1; $j -lt $lineCount; $j++) {
                $candidate = $splitLines[$j]
                $candidateValue = if ($null -ne $candidate) { $candidate } else { '' }
                if ([string]::Equals($candidateValue.TrimEnd(), $MarkerEnd, [System.StringComparison]::Ordinal)) {
                    $endIndex = $j
                    break
                }
            }

            if ($endIndex -lt 0) {
                $remainingLines.Add($currentLine) | Out-Null
                $index++
                continue
            }

            if ($null -eq $insertIndex) {
                $insertIndex = $remainingLines.Count
            }

            $index = $endIndex + 1
            while ($index -lt $lineCount -and [string]::IsNullOrWhiteSpace($splitLines[$index])) {
                $index++
            }
            continue
        }

        $remainingLines.Add($currentLine) | Out-Null
        $index++
    }

    return [pscustomobject]@{
        Lines       = $remainingLines
        InsertIndex = $insertIndex
    }
}

function Set-ProfileBlock {
    param(
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$MarkerName,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$ContentLines
    )

    $profileDir = Split-Path -Path $ProfilePath -Parent
    if ($profileDir) {
        Initialize-Directory -Path $profileDir
    }

    $markerStart = "# >>> $MarkerName >>>"
    $markerEnd = "# <<< $MarkerName <<<"

    $normalizedContentLines = @($ContentLines)
    if ($normalizedContentLines.Count -gt 0 -and -not $normalizedContentLines[-1]) {
        $normalizedContentLines = $normalizedContentLines[0..($normalizedContentLines.Count - 2)]
    }

    $blockLines = @($markerStart) + $normalizedContentLines + @($markerEnd)

    $currentContent = ''
    if (Test-Path -Path $ProfilePath) {
        $currentContent = Get-Content -Path $ProfilePath -Raw -ErrorAction SilentlyContinue
    }

    $lineSeparator = "`r`n"
    if ($currentContent -and $currentContent -notmatch "`r`n" -and $currentContent -match "`n") {
        $lineSeparator = "`n"
    }

    $blockText = $blockLines -join $lineSeparator
    if (-not $blockText.EndsWith($lineSeparator)) {
        $blockText += $lineSeparator
    }

    if (-not $currentContent) {
        Set-Content -Path $ProfilePath -Value $blockText -Encoding utf8
        return
    }

    $removalResult = Remove-ProfileBlockContent -Content $currentContent -MarkerStart $markerStart -MarkerEnd $markerEnd -ContentLinesForCleanup $normalizedContentLines -LineSeparator $lineSeparator
    $sanitizedLines = $removalResult.Lines
    if ($sanitizedLines -isnot [System.Collections.Generic.List[string]]) {
        $converted = New-Object System.Collections.Generic.List[string]
        if ($sanitizedLines) {
            foreach ($line in $sanitizedLines) {
                $converted.Add($line) | Out-Null
            }
        }
        $sanitizedLines = $converted
    }

    $insertIndex = $removalResult.InsertIndex
    if ($null -eq $insertIndex) {
        $insertIndex = $sanitizedLines.Count
        if ($sanitizedLines.Count -gt 0 -and [string]::IsNullOrEmpty($sanitizedLines[$sanitizedLines.Count - 1])) {
            $insertIndex = $sanitizedLines.Count - 1
        }
    }

    foreach ($line in $blockLines) {
        $sanitizedLines.Insert($insertIndex, $line)
        $insertIndex++
    }

    if ($sanitizedLines.Count -eq 0 -or $sanitizedLines[$sanitizedLines.Count - 1] -ne '') {
        $sanitizedLines.Add('')
    }

    $updatedContent = [string]::Join($lineSeparator, $sanitizedLines)
    Set-Content -Path $ProfilePath -Value $updatedContent -Encoding utf8
}

function Set-PowerShellCompletion {
    $markerId = 'codex-installer command completion'
    $profileBlock = @'
$psReadLineTargetVersion = [Version]'2.3.4'
$psReadLineModule = Get-Module -ListAvailable -Name PSReadLine | Where-Object { $_.Version -ge $psReadLineTargetVersion } | Sort-Object Version -Descending | Select-Object -First 1
if ($psReadLineModule) {
    if (-not (Get-Module -Name PSReadLine | Where-Object { $_.Version -ge $psReadLineTargetVersion })) {
        Import-Module $psReadLineModule.Path -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $psReadLineActive = Get-Module -Name PSReadLine | Where-Object { $_.Version -ge $psReadLineTargetVersion } | Sort-Object Version -Descending | Select-Object -First 1
    if ($psReadLineActive) {
        Set-PSReadLineOption -EditMode Windows
        Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
        Set-PSReadLineKeyHandler -Chord 'Shift+Tab' -Function TabCompletePrevious
    }
}
'@
    $blockLines = $profileBlock -split "`r?`n"
    if ($blockLines.Count -gt 0 -and -not $blockLines[-1]) {
        $blockLines = $blockLines[0..($blockLines.Count - 2)]
    }

    foreach ($profilePath in Get-AllPowerShellProfilePaths) {
        if ($blockLines.Count -eq 0) {
            Write-Verbose "Skipping profile block update for $profilePath because no content lines were generated."
            continue
        }
        Set-ProfileBlock -ProfilePath $profilePath -MarkerName $markerId -ContentLines $blockLines
    }

    $psReadLineTargetVersion = [Version]'2.3.4'
    $psReadLineModule = Get-Module -ListAvailable -Name PSReadLine | Where-Object { $_.Version -ge $psReadLineTargetVersion } | Sort-Object Version -Descending | Select-Object -First 1
    if ($psReadLineModule) {
        if (-not (Get-Module -Name PSReadLine | Where-Object { $_.Version -ge $psReadLineTargetVersion })) {
            Import-Module $psReadLineModule.Path -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    $activePsReadLine = Get-Module -Name PSReadLine | Where-Object { $_.Version -ge $psReadLineTargetVersion } | Sort-Object Version -Descending | Select-Object -First 1
    if ($activePsReadLine) {
        try {
            Set-PSReadLineOption -EditMode Windows -ErrorAction SilentlyContinue
            Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete -ErrorAction SilentlyContinue
            Set-PSReadLineKeyHandler -Chord 'Shift+Tab' -Function TabCompletePrevious -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Unable to configure PSReadLine in this session: $($_.Exception.Message)"
        }
    }

    Write-Host 'PowerShell command completion configured for current user profiles.'
}

function Set-OhMyPoshConfiguration {
    $configDir = Join-Path -Path $env:USERPROFILE -ChildPath '.config\oh-my-posh'
    Initialize-Directory -Path $configDir

    $themePath = Join-Path -Path $configDir -ChildPath 'codex.omp.json'
    $themeContent = @'
{
  "$schema": "https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/schema.json",
  "palette": {
    "background": "#1f1f28",
    "primary": "#c8c093",
    "accent": "#7e9cd8",
    "success": "#98bb6c",
    "danger": "#c34043"
  },
  "blocks": [
    {
      "type": "prompt",
      "alignment": "left",
      "segments": [
        {
          "type": "session",
          "style": "powerline",
          "foreground": "#1f1f28",
          "background": "#7e9cd8",
          "powerline_symbol": "\udb83\udc1e"
        },
        {
          "type": "path",
          "style": "powerline",
          "powerline_symbol": "\ue0b0",
          "foreground": "#c8c093",
          "background": "#1f1f28",
          "properties": {
            "style": "short",
            "folder_separator_icon": "\ue0b1"
          }
        },
        {
          "type": "git",
          "style": "powerline",
          "powerline_symbol": "\ue0b0",
          "background": "#1f1f28",
          "foreground": "#98bb6c",
          "properties": {
            "branch_icon": "\ue725",
            "status_colors_enabled": true,
            "display_status": true
          }
        }
      ]
    },
    {
      "type": "prompt",
      "alignment": "right",
      "segments": [
        {
          "type": "time",
          "style": "plain",
          "foreground": "#c8c093",
          "properties": {
            "time_format": "15:04"
          }
        }
      ]
    }
  ],
  "final_space": true
}
'@

    try {
        Set-Content -Path $themePath -Value $themeContent -Encoding utf8
    }
    catch {
        throw ("Unable to write Oh My Posh theme to {0}: {1}" -f $themePath, $_.Exception.Message)
    }

    $markerId = 'codex-installer oh-my-posh initialization'
    $blockLines = @(
        'if (Get-Command oh-my-posh -ErrorAction SilentlyContinue) {'
        ("    oh-my-posh init pwsh --config ""{0}"" | Invoke-Expression" -f $themePath)
        '}'
    )

    foreach ($profilePath in Get-AllPowerShellProfilePaths) {
        Set-ProfileBlock -ProfilePath $profilePath -MarkerName $markerId -ContentLines $blockLines
    }

    Write-Host ("Oh My Posh theme configured at {0}." -f $themePath)
}

function Update-WindowsTerminalSettings {
    param([Parameter(Mandatory)][string]$FontFamily)

    $candidatePaths = @(
        Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json'
        Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows Terminal\settings.json'
    ) | Where-Object { $_ }

    $settingsPath = $candidatePaths | Where-Object { Test-Path -Path $_ } | Select-Object -First 1
    if (-not $settingsPath) {
        Write-Verbose 'Windows Terminal settings file not found. Skipping terminal configuration.'
        return
    }

    $rawContent = Get-Content -Path $settingsPath -Raw -ErrorAction SilentlyContinue
    $needsRewrite = $false
    $settingsObject = $null

    if ($rawContent) {
        try {
            $settingsObject = $rawContent | ConvertFrom-Json -Depth 12
        }
        catch {
            Write-Warning ("Unable to parse existing Windows Terminal settings at {0}: {1}. A new configuration will be generated." -f $settingsPath, $_.Exception.Message)
            $needsRewrite = $true
        }
    }
    else {
        $needsRewrite = $true
    }

    if (-not $settingsObject) {
        $settingsObject = [ordered]@{
            '$schema'      = 'https://aka.ms/terminal-profiles-schema'
            defaultProfile = '{61c54bbd-c2c6-5271-96e7-009a87ff44bf}'
            profiles       = [ordered]@{
                defaults = [ordered]@{
                    font = [ordered]@{
                        face = $FontFamily
                    }
                }
            }
        }
    }
    else {
        if (-not $settingsObject.profiles) {
            $settingsObject.profiles = [ordered]@{}
        }
        if (-not $settingsObject.profiles.defaults) {
            $settingsObject.profiles.defaults = [ordered]@{}
        }
        $settingsObject.profiles.defaults.font = [ordered]@{
            face = $FontFamily
        }
        if (-not $settingsObject.defaultProfile) {
            $settingsObject.defaultProfile = '{61c54bbd-c2c6-5271-96e7-009a87ff44bf}'
        }
    }

    $backupPath = "$settingsPath.codex.bak"
    try {
        Copy-Item -Path $settingsPath -Destination $backupPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose ("Unable to create backup of Windows Terminal settings: {0}" -f $_.Exception.Message)
    }

    try {
        $json = $settingsObject | ConvertTo-Json -Depth 12
        Set-Content -Path $settingsPath -Value $json -Encoding utf8
        if ($needsRewrite) {
            Write-Host ("Windows Terminal settings created at {0}." -f $settingsPath)
        }
        else {
            Write-Host ("Windows Terminal settings updated at {0}." -f $settingsPath)
        }
    }
    catch {
        throw ("Unable to write Windows Terminal settings to {0}: {1}" -f $settingsPath, $_.Exception.Message)
    }
}

# ==================== MAIN EXECUTION ====================
try {
    Test-Prerequisites
    Initialize-Directory -Path $CACHE_DOWNLOAD_ROOT
    Initialize-Directory -Path $DOWNLOAD_ROOT
    Initialize-Directory -Path $CODEX_DOWNLOAD_ROOT
    Initialize-Directory -Path $FONT_DOWNLOAD_ROOT

    Install-WingetIfMissing

    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles')
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $programW6432 = [Environment]::GetEnvironmentVariable('ProgramW6432')

    $gitCandidates = @()
    if ($programFiles) {
        $gitCandidates += Join-Path $programFiles 'Git\cmd'
        $gitCandidates += Join-Path $programFiles 'Git\bin'
        $gitCandidates += Join-Path $programFiles 'Git\usr\bin'
        $gitCandidates += Join-Path $programFiles 'Git\mingw64\bin'
    }
    if ($programW6432) {
        $gitCandidates += Join-Path $programW6432 'Git\cmd'
        $gitCandidates += Join-Path $programW6432 'Git\bin'
    }
    if ($programFilesX86) {
        $gitCandidates += Join-Path $programFilesX86 'Git\cmd'
        $gitCandidates += Join-Path $programFilesX86 'Git\bin'
    }
    $gitCandidates = $gitCandidates | Where-Object { $_ } | Select-Object -Unique

    $ghCandidates = @()
    if ($programFiles) { $ghCandidates += Join-Path $programFiles 'GitHub CLI' }
    if ($programFilesX86) { $ghCandidates += Join-Path $programFilesX86 'GitHub CLI' }
    $ghCandidates = $ghCandidates | Where-Object { $_ } | Select-Object -Unique

    Install-WingetPackage -PackageId 'Git.Git' -DisplayName 'Git' -CommandName 'git' -PathCandidates $gitCandidates
    Install-WingetPackage -PackageId 'GitHub.cli' -DisplayName 'GitHub CLI' -CommandName 'gh' -PathCandidates $ghCandidates

    Ensure-VcRuntime

    Install-OhMyPosh
    Install-WindowsTerminal
    Install-Nano

    $rgFallback = $null
    $rgFallbackUsed = $false
    try {
        Install-WingetPackage -PackageId 'BurntSushi.ripgrep.MSVC' -DisplayName 'ripgrep' -CommandName 'rg'
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match 'exit code -1978335216' -or $message -match 'NoApplicableInstallers' -or $message -match 'No applicable installer') {
            $rgFallback = Install-RipgrepPortable
            $rgFallbackUsed = $true
        }
        else {
            throw
        }
    }

    $rgCommand = Get-Command rg -ErrorAction SilentlyContinue
    if (-not $rgCommand -and -not $rgFallbackUsed) {
        $rgFallback = Install-RipgrepPortable
        $rgCommand = Get-Command rg -ErrorAction SilentlyContinue
    }
    if (-not $rgCommand) {
        $candidatePaths = @()
        if ($rgFallback -and $rgFallback.ExecutablePath) {
            $candidatePaths += $rgFallback.ExecutablePath
        }
        $candidatePaths += Join-Path -Path ${env:ProgramFiles} -ChildPath 'ripgrep\rg.exe'
        $candidatePaths = $candidatePaths | Where-Object { $_ -and (Test-Path -Path $_) } | Select-Object -Unique
        if ($candidatePaths) {
            $display = ($candidatePaths | Select-Object -First 1) -replace '\\', '/'
            Write-Warning "ripgrep installed at $display, but the current session may need to be restarted before 'rg' is available on PATH."
        }
        else {
            throw 'ripgrep installation failed.'
        }
    }

    $codexInstall = Install-CodexBinary
    Set-UserPathEntry -InstallRoot $codexInstall.InstallRoot

    Update-CodexConfig

    if ($EnableFontSetup) {
        $fontFamily = $null
        try {
            $fontFamily = Install-NerdFont
        }
        catch {
            Write-Warning "Font installation failed: $($_.Exception.Message)"
        }
        if ($fontFamily) {
            try {
                Set-ConsoleDefaults -FontFamily $fontFamily
            }
            catch {
                Write-Warning "Unable to apply console defaults: $($_.Exception.Message)"
            }
            $wtCommand = Get-Command wt.exe -ErrorAction SilentlyContinue
            if ($wtCommand) {
                try {
                    Update-WindowsTerminalSettings -FontFamily $fontFamily
                }
                catch {
                    Write-Warning "Unable to update Windows Terminal settings: $($_.Exception.Message)"
                }
            }
            else {
                Write-Verbose 'Windows Terminal command not detected - skipping terminal font configuration.'
            }
        }
    }
    else {
        Write-Verbose 'Font setup skipped via -SkipFontSetup.'
    }

    Set-PSReadLineSupport
    Set-PowerShellCompletion
    try {
        Set-OhMyPoshConfiguration
    }
    catch {
        Write-Warning "Unable to configure Oh My Posh: $($_.Exception.Message)"
    }

    Write-Host "`n=== Codex installation complete! ===`n"
}
catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
    exit 1
}
finally {
    Clear-InstallerDownloads -Paths @(
        $CODEX_DOWNLOAD_ROOT,
        $FONT_DOWNLOAD_ROOT,
        $DOWNLOAD_ROOT
    )
    if ($script:InstallerHttpClient) {
        $script:InstallerHttpClient.Dispose()
        $script:InstallerHttpClient = $null
    }
    if ($script:InstallerHttpClientHandler) {
        $script:InstallerHttpClientHandler.Dispose()
        $script:InstallerHttpClientHandler = $null
    }
}
