$projectRoot = (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..')).ProviderPath
$scriptPath = Join-Path -Path $projectRoot -ChildPath 'install-codex.ps1'

$null = Remove-Item -Path Function:Test-VcRuntimeInstalled -ErrorAction SilentlyContinue

$parseErrors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors) {
    throw "Unable to parse install-codex.ps1: $($parseErrors | ForEach-Object { $_.Message } | Sort-Object | Out-String)"
}

$functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-VcRuntimeInstalled' }, $true)
if (-not $functionAst) {
    throw 'Could not locate Test-VcRuntimeInstalled definition in install-codex.ps1.'
}

Invoke-Expression $functionAst.Extent.Text

Describe 'Test-VcRuntimeInstalled' {
    BeforeEach {
        $env:WINDIR = 'C:\\Windows'
        $script:ExistingPaths = @()
        Mock -CommandName Test-Path -MockWith {
            param([string]$Path)
            return $script:ExistingPaths -contains $Path
        }
    }

    AfterEach {
        Remove-Item -Path Env:WINDIR -ErrorAction SilentlyContinue
    }

    It 'returns true when a System32 runtime file exists' {
        $script:ExistingPaths = @(
            'C:\\Windows\\System32\\vcruntime140.dll'
        )

        Test-VcRuntimeInstalled | Should -BeTrue
    }

    It 'returns true when a SysWOW64 runtime file exists' {
        $script:ExistingPaths = @(
            'C:\\Windows\\SysWOW64\\vcruntime140.dll'
        )

        Test-VcRuntimeInstalled | Should -BeTrue
    }

    It 'returns false when no runtime files exist' {
        $script:ExistingPaths = @()

        Test-VcRuntimeInstalled | Should -BeFalse
    }
}
