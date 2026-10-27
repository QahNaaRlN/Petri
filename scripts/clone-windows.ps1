#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Destination = 'D:\PersonalProjects\Petri',
    [string]$Branch = 'feat/linux-native-candidate'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepositoryUrl = 'https://github.com/QahNaaRlN/Petri.git'

function Invoke-CheckedGit {
    param([string[]]$GitArguments)
    # Native stderr can be progress output, so use the exit code as the authority.
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = & git @GitArguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    if ($code -ne 0) {
        throw "git failed ($code): $($lines -join [Environment]::NewLine)"
    }
    return ($lines -join [Environment]::NewLine)
}

function Assert-ExistingCloneState {
    $topLevel = Invoke-CheckedGit -GitArguments @('-C', $Destination, 'rev-parse', '--show-toplevel')
    if ([IO.Path]::GetFullPath($topLevel) -ne $Destination) {
        throw 'Destination must be exactly the root of the existing clone.'
    }
    $origin = Invoke-CheckedGit -GitArguments @('-C', $Destination, 'remote', 'get-url', 'origin')
    $allowedOrigins = @($RepositoryUrl, 'https://github.com/QahNaaRlN/Petri', 'git@github.com:QahNaaRlN/Petri.git')
    if ($origin -notin $allowedOrigins) {
        throw 'Existing origin is not QahNaaRlN/Petri. No files changed.'
    }
    $dirty = Invoke-CheckedGit -GitArguments @('-C', $Destination, 'status', '--porcelain', '--untracked-files=all')
    if ($dirty) {
        throw 'Existing clone has local changes. Commit or stash them before retrying; no reset or deletion was performed.'
    }
    $currentBranch = Invoke-CheckedGit -GitArguments @('-C', $Destination, 'branch', '--show-current')
    if ($currentBranch -ne $Branch) {
        throw "Existing clone is on '$currentBranch', not '$Branch'. Switch explicitly before retrying."
    }
}

Get-Command git -ErrorAction Stop | Out-Null
if ($Branch -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$') {
    throw 'Invalid branch name.'
}
Invoke-CheckedGit -GitArguments @('check-ref-format', '--branch', $Branch) | Out-Null
$Destination = [IO.Path]::GetFullPath($Destination)
if (-not $PSCmdlet.ShouldProcess($Destination, "Clone or fast-forward $RepositoryUrl at $Branch")) {
    return
}

if (Test-Path -LiteralPath $Destination) {
    if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
        throw 'Destination exists and is not a directory. No files changed.'
    }
    Assert-ExistingCloneState
    Invoke-CheckedGit -GitArguments @('-C', $Destination, 'fetch', '--no-tags', 'origin', "refs/heads/${Branch}:refs/remotes/origin/${Branch}") | Write-Output
    # Fetch can take time. Refuse concurrent branch/origin/worktree changes.
    Assert-ExistingCloneState
    Invoke-CheckedGit -GitArguments @('-C', $Destination, 'merge', '--ff-only', "origin/$Branch") | Write-Output
} else {
    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Invoke-CheckedGit -GitArguments @('clone', '--branch', $Branch, '--', $RepositoryUrl, $Destination) | Write-Output
}
Invoke-CheckedGit -GitArguments @('-C', $Destination, 'status', '--short', '--branch') | Write-Output
Write-Output "Clone ready: $Destination"
Write-Output 'To configure GitHub administration, use python scripts/configure_github.py after authenticating gh with the required repository permissions.'
