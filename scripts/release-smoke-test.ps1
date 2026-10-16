<#
.SYNOPSIS
Fresh-checkout release check: install, build the corpus, run every mode, write reports.

.DESCRIPTION
Creates a clean copy of the repository in a temporary folder, makes a new virtual environment,
installs the package, normalises the original EVTX exports, runs the single-agent, multi-agent
and full configurations, regenerates the HTML reports and checks every expected file. Nothing
in the source repository is modified.

By default the copy is a git clone of -Source at -Ref (Git LFS objects are pulled). Use
-WorkingTree to test the current uncommitted files instead (tracked and untracked, honouring
.gitignore). Runs use the deterministic fake models unless -Ollama is given.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\release-smoke-test.ps1 -WorkingTree
.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts\release-smoke-test.ps1 -Ref main -Ollama -Model qwen3:8b
#>
param(
    [string]$Source = (Split-Path -Parent $PSScriptRoot),
    [string]$Ref = "HEAD",
    [switch]$WorkingTree,
    [switch]$Ollama,
    [string]$Model = "qwen3:8b",
    [string]$Python = "python",
    [switch]$SkipTests,
    [switch]$Keep
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$work = Join-Path ([System.IO.Path]::GetTempPath()) "mair-smoke-$stamp"
$repo = Join-Path $work "repo"
$failures = New-Object System.Collections.Generic.List[string]

function Step([string]$message) { Write-Host ""; Write-Host "== $message" -ForegroundColor Cyan }

function Invoke-Native([string]$exe, [string[]]$arguments, [int[]]$allowed = @(0)) {
    # Out-Host keeps the command's output on screen; otherwise it would become the function's return value.
    & $exe @arguments | Out-Host
    if ($allowed -notcontains $LASTEXITCODE) {
        throw "'$exe $($arguments -join ' ')' exited with $LASTEXITCODE"
    }
    return $LASTEXITCODE
}

function Expect([bool]$condition, [string]$message) {
    if ($condition) { Write-Host "  ok   $message" } else { Write-Host "  FAIL $message" -ForegroundColor Red; $failures.Add($message) }
}

try {
    New-Item -ItemType Directory -Force -Path $repo | Out-Null

    if ($WorkingTree) {
        Step "Copying the working tree of $Source"
        $files = & git -C $Source ls-files --cached --others --exclude-standard
        if ($LASTEXITCODE -ne 0) { throw "git ls-files failed in $Source" }
        foreach ($relative in $files) {
            $from = Join-Path $Source $relative
            if (-not (Test-Path -LiteralPath $from -PathType Leaf)) { continue }  # Deleted but still tracked.
            $to = Join-Path $repo $relative
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to) | Out-Null
            Copy-Item -LiteralPath $from -Destination $to
        }
        Write-Host "  copied $(@($files).Count) files"
    } else {
        Step "Cloning $Source at $Ref"
        Invoke-Native git @("clone", "--quiet", $Source, $repo) | Out-Null
        Invoke-Native git @("-C", $repo, "checkout", "--quiet", $Ref) | Out-Null
        Invoke-Native git @("-C", $repo, "lfs", "pull") | Out-Null
    }

    Step "Checking original evidence exports"
    foreach ($scenario in @("S01", "S02", "S03")) {
        foreach ($name in @("Security.evtx", "Sysmon.evtx")) {
            $path = Join-Path $repo "datasets\$scenario\raw\$name"
            $isEvtx = (Test-Path $path) -and ((Get-Item $path).Length -gt 4096)
            Expect $isEvtx "$scenario $name is a real EVTX export, not a Git LFS pointer"
        }
    }
    if ($failures.Count) { throw "evidence exports are missing; install Git LFS and run 'git lfs pull'" }

    Step "Creating a fresh virtual environment and installing"
    Invoke-Native $Python @("-m", "venv", (Join-Path $repo ".venv")) | Out-Null
    $py = Join-Path $repo ".venv\Scripts\python.exe"
    Push-Location $repo
    try {
        Invoke-Native $py @("-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-e", ".[test]") | Out-Null

        Step "Normalising the evidence and running the conventional detection baseline"
        Invoke-Native $py @("-m", "event_processing", "normalise", "--datasets", "datasets", "--out", "out\corpus") | Out-Null
        Invoke-Native $py @("-m", "event_processing", "detect", "--corpus", "out\corpus", "--out", "out\detections") | Out-Null
        Expect (Test-Path "out\detections\summary.json") "conventional detection summary written"

        $llm = if ($Ollama) { @("--llm", "ollama", "--model", $Model) } else { @("--llm", "fake") }
        foreach ($mode in @("single-agent", "multi-agent", "full")) {
            Step "Running $mode ($($llm -join ' '))"
            # 1 means written but incomplete (for example an unresolved investigation window).
            $code = Invoke-Native $py (@("-m", "incident_reconstruction", "--corpus", "out\corpus", "--mode", $mode,
                                         "--out", "out\runs") + $llm) @(0, 1)
            Expect ($code -eq 0 -or $code -eq 1) "$mode finished with exit code $code"
            foreach ($scenario in @("S01", "S02", "S03")) {
                $kinds = @("pipeline", "reconstruction")
                if ($mode -ne "single-agent") { $kinds += "orchestration" }
                if ($mode -eq "full") { $kinds += "verification" }
                foreach ($kind in $kinds) {
                    Expect (Test-Path "out\runs\$mode\$scenario.$kind.json") "$mode $scenario.$kind.json"
                }
                Expect (Test-Path "out\runs\$mode\$scenario.report.html") "$mode $scenario.report.html"
            }
        }

        Step "Regenerating reports with the standalone command"
        Invoke-Native $py @("-m", "incident_reconstruction.report", "--corpus", "out\corpus", "--runs", "out\runs") | Out-Null
        $index = Get-Content -Raw -Encoding UTF8 "out\runs\index.html"
        Expect ($index -match "full/S02.report.html") "index links every configuration"

        if (-not $SkipTests) {
            Step "Running the orchestration and reconstruction tests"
            Invoke-Native $py @("-m", "pytest", "-q", "incident_reconstruction\tests", "tests\test_orchestration_corpus.py",
                                "--basetemp", ".test-tmp") | Out-Null
            Expect $true "orchestration and reconstruction tests passed"
        }
    } finally {
        Pop-Location
    }
} catch {
    $failures.Add($_.Exception.Message)
    Write-Host "  FAIL $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Write-Host ""
    if ($failures.Count -eq 0) {
        Write-Host "RELEASE SMOKE TEST PASSED ($repo)" -ForegroundColor Green
    } else {
        Write-Host "RELEASE SMOKE TEST FAILED: $($failures.Count) problem(s)" -ForegroundColor Red
        $failures | ForEach-Object { Write-Host "  - $_" }
    }
    if ($Keep -or $failures.Count) {
        Write-Host "Kept for inspection: $work"
    } else {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
}
if ($failures.Count) { exit 1 } else { exit 0 }
