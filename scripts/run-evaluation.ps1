<#
    Runs the four-configuration comparison end to end and scores it, as docs/EVALUATION_PROTOCOL.md specifies.

    Usage:
        powershell -ExecutionPolicy Bypass -File scripts/run-evaluation.ps1
        powershell -ExecutionPolicy Bypass -File scripts/run-evaluation.ps1 -Scenario S02 -Out out/trial

    Requires an installed local Ollama with the model already pulled (this script never downloads anything).
    A project-local server is started when none is serving, using out/tools/ollama/ollama.exe and
    out/ollama-models/, loopback only with cloud disabled. Every step is logged under <Out>/logs.

    A scored run needs the verifier code and protocol to be unmodified since they were committed; the script
    refuses to continue otherwise unless -AllowDirty is given, and the results record the fact either way.

    Ownership: Evidence Verification & Evaluation.
#>

param(
    [string]$Model = "qwen3:8b",
    [string]$Out = "out/scored",
    [string[]]$Scenario,
    [string]$OllamaExe = "out/tools/ollama/ollama.exe",
    [string]$VerifierTimeout = "180",
    [string]$HardwareNote = "",
    [switch]$AllowDirty
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$py = Join-Path $repo ".venv\Scripts\python.exe"
$endpoint = "http://127.0.0.1:11434"
$logs = Join-Path $Out "logs"
New-Item -ItemType Directory -Force -Path $logs | Out-Null

function Step($name, [scriptblock]$body) {
    $stamp = Get-Date -Format "HH:mm:ss"
    Write-Host ""
    Write-Host "[$stamp] $name" -ForegroundColor Cyan
    $started = Get-Date
    & $body
    $code = $LASTEXITCODE
    $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds)
    # Exit 1 from the pipeline means "written but incomplete" (a known, recorded gap), not a failure.
    if ($code -gt 1) { throw "$name failed with exit code $code" }
    Write-Host "[$stamp] $name done in ${elapsed}s (exit $code)"
}

Write-Host "=== MAIR evaluation run ==="

# 1. The scored run must use frozen code.
$dirty = git status --porcelain -- evidence_verification docs/EVALUATION_PROTOCOL.md
if ($dirty) {
    Write-Host "Verifier code or protocol differs from the committed version:" -ForegroundColor Yellow
    $dirty | ForEach-Object { Write-Host "  $_" }
    if (-not $AllowDirty) { throw "refusing a scored run on modified code; commit the change or pass -AllowDirty" }
}

# 2. Local model runtime: use a running server, else start the project-local one.
function Test-Ollama { try { Invoke-RestMethod "$endpoint/api/version" -TimeoutSec 3 | Out-Null; $true } catch { $false } }
$server = $null
if (-not (Test-Ollama)) {
    if (-not (Test-Path $OllamaExe)) { throw "no Ollama serving on $endpoint and $OllamaExe not found" }
    $env:OLLAMA_HOST = "127.0.0.1:11434"
    $env:OLLAMA_MODELS = Join-Path $repo "out/ollama-models"
    $env:OLLAMA_NO_CLOUD = "1"
    $server = Start-Process -FilePath $OllamaExe -ArgumentList "serve" -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logs "ollama.out.log") -RedirectStandardError (Join-Path $logs "ollama.err.log")
    foreach ($i in 1..30) { Start-Sleep 2; if (Test-Ollama) { break } }
    if (-not (Test-Ollama)) { throw "the local Ollama server did not start" }
}
$installed = (Invoke-RestMethod "$endpoint/api/tags").models.name
if ($installed -notcontains $Model) { throw "model $Model is not installed locally; this script never pulls weights" }
Write-Host "Ollama $((Invoke-RestMethod "$endpoint/api/version").version) serving $Model"

$scenarioArgs = @()
foreach ($s in $Scenario) { $scenarioArgs += @("--scenario", $s) }
$common = @("--corpus", "out/corpus", "--llm", "ollama", "--model", $Model, "--out", "$Out/runs")

try {
    Step "Normalise corpus" { & $py -m event_processing normalise --datasets datasets --out out/corpus *>&1 | Tee-Object -FilePath (Join-Path $logs "normalise.log") }
    Step "Configuration A: detect" { & $py -m event_processing detect --corpus out/corpus --out "$Out/detections" *>&1 | Tee-Object -FilePath (Join-Path $logs "detect.log") }
    Step "Configuration B: single-agent" { & $py -m incident_reconstruction @common @scenarioArgs --mode single-agent *>&1 | Tee-Object -FilePath (Join-Path $logs "B.log") }
    Step "Configuration C: multi-agent, no verifier" { & $py -m incident_reconstruction @common @scenarioArgs --mode multi-agent *>&1 | Tee-Object -FilePath (Join-Path $logs "C.log") }
    $env:MAIR_VERIFIER_LLM = "ollama"
    $env:MAIR_VERIFIER_MODEL = $Model
    $env:MAIR_VERIFIER_TIMEOUT = $VerifierTimeout
    Step "Configuration D: full MAIR" { & $py -m incident_reconstruction @common @scenarioArgs --mode full --verifier evidence_verification.agent:make_agent_verifier *>&1 | Tee-Object -FilePath (Join-Path $logs "D.log") }
    Step "Score against the private key" {
        & $py -m evidence_verification.evaluation --corpus out/corpus --runs "$Out/runs" --detections "$Out/detections" --out "$Out/evaluation" --hardware-note $HardwareNote *>&1 | Tee-Object -FilePath (Join-Path $logs "evaluate.log")
    }
    Write-Host ""
    Write-Host "Done. Results: $Out/evaluation/results.md (tables) and results.json (everything)." -ForegroundColor Green
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}
