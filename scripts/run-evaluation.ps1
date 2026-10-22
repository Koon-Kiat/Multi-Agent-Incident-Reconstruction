<#
Corrected comparison workflow (protocol Amendment 4). Never downloads model weights.
Use a new output folder; historical results are never overwritten.

  ./scripts/run-evaluation.ps1 -Out out/corrected-01 -AllowDirty
  ./scripts/run-evaluation.ps1 -Out out/corrected-01 -Only review -AllowDirty
  # Independent reviewers complete the generated forms against the private lab key.
  ./scripts/run-evaluation.ps1 -Out out/corrected-01 -Only score -AllowDirty `
      -ClaimReviews out/corrected-01/review/claim_reviews.json `
      -ScoringContract out/corrected-01/review/scoring_contract.json

The default runs prep,B,C,D. Review and score do not start or require Ollama.
-AllowPartial produces explicitly diagnostic output and never a final score.
#>
param(
    [string]$Model = "qwen3:8b",
    [string]$Out = "out/corrected-01",
    [string[]]$Scenario,
    [string]$OllamaExe = "out/tools/ollama/ollama.exe",
    [string]$VerifierTimeout = "180",
    [string]$HardwareNote = "",
    [string]$GroundTruthDir = "ground_truth/private",
    [string]$ClaimReviews,
    [string]$ScoringContract,
    [string[]]$Only = @("prep", "B", "C", "D"),
    [switch]$AllowDirty,
    [switch]$AllowPartial
)
$ErrorActionPreference = "Stop"
$Only = @($Only | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$unknown = @($Only | Where-Object { @("prep", "B", "C", "D", "review", "score") -notcontains $_ })
if ($unknown) { throw "unknown stage(s): $($unknown -join ', ')" }
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$py = Join-Path $repo ".venv/Scripts/python.exe"
$corpus = Join-Path $Out "corpus"
$logs = Join-Path $Out "logs"
if ($Only -contains "prep" -and (Test-Path -LiteralPath "$Out/detections")) { throw "refusing to overwrite $Out/detections" }
foreach ($stage in $Only) {
    $target = switch ($stage) {
        prep { $corpus }; B { "$Out/runs/single-agent" }; C { "$Out/runs/multi-agent" }
        D { "$Out/runs/full" }; review { "$Out/review" }; score { "$Out/evaluation" }
    }
    if (Test-Path -LiteralPath $target) { throw "refusing to overwrite $target; select a new output folder or stage" }
}
New-Item -ItemType Directory -Force -Path $logs | Out-Null
function Step($name, [scriptblock]$body, [int[]]$allowed = @(0)) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] $name" -ForegroundColor Cyan
    & $body
    if ($allowed -notcontains $LASTEXITCODE) { throw "$name failed with exit code $LASTEXITCODE" }
}
$dirty = git status --porcelain -- event_processing authentication_agent endpoint_agent incident_reconstruction evidence_verification pyproject.toml docs/EVALUATION_PROTOCOL.md
if ($LASTEXITCODE -ne 0) { throw "git status failed; cannot check the implementation revision" }
if ($dirty -and -not $AllowDirty) { throw "implementation/protocol differs from the commit; commit it or pass -AllowDirty for a fingerprinted development run" }
$scenarioArgs = @()
foreach ($s in $Scenario) { $scenarioArgs += @("--scenario", $s) }
$common = @("--corpus", $corpus, "--llm", "ollama", "--model", $Model, "--out", "$Out/runs")
$endpoint = "http://127.0.0.1:11434"
function Test-Ollama { try { Invoke-RestMethod "$endpoint/api/version" -TimeoutSec 3 | Out-Null; $true } catch { $false } }
$server = $null
try {
    if (@($Only | Where-Object { @("B", "C", "D") -contains $_ }).Count) {
        if (-not (Test-Ollama)) {
            if (-not (Test-Path -LiteralPath $OllamaExe)) { throw "local Ollama executable not found: $OllamaExe" }
            $env:OLLAMA_HOST = "127.0.0.1:11434"
            $env:OLLAMA_MODELS = Join-Path $repo "out/ollama-models"
            $env:OLLAMA_NO_CLOUD = "1"
            $server = Start-Process -FilePath $OllamaExe -ArgumentList serve -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput "$logs/ollama.out.log" -RedirectStandardError "$logs/ollama.err.log"
            foreach ($i in 1..30) { Start-Sleep 1; if (Test-Ollama) { break } }
            if (-not (Test-Ollama)) { throw "local Ollama did not start" }
        }
        if ((Invoke-RestMethod "$endpoint/api/tags").models.name -notcontains $Model) { throw "model $Model is not installed; no weights were downloaded" }
    }
    if ($Only -contains "prep") {
        Step "Normalise fresh corpus" { & $py -m event_processing normalise --datasets datasets --out $corpus *>&1 | Tee-Object -FilePath "$logs/normalise.log" }
        Step "Rules-only detection baseline" { & $py -m event_processing detect --corpus $corpus --out "$Out/detections" *>&1 | Tee-Object -FilePath "$logs/detect.log" }
    }
    # Only the pipeline's documented exit 1 (written but incomplete) is accepted.
    if ($Only -contains "B") { Step "Single-agent generalist baseline" { & $py -m incident_reconstruction @common @scenarioArgs --mode single-agent *>&1 | Tee-Object -FilePath "$logs/B.log" } @(0,1) }
    if ($Only -contains "C") { Step "Specialist-agent reconstruction" { & $py -m incident_reconstruction @common @scenarioArgs --mode multi-agent *>&1 | Tee-Object -FilePath "$logs/C.log" } @(0,1) }
    if ($Only -contains "D") {
        $env:MAIR_VERIFIER_LLM = "ollama"
        $env:MAIR_VERIFIER_MODEL = $Model
        $env:MAIR_VERIFIER_TIMEOUT = $VerifierTimeout
        Step "Specialist-agent reconstruction with evidence verification" { & $py -m incident_reconstruction @common @scenarioArgs --mode full --verifier evidence_verification.agent:make_agent_verifier *>&1 | Tee-Object -FilePath "$logs/D.log" } @(0,1)
    }
    if ($Only -contains "review") {
        Step "Prepare unanswered independent review forms" { & $py -m evidence_verification.evaluation.prepare_review --corpus $corpus --runs "$Out/runs" --ground-truth $GroundTruthDir --out "$Out/review" *>&1 | Tee-Object -FilePath "$logs/review.log" }
    }
    if ($Only -contains "score") {
        $scoreArgs = @("--corpus",$corpus,"--runs","$Out/runs","--detections","$Out/detections","--ground-truth",$GroundTruthDir,"--out","$Out/evaluation","--hardware-note",$HardwareNote)
        if ($ClaimReviews) { $scoreArgs += @("--claim-reviews",$ClaimReviews) }
        if ($ScoringContract) { $scoreArgs += @("--scoring-contract",$ScoringContract) }
        if ($AllowPartial) { $scoreArgs += "--allow-partial" }
        Step "Evaluate saved runs" { & $py -m evidence_verification.evaluation @scoreArgs *>&1 | Tee-Object -FilePath "$logs/evaluate.log" }
    }
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}
