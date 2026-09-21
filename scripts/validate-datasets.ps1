$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$datasetRoot = Join-Path $repoRoot "datasets"

$scenarios = @("S01", "S02", "S03")

$failed = $false

foreach ($scenario in $scenarios) {

    Write-Host ""
    Write-Host "===== $scenario ====="

    $scenarioRoot = Join-Path $datasetRoot $scenario

    $securityPath = Join-Path $scenarioRoot "raw\Security.evtx"
    $sysmonPath   = Join-Path $scenarioRoot "raw\Sysmon.evtx"
    $manifestPath = Join-Path $scenarioRoot "metadata\manifest.json"
    $metadataPath = Join-Path $scenarioRoot "metadata\scenario_metadata.json"

    $required = @(
        $securityPath,
        $sysmonPath,
        $manifestPath,
        $metadataPath
    )

    foreach ($path in $required) {
        if (Test-Path $path) {
            Write-Host "[PASS] Exists: $path"
        }
        else {
            Write-Host "[FAIL] Missing: $path"
            $failed = $true
        }
    }

    if (-not (Test-Path $manifestPath)) {
        continue
    }

    try {
        $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
        Write-Host "[PASS] Manifest JSON parses"
    }
    catch {
        Write-Host "[FAIL] Manifest JSON invalid"
        $failed = $true
        continue
    }

    try {
        $null = Get-Content $metadataPath -Raw | ConvertFrom-Json
        Write-Host "[PASS] Scenario metadata JSON parses"
    }
    catch {
        Write-Host "[FAIL] Scenario metadata JSON invalid"
        $failed = $true
    }

    foreach ($entry in $manifest.files) {

        $filePath = Join-Path $scenarioRoot ("raw\" + $entry.filename)

        if (-not (Test-Path $filePath)) {
            Write-Host "[FAIL] Manifest file missing: $($entry.filename)"
            $failed = $true
            continue
        }

        $actualHash = (Get-FileHash $filePath -Algorithm SHA256).Hash

        if ($actualHash -eq $entry.sha256) {
            Write-Host "[PASS] SHA256: $($entry.filename)"
        }
        else {
            Write-Host "[FAIL] SHA256 mismatch: $($entry.filename)"
            Write-Host "       Expected: $($entry.sha256)"
            Write-Host "       Actual:   $actualHash"
            $failed = $true
        }
    }

    try {
        $null = Get-WinEvent -Path $securityPath -MaxEvents 1
        Write-Host "[PASS] Security.evtx readable"
    }
    catch {
        Write-Host "[FAIL] Security.evtx could not be read"
        $failed = $true
    }

    try {
        $null = Get-WinEvent -Path $sysmonPath -MaxEvents 1
        Write-Host "[PASS] Sysmon.evtx readable"
    }
    catch {
        Write-Host "[FAIL] Sysmon.evtx could not be read"
        $failed = $true
    }
}

Write-Host ""

if ($failed) {
    Write-Host "DATASET VALIDATION FAILED"
    exit 1
}
else {
    Write-Host "ALL DATASET CHECKS PASSED"
    exit 0
}
