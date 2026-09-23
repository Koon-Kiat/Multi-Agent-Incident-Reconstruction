<#
.SYNOPSIS
    Negative tests for the Evidence Verification & Evaluation ground-truth evidence validator.

.DESCRIPTION
    A validator that only ever reports PASS proves nothing. This script copies
    the real ground truth, injects a known fault into the copy, and asserts
    that verify-ground-truth.ps1 detects it and exits non-zero.

    The real ground truth and the real datasets are never modified: every
    mutation is written to a temporary directory and the validator is pointed
    at that directory with -GroundTruthDir.

    This file is public. It therefore contains NO answer-key literals - no
    record IDs, timestamps, hosts, stage IDs, labels or techniques. Every test
    fixture is derived from the private CSVs at runtime, so nothing about the
    answer key is embedded in a committed file. This also means the tests keep
    working if Dataset & Ground Truth Management revises the ground truth.

    Ownership: Evidence Verification & Evaluation.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/test-verify-ground-truth.ps1
#>

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$GroundTruthDir
)

$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
if (-not $GroundTruthDir) { $GroundTruthDir = Join-Path $RepoRoot 'ground_truth\private' }

$validator = Join-Path $PSScriptRoot 'verify-ground-truth.ps1'
$workRoot = Join-Path ([System.IO.Path]::GetTempPath()) "mair-evidence-tests-$PID"

$passed = 0
$failed = 0

function Invoke-Validator {
    # Runs the validator against a mutated copy and returns its output plus
    # exit code. Uses a child powershell process so the validator's own exit
    # code is observable.
    param([string]$Dir)
    $output = & powershell -ExecutionPolicy Bypass -NonInteractive -File $validator `
        -RepoRoot $RepoRoot -GroundTruthDir $Dir 2>&1 | Out-String
    return [pscustomobject]@{ Output = $output; ExitCode = $LASTEXITCODE }
}

function Get-FirstRecordId {
    # First record ID in a semicolon-packed ground-truth field, or $null.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    return ($Value -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 1)
}

function New-Mutation {
    <#
        Copies the real CSVs to a scratch directory, then applies one textual
        substitution to one file. $Find is computed by the caller from the
        CSV's own contents, never hardcoded.
    #>
    param([string]$Name, [string]$File, [string]$Find, [string]$Replace, [switch]$ReplaceAll)

    $dir = Join-Path $workRoot $Name
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item (Join-Path $GroundTruthDir '*_ground_truth.csv') $dir

    $target = Join-Path $dir $File
    $content = Get-Content $target -Raw

    # Guard against a fixture that silently matches more (or less) of the file
    # than intended - a mutation that lands somewhere unexpected would make the
    # test assert the wrong thing. Fields repeated on every row, such as the
    # host, are mutated deliberately with -ReplaceAll.
    $occurrences = ([regex]::Matches($content, [regex]::Escape($Find))).Count
    $expected = if ($ReplaceAll) { 'at least 1' } else { 'exactly 1' }
    if (($ReplaceAll -and $occurrences -lt 1) -or (-not $ReplaceAll -and $occurrences -ne 1)) {
        throw "test setup error: '$Find' occurs $occurrences time(s) in $File - expected $expected"
    }

    ($content -replace [regex]::Escape($Find), $Replace) | Set-Content $target -NoNewline
    return $dir
}

function Assert-Detects {
    param([string]$Name, [string]$Dir, [string]$ExpectedCheck)

    $r = Invoke-Validator -Dir $Dir
    $sawCheck = $r.Output -match [regex]::Escape($ExpectedCheck)
    $nonZero = $r.ExitCode -ne 0

    if ($sawCheck -and $nonZero) {
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
        $script:passed++
    }
    else {
        Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
        if (-not $sawCheck) { Write-Host "          expected check '$ExpectedCheck' was not reported" -ForegroundColor Red }
        if (-not $nonZero) { Write-Host "          validator exited 0 on corrupted input" -ForegroundColor Red }
        $script:failed++
    }
}

Write-Host ''
Write-Host '=== Evidence Verification & Evaluation validator negative tests ===' -ForegroundColor Cyan
Write-Host ''

try {
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null

    # ---- derive every fixture from the CSVs, so no key material is committed ----

    $csvFiles = @(Get-ChildItem (Join-Path $GroundTruthDir '*_ground_truth.csv'))
    if ($csvFiles.Count -eq 0) { throw "no ground-truth CSVs found in $GroundTruthDir" }

    # A row citing exactly one record in total: blanking it leaves the stage
    # with no evidence at all.
    $soleRow = $null; $soleFile = $null; $soleId = $null
    # A row citing a Security record, used for the nonexistent-record test.
    $secRow = $null; $secFile = $null; $secId = $null

    foreach ($f in $csvFiles) {
        foreach ($row in (Import-Csv $f.FullName)) {
            $sec = @($row.security_record_ids -split ';' | Where-Object { $_.Trim() })
            $sys = @($row.sysmon_record_ids -split ';' | Where-Object { $_.Trim() })

            if (-not $secRow -and $sec.Count -ge 1) {
                $secRow = $row; $secFile = $f.Name; $secId = Get-FirstRecordId $row.security_record_ids
            }
            if (-not $soleRow -and ($sec.Count + $sys.Count) -eq 1) {
                $soleRow = $row; $soleFile = $f.Name
                $soleId = if ($sec.Count -eq 1) { Get-FirstRecordId $row.security_record_ids } else { Get-FirstRecordId $row.sysmon_record_ids }
            }
        }
    }
    if (-not $secRow) { throw 'no ground-truth row cites a Security record' }
    if (-not $soleRow) { throw 'no ground-truth row cites exactly one record' }

    $timeRow = (Import-Csv $csvFiles[0].FullName | Where-Object { $_.time_utc } | Select-Object -First 1)
    $hostRow = (Import-Csv $csvFiles[0].FullName | Where-Object { $_.host } | Select-Object -First 1)
    $orderRow = (Import-Csv $csvFiles[0].FullName | Select-Object -First 1)

    # 1. A cited record that does not exist in the telemetry must be caught.
    #    This is the fabricated-evidence case the verifier exists to detect.
    Assert-Detects 'nonexistent record ID is detected' `
    (New-Mutation 'bad-record' $secFile $secId '99999999') `
        'record-resolves'

    # 2. A stage whose declared time no longer matches its anchor record.
    $shifted = ([datetime]::Parse($timeRow.time_utc, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind)).AddMinutes(-7).ToUniversalTime().ToString('o')
    Assert-Detects 'stage/record timestamp drift is detected' `
    (New-Mutation 'bad-time' $csvFiles[0].Name $timeRow.time_utc $shifted) `
        'stage-time'

    # 3. Stages attributed to the wrong host. The host repeats on every row of
    #    a scenario, so this mutation is deliberately applied to all of them.
    Assert-Detects 'host mismatch is detected' `
    (New-Mutation 'bad-host' $csvFiles[0].Name ",$($hostRow.host)," ',WRONG-HOST-01,' -ReplaceAll) `
        'record-host'

    # 4. A stage citing no evidence at all on either channel.
    Assert-Detects 'evidence-free stage is detected' `
    (New-Mutation 'no-evidence' $soleFile ",$soleId," ',,') `
        'stage-has-evidence'

    # 5. Stage ordering that is no longer a contiguous sequence.
    Assert-Detects 'broken stage ordering is detected' `
    (New-Mutation 'bad-order' $csvFiles[0].Name "$($orderRow.stage_id),$($orderRow.stage_order)," "$($orderRow.stage_id),97,") `
        'stage-order-contiguous'

    # 6. The unmodified ground truth must still pass, otherwise the tests above
    #    could be passing for the wrong reason.
    $r = Invoke-Validator -Dir $GroundTruthDir
    if ($r.ExitCode -eq 0 -and $r.Output -match 'RESULT: PASS') {
        Write-Host '  PASS  unmodified ground truth still passes' -ForegroundColor Green
        $passed++
    }
    else {
        Write-Host '  FAIL  unmodified ground truth no longer passes' -ForegroundColor Red
        Write-Host $r.Output
        $failed++
    }
}
finally {
    if (Test-Path $workRoot) { Remove-Item $workRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host ("Passed: {0}   Failed: {1}" -f $passed, $failed)
Write-Host ''

if ($failed -gt 0) {
    Write-Host 'RESULT: validator tests FAILED' -ForegroundColor Red
    exit 1
}
Write-Host 'RESULT: validator tests passed' -ForegroundColor Green
exit 0
