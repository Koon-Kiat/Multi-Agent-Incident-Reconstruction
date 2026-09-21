<#
.SYNOPSIS
    M6 deterministic ground-truth evidence validator.

.DESCRIPTION
    Independently checks that every Event Record ID cited by M1's private
    ground-truth tables resolves to a real event in the public MAIR telemetry,
    and that the recorded timestamp, host and event type are consistent with
    the corpus.

    This validator makes no judgement about whether a scenario is malicious.
    It only establishes that the answer key is mechanically usable as an
    evaluation key: stage -> Event Record ID -> original EVTX evidence.

    Ownership: M6 (Evidence Verification & Evaluation).
    Input   : M1 private ground-truth package (withheld from M2/M3/M4/M5).
    Output  : console report + optional machine-readable JSON.

.PARAMETER RepoRoot
    Repository root. Defaults to the parent of this script's directory.

.PARAMETER GroundTruthDir
    Directory holding the private ground-truth CSVs. Defaults to
    <RepoRoot>\ground_truth\private (gitignored).

.PARAMETER JsonOut
    Optional path for a machine-readable result file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/verify-ground-truth.ps1
#>

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$GroundTruthDir,
    [string]$JsonOut
)

$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
if (-not $GroundTruthDir) { $GroundTruthDir = Join-Path $RepoRoot 'ground_truth\private' }

# Expected Windows event IDs per telemetry channel. A cited record whose event
# ID falls outside these sets is reported as a warning, not a failure: the key
# may legitimately cite a record type we have not anticipated.
$ExpectedSecurityEventIds = @(4624, 4625, 4688, 4672, 4634, 4647, 4648)
$ExpectedSysmonEventIds = @(1, 11)

# Tolerance between a stage's declared time_utc and the timestamp of its
# anchor (first cited) record.
$TimeToleranceSeconds = 2.0

$findings = New-Object System.Collections.ArrayList
$stageRows = New-Object System.Collections.ArrayList

function Add-Finding {
    param(
        [ValidateSet('FAIL', 'WARN', 'INFO')][string]$Severity,
        [string]$Check,
        [string]$Scenario,
        [string]$Stage,
        [string]$Message
    )
    $null = $findings.Add([pscustomobject]@{
            severity = $Severity
            check    = $Check
            scenario = $Scenario
            stage    = $Stage
            message  = $Message
        })
}

# ---------------------------------------------------------------------------
# EVTX indexing
# ---------------------------------------------------------------------------

function Get-EvtxIndex {
    <#
        Reads an EVTX export once and returns a hashtable keyed by
        EventRecordID. Values carry the fields the validator needs so that no
        check has to re-open the file.
    #>
    param([string]$Path)

    $index = @{}
    $events = Get-WinEvent -Path $Path -Oldest -ErrorAction Stop

    foreach ($e in $events) {
        $data = @{}
        try {
            $xml = [xml]$e.ToXml()
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = $d.'#text' }
            }
        }
        catch {
            # Rendering failed for this record; identity fields below are still
            # valid because they come from the System header, not EventData.
        }

        $index[[int64]$e.RecordId] = [pscustomobject]@{
            RecordId  = [int64]$e.RecordId
            EventId   = $e.Id
            TimeUtc   = $e.TimeCreated.ToUniversalTime()
            Computer  = $e.MachineName
            Provider  = $e.ProviderName
            EventData = $data
        }
    }

    return [pscustomobject]@{
        Index = $index
        Count = $events.Count
        MinId = ($events | Measure-Object RecordId -Minimum).Minimum
        MaxId = ($events | Measure-Object RecordId -Maximum).Maximum
        First = ($events | Select-Object -First 1).TimeCreated.ToUniversalTime()
        Last  = ($events | Select-Object -Last 1).TimeCreated.ToUniversalTime()
    }
}

function Split-RecordIds {
    # Ground-truth CSVs pack multiple record IDs into one field, semicolon
    # separated, e.g. "<id>;<id>". Empty means "no record of this channel
    # supports the stage", which is legitimate.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @($Value -split ';' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' } |
        ForEach-Object { [int64]$_ })
}

# ---------------------------------------------------------------------------
# Check 1 - dataset integrity (hashes must match manifest before anything else)
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '=== MAIR M6 Ground-Truth Evidence Validator ===' -ForegroundColor Cyan
Write-Host ''
Write-Host '[1/7] Dataset integrity' -ForegroundColor Yellow

$scenarios = @('S01', 'S02', 'S03')

foreach ($sid in $scenarios) {
    $manifestPath = Join-Path $RepoRoot "datasets\$sid\metadata\manifest.json"
    if (-not (Test-Path $manifestPath)) {
        Add-Finding FAIL 'manifest-present' $sid '' "manifest.json missing at $manifestPath"
        continue
    }

    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    foreach ($f in $manifest.files) {
        $evtx = Join-Path $RepoRoot "datasets\$sid\raw\$($f.filename)"
        if (-not (Test-Path $evtx)) {
            Add-Finding FAIL 'evtx-present' $sid '' "$($f.filename) missing"
            continue
        }
        $actual = (Get-FileHash $evtx -Algorithm SHA256).Hash
        if ($actual -ne $f.sha256.ToUpper()) {
            Add-Finding FAIL 'evtx-sha256' $sid '' "$($f.filename) hash mismatch: manifest $($f.sha256) actual $actual"
        }
        else {
            Write-Host ("      {0} {1,-14} sha256 OK" -f $sid, $f.filename) -ForegroundColor DarkGray
        }
    }
}

# ---------------------------------------------------------------------------
# Check 2 - ground-truth package present and parseable
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '[2/7] Ground-truth package' -ForegroundColor Yellow

$requiredColumns = @(
    'scenario_id', 'stage_id', 'stage_order', 'time_utc', 'actual_activity',
    'actor', 'host', 'expected_label', 'security_record_ids',
    'sysmon_record_ids', 'mitre_technique', 'notes'
)

$groundTruth = @{}

foreach ($sid in $scenarios) {
    $csvPath = Join-Path $GroundTruthDir "${sid}_ground_truth.csv"
    if (-not (Test-Path $csvPath)) {
        Add-Finding FAIL 'gt-present' $sid '' "ground-truth CSV missing at $csvPath"
        continue
    }

    $rows = @(Import-Csv $csvPath)
    if ($rows.Count -eq 0) {
        Add-Finding FAIL 'gt-nonempty' $sid '' 'ground-truth CSV contains no stage rows'
        continue
    }

    # Column names can carry a UTF-8 BOM on the first header; normalise it so
    # the schema check does not fail on an invisible character.
    $bom = [string][char]0xFEFF
    $columns = @($rows[0].PSObject.Properties.Name | ForEach-Object { $_.TrimStart($bom) })
    $missing = @($requiredColumns | Where-Object { $columns -notcontains $_ })
    if ($missing.Count -gt 0) {
        Add-Finding FAIL 'gt-schema' $sid '' "missing required column(s): $($missing -join ', ')"
    }

    $groundTruth[$sid] = $rows
    Write-Host ("      {0} {1} stage row(s)" -f $sid, $rows.Count) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Check 3 - every cited Event Record ID resolves in the public telemetry
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '[3/7] Stage -> Event Record ID resolution' -ForegroundColor Yellow

$evtxIndexes = @{}

foreach ($sid in $scenarios) {
    if (-not $groundTruth.ContainsKey($sid)) { continue }

    foreach ($channel in @('Security', 'Sysmon')) {
        $path = Join-Path $RepoRoot "datasets\$sid\raw\$channel.evtx"
        if (-not (Test-Path $path)) { continue }
        try {
            $evtxIndexes["$sid/$channel"] = Get-EvtxIndex -Path $path
        }
        catch {
            Add-Finding FAIL 'evtx-parse' $sid '' "$channel.evtx could not be parsed: $($_.Exception.Message)"
        }
    }
}

foreach ($sid in $scenarios) {
    if (-not $groundTruth.ContainsKey($sid)) { continue }

    foreach ($row in $groundTruth[$sid]) {
        $stageId = $row.stage_id
        $gtHost = $row.host

        $citations = @(
            @{ Channel = 'Security'; Ids = (Split-RecordIds $row.security_record_ids); Expected = $ExpectedSecurityEventIds },
            @{ Channel = 'Sysmon'; Ids = (Split-RecordIds $row.sysmon_record_ids); Expected = $ExpectedSysmonEventIds }
        )

        $resolved = 0
        $cited = 0
        $anchorTime = $null

        foreach ($c in $citations) {
            $bundle = $evtxIndexes["$sid/$($c.Channel)"]
            foreach ($rid in $c.Ids) {
                $cited++
                if (-not $bundle) {
                    Add-Finding FAIL 'record-resolves' $sid $stageId "$($c.Channel) record $rid cannot be checked: no parsed index"
                    continue
                }
                if (-not $bundle.Index.ContainsKey($rid)) {
                    Add-Finding FAIL 'record-resolves' $sid $stageId "$($c.Channel) record $rid does not exist in $sid\raw\$($c.Channel).evtx (file holds $($bundle.MinId)-$($bundle.MaxId))"
                    continue
                }

                $ev = $bundle.Index[$rid]
                $resolved++
                if (-not $anchorTime) { $anchorTime = $ev.TimeUtc }

                # Event type sanity
                if ($c.Expected -notcontains $ev.EventId) {
                    Add-Finding WARN 'record-event-type' $sid $stageId "$($c.Channel) record $rid is Event ID $($ev.EventId), outside the expected set for this channel"
                }

                # Host consistency
                if ($gtHost -and $ev.Computer) {
                    $a = $ev.Computer.Split('.')[0]
                    $b = $gtHost.Split('.')[0]
                    if ($a -ne $b) {
                        Add-Finding FAIL 'record-host' $sid $stageId "$($c.Channel) record $rid host '$($ev.Computer)' does not match ground-truth host '$gtHost'"
                    }
                }
            }
        }

        if ($cited -eq 0) {
            Add-Finding FAIL 'stage-has-evidence' $sid $stageId 'stage cites no Event Record IDs on any channel'
        }

        # Declared stage time vs the anchor record's own timestamp
        $timeDelta = $null
        if ($anchorTime -and $row.time_utc) {
            try {
                $declared = [datetime]::Parse($row.time_utc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
                $timeDelta = [math]::Abs(($declared - $anchorTime).TotalSeconds)
                if ($timeDelta -gt $TimeToleranceSeconds) {
                    Add-Finding FAIL 'stage-time' $sid $stageId "declared time_utc $($row.time_utc) differs from anchor record time $($anchorTime.ToString('o')) by $([math]::Round($timeDelta,3))s"
                }
            }
            catch {
                Add-Finding FAIL 'stage-time-format' $sid $stageId "time_utc '$($row.time_utc)' is not a parseable timestamp"
            }
        }

        $null = $stageRows.Add([pscustomobject]@{
                scenario        = $sid
                stage_id        = $stageId
                stage_order     = [int]$row.stage_order
                expected_label  = $row.expected_label
                cited_records   = $cited
                resolved        = $resolved
                anchor_time_utc = if ($anchorTime) { $anchorTime.ToString('o') } else { $null }
                time_delta_s    = if ($null -ne $timeDelta) { [math]::Round($timeDelta, 4) } else { $null }
                activity        = $row.actual_activity
            })

        $status = if ($resolved -eq $cited -and $cited -gt 0) { 'OK  ' } else { 'FAIL' }
        Write-Host ("      [{0}] {1,-9} {2}/{3} record(s) resolved  {4}" -f $status, $stageId, $resolved, $cited, $row.actual_activity) -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# Check 4 - stage ordering is well formed
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '[4/7] Stage ordering' -ForegroundColor Yellow

foreach ($sid in $scenarios) {
    if (-not $groundTruth.ContainsKey($sid)) { continue }

    $rows = @($groundTruth[$sid] | Sort-Object { [int]$_.stage_order })
    $orders = @($rows | ForEach-Object { [int]$_.stage_order })

    $expectedSeq = 1..$rows.Count
    if (($orders -join ',') -ne ($expectedSeq -join ',')) {
        Add-Finding FAIL 'stage-order-contiguous' $sid '' "stage_order is not a contiguous 1..$($rows.Count) sequence: $($orders -join ',')"
    }

    $ids = @($rows | ForEach-Object { $_.stage_id })
    $dupes = @($ids | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    if ($dupes.Count -gt 0) {
        Add-Finding FAIL 'stage-id-unique' $sid '' "duplicate stage_id(s): $($dupes -join ', ')"
    }

    $prev = $null
    foreach ($r in $rows) {
        try { $t = [datetime]::Parse($r.time_utc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
        catch { continue }
        if ($prev -and $t -lt $prev) {
            Add-Finding FAIL 'stage-chronology' $sid $r.stage_id "stage time $($r.time_utc) is earlier than the preceding stage"
        }
        $prev = $t
    }

    # Every stage in a scenario must carry the same expected label, otherwise
    # scenario-level classification scoring is ambiguous.
    $labels = @($rows | ForEach-Object { $_.expected_label.Trim().ToLower() } | Sort-Object -Unique)
    if ($labels.Count -gt 1) {
        Add-Finding WARN 'label-consistency' $sid '' "mixed expected_label values within one scenario: $($labels -join ', ')"
    }

    Write-Host ("      {0} {1} stage(s), label '{2}'" -f $sid, $rows.Count, ($labels -join '/')) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Check 5 - scenario window containment
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '[5/7] Scenario window containment' -ForegroundColor Yellow

foreach ($sid in $scenarios) {
    if (-not $groundTruth.ContainsKey($sid)) { continue }

    $metaPath = Join-Path $RepoRoot "datasets\$sid\metadata\scenario_metadata.json"
    if (-not (Test-Path $metaPath)) { continue }
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json

    $startRaw = if ($meta.scenario_start_utc) { $meta.scenario_start_utc } else { $meta.capture_start_utc }
    $endRaw = if ($meta.scenario_end_utc) { $meta.scenario_end_utc } else { $meta.capture_end_utc }
    if (-not $startRaw -or -not $endRaw) {
        Add-Finding WARN 'scenario-window' $sid '' 'scenario_metadata.json declares no start/end window'
        continue
    }

    $start = [datetime]::Parse($startRaw, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $end = [datetime]::Parse($endRaw, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()

    foreach ($r in $groundTruth[$sid]) {
        try { $t = [datetime]::Parse($r.time_utc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() }
        catch { continue }
        if ($t -lt $start -or $t -gt $end) {
            Add-Finding FAIL 'stage-in-window' $sid $r.stage_id "stage time $($r.time_utc) falls outside the declared scenario window $($start.ToString('o')) .. $($end.ToString('o'))"
        }
    }

    Write-Host ("      {0} window {1} .. {2}" -f $sid, $start.ToString('HH:mm:ss'), $end.ToString('HH:mm:ss')) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Check 6 - Event Record IDs are only unique within a scenario+channel
#
# Both lab scenarios are recorded from the same VMware snapshot, so Windows
# restarts record numbering from the same point. The same EventRecordID
# therefore denotes a DIFFERENT event in S02 and S03. Any evidence_id built
# from the record number alone will silently resolve to the wrong event, which
# is exactly the failure the shared evidence-ID contract is meant to prevent.
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '[6/7] Cross-scenario record-ID uniqueness' -ForegroundColor Yellow

foreach ($channel in @('Security', 'Sysmon')) {
    for ($i = 0; $i -lt $scenarios.Count; $i++) {
        for ($j = $i + 1; $j -lt $scenarios.Count; $j++) {
            $a = $evtxIndexes["$($scenarios[$i])/$channel"]
            $b = $evtxIndexes["$($scenarios[$j])/$channel"]
            if (-not $a -or -not $b) { continue }

            $lo = [math]::Max($a.MinId, $b.MinId)
            $hi = [math]::Min($a.MaxId, $b.MaxId)
            if ($lo -le $hi) {
                $collisions = @($a.Index.Keys | Where-Object { $b.Index.ContainsKey($_) })
                Add-Finding WARN 'record-id-scope' '' '' "$channel record IDs collide between $($scenarios[$i]) and $($scenarios[$j]): $($collisions.Count) shared ID(s) in range $lo..$hi. evidence_id MUST be scoped as scenario+channel+record_id."
                Write-Host ("      {0}: {1} vs {2} - {3} colliding ID(s)" -f $channel, $scenarios[$i], $scenarios[$j], $collisions.Count) -ForegroundColor DarkGray
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Check 7 - answer key is not leaking into the public dataset tree
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '[7/7] Answer-key containment' -ForegroundColor Yellow

# Literal terms that should never appear in agent-visible files. MITRE
# technique IDs are matched by pattern rather than by listing the specific
# techniques used, so that this public script does not itself hint at which
# techniques the answer key contains.
$leakTerms = @('expected_label', 'ground_truth', 'malicious', 'benign', 'mitre_technique')
$leakPatterns = @('\bT1[0-9]{3}(\.[0-9]{3})?\b')

# Neutral phrases that legitimately contain a leak term. These are stripped
# before scanning so that a genuine leak elsewhere in the same file is still
# reported - exempting the whole file would hide it.
$neutralPhrases = @(
    'ground_truth_withheld',
    'ground-truth labels, expected stages, detailed scenario actions and answer keys',
    'ground truth is supplied separately',
    'ground-truth interpretation is withheld separately',
    'ground-truth interpretation, expected labels and attack labels are stored separately',
    'ground-truth activity, attack labels and expected stages are stored separately',
    'ground truth is withheld separately',
    'detailed ground-truth interpretation is intentionally withheld'
)

$publicFiles = @(Get-ChildItem (Join-Path $RepoRoot 'datasets') -Recurse -File -Include *.json, *.md, *.csv -ErrorAction SilentlyContinue)

foreach ($pf in $publicFiles) {
    $text = Get-Content $pf.FullName -Raw
    $scrubbed = $text
    foreach ($phrase in $neutralPhrases) {
        $scrubbed = [regex]::Replace($scrubbed, [regex]::Escape($phrase), '', 'IgnoreCase')
    }
    $rel = $pf.FullName.Replace($RepoRoot, '').TrimStart('\')
    foreach ($term in $leakTerms) {
        if ($scrubbed -match [regex]::Escape($term)) {
            Add-Finding WARN 'answer-key-leak' '' '' "public file $rel contains '$term' outside a neutral withholding statement"
        }
    }
    foreach ($pattern in $leakPatterns) {
        $m = [regex]::Match($scrubbed, $pattern)
        if ($m.Success) {
            Add-Finding WARN 'answer-key-leak' '' '' "public file $rel contains a MITRE technique ID ('$($m.Value)')"
        }
    }
}

$gtInGit = & git -C $RepoRoot ls-files 'ground_truth/private' 2>$null
if ($gtInGit) {
    Add-Finding FAIL 'answer-key-tracked' '' '' "private ground truth is tracked by git: $gtInGit"
}
else {
    Write-Host '      private ground truth is not tracked by git' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$fails = @($findings | Where-Object { $_.severity -eq 'FAIL' })
$warns = @($findings | Where-Object { $_.severity -eq 'WARN' })

$totalCited = ($stageRows | Measure-Object cited_records -Sum).Sum
$totalResolved = ($stageRows | Measure-Object resolved -Sum).Sum

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
Write-Host ("Scenarios          : {0}" -f $groundTruth.Keys.Count)
Write-Host ("Ground-truth stages: {0}" -f $stageRows.Count)
Write-Host ("Record IDs cited   : {0}" -f $totalCited)
Write-Host ("Record IDs resolved: {0}" -f $totalResolved)
Write-Host ("Failures           : {0}" -f $fails.Count)
Write-Host ("Warnings           : {0}" -f $warns.Count)

if ($findings.Count -gt 0) {
    Write-Host ''
    foreach ($f in $findings | Sort-Object { if ($_.severity -eq 'FAIL') { 0 } else { 1 } }) {
        $color = if ($f.severity -eq 'FAIL') { 'Red' } else { 'Yellow' }
        $scope = @($f.scenario, $f.stage) | Where-Object { $_ }
        Write-Host ("[{0}] {1} {2} - {3}" -f $f.severity, $f.check, ($scope -join '/'), $f.message) -ForegroundColor $color
    }
}

if ($JsonOut) {
    $result = [pscustomobject]@{
        generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        repo_root        = $RepoRoot
        scenarios        = @($groundTruth.Keys | Sort-Object)
        stages           = @($stageRows)
        record_ids_cited = $totalCited
        records_resolved = $totalResolved
        failures         = $fails.Count
        warnings         = $warns.Count
        findings         = @($findings)
    }
    $result | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonOut -Encoding utf8
    Write-Host ''
    Write-Host "JSON result written to $JsonOut" -ForegroundColor DarkGray
}

Write-Host ''
if ($fails.Count -gt 0) {
    Write-Host 'RESULT: FAIL - ground truth is not yet mechanically usable as an evaluation key.' -ForegroundColor Red
    exit 1
}
Write-Host 'RESULT: PASS - every cited Event Record ID resolves to real evidence.' -ForegroundColor Green
exit 0
