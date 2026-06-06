#Requires -Version 7.0
<#
.SYNOPSIS
    Scans the Majestic Million domain list for DNSSEC and (optionally) classifies
    each signed/failed result into Validated / Island-of-security / Bogus.

.DESCRIPTION
    PASS 1  (scan, unchanged behaviour)
    --------------------------------------------------------------------------
    For each name, a DNSSEC-aware resolver (round-robin over 1.1.1.1 / 8.8.8.8 /
    9.9.9.9) is queried for A/AAAA with the DO bit set. A name is counted
    Signed when the response contains an RRSIG whose OWNER name equals the
    queried name (so signed apexes AND signed sub-domain records are caught,
    while a CNAME to a signed CDN target is not a false positive). Results land
    in one of: Signed / Unsigned / NoAnswer.

    The known limitation of Pass 1 is that "Signed" conflates two very different
    states, and one important state is invisible:
      * Validated  - signed AND chained to the root (real protection, AD=1).
      * Island     - signed but the parent holds NO DS, so a validating resolver
                     treats it as *insecure* (AD=0). Cosmetic; no protection.
      * Bogus      - signed, DS present, but the chain FAILS (expired RRSIG,
                     mismatched DS, etc.). A validating resolver returns
                     SERVFAIL, so Pass 1 silently files these under NoAnswer.
                     This is the DNSSEC-induced-outage population and the most
                     interesting number for an availability-risk argument.

    PASS 2  (classification, new -- enabled with -Classify)
    --------------------------------------------------------------------------
    Re-examines only the rows that need it and adds a Classification column.

      Signed rows  -> Validated vs Island.
        Reasoning: Pass 1 used a *validating* resolver, so a Signed result has
        ALREADY excluded Bogus (a broken chain would have SERVFAILed into
        NoAnswer, not returned RRSIGs). What remains is to ask whether a DS
        exists in the parent:
            DS present -> in-chain -> Validated   (resolver would set AD=1)
            DS absent  -> Island of security      (resolver served it AD=0)

      NoAnswer rows -> hunt for Bogus.
        A validation-failure SERVFAIL can only happen when a chain exists, i.e.
        when the parent publishes a DS. So we first prefilter NoAnswer rows by a
        DS lookup (fast, parallel); only NoAnswer-WITH-DS can possibly be Bogus.
        DS-less NoAnswer is just Dead (NXDOMAIN / NODATA / parked / timeout).
        Each candidate is then *confirmed* with delv, which does its own
        validation from the root trust anchor and reports Secure / Insecure /
        Bogus authoritatively. Without delv the candidates are reported as
        SuspectedBogus (unconfirmed).

    Why delv, and a caveat on the fast DS path
    --------------------------------------------------------------------------
    delv (BIND) is the gold standard: it walks the real chain, so it places the
    zone cut correctly, treats islands as insecure, and reports broken chains as
    validation failures -- all the edge cases a literal-name DS query gets wrong.
    The DS-only fast path is correct for *registrable apex* names (the bulk of
    Majestic). For a signed RECORD inside a signed parent zone (a multi-label
    name with no zone cut of its own, e.g. www.example.com), the DS sits at the
    zone apex, not at the queried name -- so the DS-only path would mislabel it.
    Such rows are therefore marked "InSignedZone" rather than guessed at; use
    -UseDelvForSigned for an authoritative verdict on every signed row.

.PARAMETER InputCsv
    Path to the Majestic Million CSV. Defaults to .\majestic_million.csv.

.PARAMETER OutputCsv
    Pass 1 results CSV. Defaults to .\dnssec_report.csv.

.PARAMETER ClassifiedCsv
    Pass 2 enriched results CSV. Defaults to .\dnssec_report_classified.csv.

.PARAMETER Classify
    Run Pass 2 after the scan (or after loading an existing report).

.PARAMETER ClassifyOnly
    Skip the scan; load an existing -OutputCsv and run Pass 2 against it.
    Use this to enrich a report you already have (e.g. your 1M run) without
    re-scanning.

.PARAMETER UseDelvForSigned
    Classify EVERY signed row with delv instead of the fast DS path. Authoritative
    but much slower over a large signed set. Requires delv.

.PARAMETER DelvPath
    Path to the delv executable if it is not on PATH.

.PARAMETER ThrottleLimit
    Max concurrent lookups. Default 500. (DNS is I/O bound.)

.PARAMETER BatchSize
    Domains per parallel batch before flushing. Default 20000.

.PARAMETER Server
    DNSSEC-aware resolver(s). Default 1.1.1.1, 8.8.8.8, 9.9.9.9. Best for a full
    run: a LOCAL validating resolver (e.g. unbound on 127.0.0.1) -- no external
    rate limit, far higher sustained throughput, and it removes the timeout
    contamination that otherwise inflates the NoAnswer bucket.

.PARAMETER Limit
    Process only the first N domains (testing).

.PARAMETER Resume
    Skip names already present in the relevant output file and append the rest.

.EXAMPLE
    # Full scan + classification in one go
    pwsh -File .\Scan-Dnssec.ps1 -Classify

.EXAMPLE
    # You already have dnssec_report.csv from a previous run -- just classify it
    pwsh -File .\Scan-Dnssec.ps1 -ClassifyOnly

.EXAMPLE
    # Authoritative (delv) verdict on every signed row, delv off PATH
    pwsh -File .\Scan-Dnssec.ps1 -ClassifyOnly -UseDelvForSigned -DelvPath 'C:\Program Files\ISC BIND 9\bin\delv.exe'
#>
[CmdletBinding()]
param(
    [string]  $InputCsv         = (Join-Path $PSScriptRoot 'majestic_million.csv'),
    [string]  $OutputCsv        = (Join-Path $PSScriptRoot 'dnssec_report.csv'),
    [string]  $ClassifiedCsv    = (Join-Path $PSScriptRoot 'dnssec_report_classified.csv'),
    [switch]  $Classify,
    [switch]  $ClassifyOnly,
    [switch]  $UseDelvForSigned,
    [string]  $DelvPath,
    [int]     $ThrottleLimit    = 500,
    [int]     $BatchSize        = 20000,
    [string[]]$Server           = @('1.1.1.1', '8.8.8.8', '9.9.9.9'),
    [int]     $Limit,
    [switch]  $Resume
)

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw "This script relies on Resolve-DnsName, which is only available on Windows."
}

# --- Locate delv (optional) --------------------------------------------------
$delvExe = $null
if ($DelvPath) {
    if (Test-Path -LiteralPath $DelvPath) { $delvExe = (Resolve-Path -LiteralPath $DelvPath).Path }
    else { Write-Warning "DelvPath '$DelvPath' not found; falling back to PATH / DS-only." }
}
if (-not $delvExe) {
    $cmd = Get-Command delv -ErrorAction SilentlyContinue
    if ($cmd) { $delvExe = $cmd.Source }
}
if (($Classify -or $ClassifyOnly)) {
    if ($delvExe) {
        Write-Host "delv found: $delvExe (Bogus confirmation enabled)." -ForegroundColor Cyan
    } else {
        Write-Warning "delv not found. Bogus candidates will be reported as 'SuspectedBogus' (unconfirmed). Install BIND tools (e.g. 'choco install bind-toolsonly') or pass -DelvPath for authoritative results."
        if ($UseDelvForSigned) { throw "-UseDelvForSigned requires delv, which was not found." }
    }
}

# ============================================================================
#  PASS 1 -- SCAN  (unchanged logic; skipped entirely when -ClassifyOnly)
# ============================================================================
if (-not $ClassifyOnly) {

    if (-not (Test-Path -LiteralPath $InputCsv)) { throw "Input CSV not found: $InputCsv" }

    Write-Host "Reading domains from $InputCsv ..." -ForegroundColor Cyan
    $domains = Import-Csv -LiteralPath $InputCsv |
        Select-Object @{N = 'Rank'; E = { $_.GlobalRank } }, @{N = 'Domain'; E = { $_.Domain } }
    if ($Limit -gt 0) { $domains = $domains | Select-Object -First $Limit }

    $totalAll = $domains.Count
    Write-Host "Loaded $totalAll domains." -ForegroundColor Cyan
    Write-Host ("Resolver(s): {0} | ThrottleLimit: {1} | BatchSize: {2}" -f ($Server -join ', '), $ThrottleLimit, $BatchSize) -ForegroundColor Cyan

    if ($Resume -and (Test-Path -LiteralPath $OutputCsv)) {
        Write-Host "Resume: reading already-processed domains from $OutputCsv ..." -ForegroundColor Cyan
        $done = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]((Import-Csv -LiteralPath $OutputCsv).Domain),
            [System.StringComparer]::OrdinalIgnoreCase)
        $domains = $domains | Where-Object { -not $done.Contains($_.Domain) }
        Write-Host "Resume: $($done.Count) already done, $($domains.Count) remaining." -ForegroundColor Cyan
    } elseif (Test-Path -LiteralPath $OutputCsv) {
        Remove-Item -LiteralPath $OutputCsv -Force
    }

    $total = $domains.Count
    if ($total -eq 0) { Write-Host "Nothing to scan." -ForegroundColor Yellow }
    else {
        $swAll = [System.Diagnostics.Stopwatch]::StartNew()
        $processed = 0; $signedCnt = 0; $batchIndex = 0

        for ($offset = 0; $offset -lt $total; $offset += $BatchSize) {
            $batch = $domains[$offset..([Math]::Min($offset + $BatchSize, $total) - 1)]
            $batchIndex++

            $results = $batch | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $row = $_; $domain = $row.Domain; $servers = $using:Server
                $qname = $domain.TrimEnd('.').ToLowerInvariant()

                $common = @{ Name = $domain; DnssecOk = $true; ErrorAction = 'SilentlyContinue'; QuickTimeout = $true }
                if ($servers -and $servers.Count -gt 0) {
                    $common.Server = $servers[[Math]::Abs($domain.GetHashCode()) % $servers.Count]
                }

                $status = 'Unsigned'; $signedType = ''; $detail = ''
                try {
                    $resolved = $false
                    foreach ($qt in 'A', 'AAAA') {
                        $records = Resolve-DnsName -Type $qt @common
                        if (-not $records) { continue }
                        $ownAnswer = @($records | Where-Object {
                            $_.Type -in 'A', 'AAAA', 'CNAME' -and $_.Name.TrimEnd('.').ToLowerInvariant() -eq $qname })
                        if ($ownAnswer.Count -gt 0) { $resolved = $true }
                        $sigs = @($records | Where-Object {
                            $_.Type -eq 'RRSIG' -and $_.Name.TrimEnd('.').ToLowerInvariant() -eq $qname })
                        if ($sigs.Count -gt 0) {
                            $status = 'Signed'
                            $signedType = (($sigs | ForEach-Object { $_.TypeCovered }) | Select-Object -Unique) -join ','
                            break
                        }
                        if ($resolved) { break }
                    }
                    if ($status -ne 'Signed' -and -not $resolved) {
                        $status = 'NoAnswer'; $detail = 'No A/AAAA/CNAME answer (NXDOMAIN, NODATA, or timeout)'
                    }
                } catch { $status = 'Error'; $detail = $_.Exception.Message }

                [pscustomobject]@{
                    Rank = $row.Rank; Domain = $domain
                    DnssecEnabled = ($status -eq 'Signed'); Status = $status
                    SignedRecordType = $signedType; Detail = $detail
                }
            }

            $results | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Append
            $processed += $batch.Count
            $signedCnt += @($results | Where-Object DnssecEnabled).Count
            $rate = $processed / [Math]::Max($swAll.Elapsed.TotalSeconds, 0.001)
            Write-Host ("Batch {0}: {1}/{2} processed, {3} signed so far ({4:N1} dom/s)" -f `
                $batchIndex, $processed, $total, $signedCnt, $rate) -ForegroundColor DarkGray
        }
        $swAll.Stop()
        Write-Host ""
        Write-Host "Scan done. $processed domains in $($swAll.Elapsed.ToString('hh\:mm\:ss'))." -ForegroundColor Green
        Write-Host ("DNSSEC-signed (Pass 1): {0} ({1:P2})" -f $signedCnt, ($signedCnt / [Math]::Max($processed,1))) -ForegroundColor Green
        Write-Host "Report written to $OutputCsv" -ForegroundColor Green
    }
}

# ============================================================================
#  PASS 2 -- CLASSIFY  (Validated / Island  and  Bogus hunt)
# ============================================================================
if (-not ($Classify -or $ClassifyOnly)) { return }

if (-not (Test-Path -LiteralPath $OutputCsv)) { throw "Cannot classify: report not found at $OutputCsv" }

Write-Host ""
Write-Host "=== PASS 2: classification ===" -ForegroundColor Cyan
$rows = Import-Csv -LiteralPath $OutputCsv
Write-Host ("Loaded {0} rows from {1}." -f $rows.Count, $OutputCsv) -ForegroundColor Cyan

# Rows that need work; Unsigned passes through untouched.
$signedRows   = @($rows | Where-Object { $_.Status -eq 'Signed' })
$noAnswerRows = @($rows | Where-Object { $_.Status -eq 'NoAnswer' })
$passThrough  = @($rows | Where-Object { $_.Status -notin 'Signed', 'NoAnswer' })
Write-Host ("Signed: {0} | NoAnswer: {1} | Other(pass-through): {2}" -f $signedRows.Count, $noAnswerRows.Count, $passThrough.Count) -ForegroundColor DarkGray

# --- 2a. Signed -> Validated / Island ---------------------------------------
Write-Host "Classifying signed rows (Validated vs Island) ..." -ForegroundColor Cyan
$signedClassified = $signedRows | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $row = $_; $servers = $using:Server; $delv = $using:delvExe; $useDelv = $using:UseDelvForSigned
    $qname = $row.Domain.TrimEnd('.').ToLowerInvariant()
    $labels = $qname.Split('.')

    $class = 'InSignedZone'   # default for multi-label records where the DS path is unreliable
    $dsPresent = ''

    if ($useDelv -and $delv) {
        # Authoritative path: delv validates from the root trust anchor.
        $out = (& $delv "@$($servers[0])" $qname A 2>&1) -join "`n"
        if     ($out -match 'fully validated')                                           { $class = 'Validated' }
        elseif ($out -match 'unsigned answer')                                           { $class = 'Island' }
        elseif ($out -match 'resolution failed|broken trust|no valid|insecurity|validat'){ $class = 'Bogus' }
        else                                                                             { $class = 'Indeterminate' }
    }
    else {
        # Fast path: a DS at the queried name proves an in-chain zone cut.
        # Reliable when the name IS the signed apex; for a signed record inside a
        # signed parent zone (no zone cut here) we leave it 'InSignedZone'.
        $ds = Resolve-DnsName -Name $qname -Type DS -Server $servers[0] -DnssecOk -ErrorAction SilentlyContinue
        $hasDs = @($ds | Where-Object { $_.Type -eq 'DS' -and $_.Name.TrimEnd('.').ToLowerInvariant() -eq $qname }).Count -gt 0
        $dsPresent = $hasDs
        if ($hasDs)            { $class = 'Validated' }
        elseif ($labels.Count -le 2) { $class = 'Island' }   # apex with no DS = genuine island
        # else: multi-label record -> 'InSignedZone' (run -UseDelvForSigned to resolve)
    }

    $row | Select-Object *, @{N='DsPresent';E={$dsPresent}}, @{N='Classification';E={$class}}
}

# --- 2b. NoAnswer -> Bogus hunt ---------------------------------------------
# Prefilter: only NoAnswer rows WITH a parent DS can be Bogus (a validation
# SERVFAIL requires a chain). Everything else is Dead.
Write-Host "Prefiltering NoAnswer rows for DS (Bogus candidates) ..." -ForegroundColor Cyan
$noAnswerScanned = $noAnswerRows | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $row = $_; $servers = $using:Server
    $qname = $row.Domain.TrimEnd('.').ToLowerInvariant()
    $ds = Resolve-DnsName -Name $qname -Type DS -Server $servers[0] -DnssecOk -ErrorAction SilentlyContinue
    $hasDs = @($ds | Where-Object { $_.Type -eq 'DS' -and $_.Name.TrimEnd('.').ToLowerInvariant() -eq $qname }).Count -gt 0
    $row | Select-Object *, @{N='DsPresent';E={$hasDs}}, @{N='Classification';E={ if ($hasDs) {'BogusCandidate'} else {'Dead'} }}
}

$candidates = @($noAnswerScanned | Where-Object Classification -eq 'BogusCandidate')
Write-Host ("Bogus candidates (NoAnswer + DS present): {0}" -f $candidates.Count) -ForegroundColor DarkGray

if ($candidates.Count -gt 0) {
    if ($delvExe) {
        Write-Host "Confirming candidates with delv ..." -ForegroundColor Cyan
        $confirmed = $candidates | ForEach-Object -ThrottleLimit ([Math]::Min($ThrottleLimit,100)) -Parallel {
            $row = $_; $servers = $using:Server; $delv = $using:delvExe
            $qname = $row.Domain.TrimEnd('.').ToLowerInvariant()
            $out = (& $delv "@$($servers[0])" $qname A 2>&1) -join "`n"
            $class =
                if     ($out -match 'fully validated') { 'Validated' }   # recovered since Pass 1
                elseif ($out -match 'unsigned answer') { 'Dead' }        # DS but effectively insecure now
                elseif ($out -match 'resolution failed|broken trust|no valid|insecurity|validat|SERVFAIL') { 'Bogus' }
                else   { 'SuspectedBogus' }
            $row.Classification = $class
            $row
        }
        # Merge confirmed verdicts back over the candidate rows.
        $byDomain = @{}; foreach ($c in $confirmed) { $byDomain[$c.Domain] = $c }
        $noAnswerFinal = $noAnswerScanned | ForEach-Object {
            if ($byDomain.ContainsKey($_.Domain)) { $byDomain[$_.Domain] } else { $_ }
        }
    } else {
        # No delv: leave candidates flagged for follow-up.
        foreach ($c in $candidates) { $c.Classification = 'SuspectedBogus' }
        $noAnswerFinal = $noAnswerScanned
    }
} else {
    $noAnswerFinal = $noAnswerScanned
}

# --- 2c. Pass-through rows get matching columns ------------------------------
$passThroughOut = $passThrough | ForEach-Object {
    $_ | Select-Object *, @{N='DsPresent';E={''}}, @{N='Classification';E={ $_.Status }}
}

# --- 2d. Write enriched report ----------------------------------------------
$all = @($signedClassified) + @($noAnswerFinal) + @($passThroughOut)
$all | Sort-Object { [int]$_.Rank } | Export-Csv -LiteralPath $ClassifiedCsv -NoTypeInformation
Write-Host "Classified report written to $ClassifiedCsv" -ForegroundColor Green

# --- 2e. Summary ------------------------------------------------------------
$tot       = $all.Count
$validated = @($all | Where-Object Classification -eq 'Validated').Count
$island    = @($all | Where-Object Classification -in 'Island','InSignedZone').Count
$bogus     = @($all | Where-Object Classification -in 'Bogus','SuspectedBogus').Count
$dead      = @($all | Where-Object Classification -eq 'Dead').Count
$unsigned  = @($all | Where-Object Classification -eq 'Unsigned').Count
$signedTot = $validated + $island + $bogus
$resolvable = $tot - $dead

Write-Host ""
Write-Host "================ CLASSIFICATION SUMMARY ================" -ForegroundColor Green
Write-Host ("Total rows ............ {0}" -f $tot)
Write-Host ("Validated (protected) . {0} ({1:P2} of all)" -f $validated, ($validated/[Math]::Max($tot,1)))
Write-Host ("Island of security .... {0}" -f $island)
Write-Host ("Bogus / Suspected ..... {0}   <- DNSSEC currently FAILING (availability risk)" -f $bogus)
Write-Host ("Unsigned .............. {0}" -f $unsigned)
Write-Host ("Dead / no address ..... {0}" -f $dead)
if ($signedTot -gt 0) {
    Write-Host ("--> Of zones that attempt DNSSEC ({0}), {1:P2} are broken/bogus." -f `
        $signedTot, ($bogus/[Math]::Max($signedTot,1))) -ForegroundColor Yellow
}
if (-not $delvExe) {
    Write-Host "(delv absent: 'Bogus' figure is SuspectedBogus and unconfirmed.)" -ForegroundColor DarkYellow
}
Write-Host "========================================================" -ForegroundColor Green
