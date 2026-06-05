#Requires -Version 7.0
<#
.SYNOPSIS
    Scans the Majestic Million domain list and reports which domains use DNSSEC.

.DESCRIPTION
    Reads names from majestic_million.csv and, for each one, determines whether
    that NAME is protected by DNSSEC. A name is protected when the RRset that
    directly answers it (its A/AAAA record, or its CNAME) is signed -- i.e. the
    DNS response contains an RRSIG whose OWNER name equals the queried name.

    This owner-name match is deliberate. It means:
      * Zone apexes (e.g. cloudflare.com) are detected correctly.
      * Sub-domains that are merely records inside a signed parent zone
        (e.g. www.cloudflare.com) are ALSO detected correctly -- something a
        DNSKEY-at-apex check cannot do, because sub-domains have no DNSKEY.
      * A name that is a CNAME to a signed CDN target (e.g. a site whose www
        points at *.cdn.cloudflare.net) is NOT a false positive: the target's
        signature has a different owner name, so it is ignored. Only the
        listed name's own RRset counts.

    The work is spread across many runspaces with ForEach-Object -Parallel.
    Input is processed in batches so that:
      * memory stays bounded (results are flushed to disk per batch),
      * progress can be reported, and
      * the run can be resumed if interrupted (-Resume).

.PARAMETER InputCsv
    Path to the Majestic Million CSV. Defaults to .\majestic_million.csv.

.PARAMETER OutputCsv
    Path to the results CSV. Defaults to .\dnssec_report.csv.

.PARAMETER ThrottleLimit
    Maximum concurrent DNS lookups. DNS is I/O bound, so this can be high.
    Default 200.

.PARAMETER BatchSize
    Number of domains handed to each parallel batch before flushing results.
    Default 5000.

.PARAMETER Server
    DNS server(s) to query. Defaults to 1.1.1.1, 8.8.8.8 and 9.9.9.9. When more
    than one is given, queries are spread across them per-domain (round-robin by
    a stable hash) so that no single public resolver rate-limits the run -- this
    is the main throughput ceiling over a million queries, not CPU or batching.
    A DNSSEC-aware resolver that returns RRSIG records when the DO bit is set is
    REQUIRED for accurate results; all three defaults qualify. Do NOT rely on a
    typical system/ISP resolver -- many strip DNSSEC data, silently making every
    domain look Unsigned. Best of all for a full run: point this at a LOCAL
    validating resolver (e.g. unbound on 127.0.0.1) -- no external rate limit,
    far higher sustained throughput.

.PARAMETER Limit
    Process only the first N domains (handy for testing).

.PARAMETER Resume
    Skip domains already present in an existing OutputCsv and append the rest.

.EXAMPLE
    pwsh -File .\Scan-Dnssec.ps1 -Limit 1000 -Server 1.1.1.1

.EXAMPLE
    pwsh -File .\Scan-Dnssec.ps1 -ThrottleLimit 300 -Server 8.8.8.8
#>
[CmdletBinding()]
param(
    [string]$InputCsv      = (Join-Path $PSScriptRoot 'majestic_million.csv'),
    [string]$OutputCsv     = (Join-Path $PSScriptRoot 'dnssec_report.csv'),
    [int]   $ThrottleLimit = 500,
    [int]   $BatchSize     = 20000,
    [string[]]$Server      = @('1.1.1.1', '8.8.8.8', '9.9.9.9'),
    [int]   $Limit,
    [switch]$Resume
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputCsv)) {
    throw "Input CSV not found: $InputCsv"
}

# Resolve-DnsName is a Windows-only cmdlet (DnsClient module). Bail early with a
# clear message on non-Windows so the failure isn't cryptic inside a runspace.
if (-not $IsWindows) {
    throw "This script relies on Resolve-DnsName, which is only available on Windows."
}

Write-Host "Reading domains from $InputCsv ..." -ForegroundColor Cyan

# Import only the columns we need to keep memory down (~1M rows).
$domains = Import-Csv -LiteralPath $InputCsv |
    Select-Object @{N = 'Rank'; E = { $_.GlobalRank } }, @{N = 'Domain'; E = { $_.Domain } }

if ($Limit -gt 0) {
    $domains = $domains | Select-Object -First $Limit
}

$totalAll = $domains.Count
Write-Host "Loaded $totalAll domains." -ForegroundColor Cyan

if ($Server) {
    Write-Host ("Resolver(s): {0} | ThrottleLimit: {1} | BatchSize: {2}" -f ($Server -join ', '), $ThrottleLimit, $BatchSize) -ForegroundColor Cyan
} else {
    Write-Warning "No -Server set: using the system resolver. Many resolvers STRIP DNSSEC data, which will make every domain look Unsigned. Pass -Server 1.1.1.1 (or another DNSSEC-aware resolver) for accurate results."
}

# --- Resume support: skip domains already in the output file -----------------
if ($Resume -and (Test-Path -LiteralPath $OutputCsv)) {
    Write-Host "Resume: reading already-processed domains from $OutputCsv ..." -ForegroundColor Cyan
    $done = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]((Import-Csv -LiteralPath $OutputCsv).Domain),
        [System.StringComparer]::OrdinalIgnoreCase)
    $domains = $domains | Where-Object { -not $done.Contains($_.Domain) }
    Write-Host "Resume: $($done.Count) already done, $($domains.Count) remaining." -ForegroundColor Cyan
} elseif (Test-Path -LiteralPath $OutputCsv) {
    # Fresh run: start a clean output file.
    Remove-Item -LiteralPath $OutputCsv -Force
}

$total = $domains.Count
if ($total -eq 0) {
    Write-Host "Nothing to do." -ForegroundColor Yellow
    return
}

$swAll      = [System.Diagnostics.Stopwatch]::StartNew()
$processed  = 0
$signedCnt  = 0
$batchIndex = 0

# Pre-slice into batches.
for ($offset = 0; $offset -lt $total; $offset += $BatchSize) {
    $batch = $domains[$offset..([Math]::Min($offset + $BatchSize, $total) - 1)]
    $batchIndex++

    $results = $batch | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $row     = $_
        $domain  = $row.Domain
        $servers = $using:Server
        $qname   = $domain.TrimEnd('.').ToLowerInvariant()

        $common = @{
            Name         = $domain
            DnssecOk     = $true
            ErrorAction  = 'SilentlyContinue'
            QuickTimeout = $true   # bounds each lookup to ~1s on no response
        }
        # Spread load across the configured resolvers (per-domain round-robin via
        # a stable hash) so no single public resolver rate-limits us over a long
        # run. With one resolver this just always picks it.
        if ($servers -and $servers.Count -gt 0) {
            $common.Server = $servers[[Math]::Abs($domain.GetHashCode()) % $servers.Count]
        }

        $status     = 'Unsigned'
        $signedType = ''
        $detail     = ''

        try {
            # The name is protected only if the RRset that directly answers it
            # is signed -- an RRSIG whose OWNER name equals the queried name.
            # Matching the owner name keeps a CNAME to a signed CDN target from
            # registering as a false positive (its RRSIG has a different owner).
            $resolved = $false
            foreach ($qt in 'A', 'AAAA') {
                $records = Resolve-DnsName -Type $qt @common
                if (-not $records) { continue }

                $ownAnswer = @($records | Where-Object {
                        $_.Type -in 'A', 'AAAA', 'CNAME' -and
                        $_.Name.TrimEnd('.').ToLowerInvariant() -eq $qname })
                if ($ownAnswer.Count -gt 0) { $resolved = $true }

                $sigs = @($records | Where-Object {
                        $_.Type -eq 'RRSIG' -and
                        $_.Name.TrimEnd('.').ToLowerInvariant() -eq $qname })
                if ($sigs.Count -gt 0) {
                    $status     = 'Signed'
                    $signedType = (($sigs | ForEach-Object { $_.TypeCovered }) |
                        Select-Object -Unique) -join ','
                    break
                }
                if ($resolved) { break }   # name resolves here but isn't signed
            }

            if ($status -ne 'Signed' -and -not $resolved) {
                $status = 'NoAnswer'
                $detail = 'No A/AAAA/CNAME answer (NXDOMAIN, NODATA, or timeout)'
            }
        } catch {
            $status = 'Error'
            $detail = $_.Exception.Message
        }

        [pscustomobject]@{
            Rank             = $row.Rank
            Domain           = $domain
            DnssecEnabled    = ($status -eq 'Signed')
            Status           = $status
            SignedRecordType = $signedType
            Detail           = $detail
        }
    }

    # Flush this batch to disk immediately (append after the first write).
    $results | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Append

    $processed += $batch.Count
    $signedCnt += @($results | Where-Object DnssecEnabled).Count

    $rate = $processed / [Math]::Max($swAll.Elapsed.TotalSeconds, 0.001)
    $eta  = if ($rate -gt 0) { [TimeSpan]::FromSeconds(($total - $processed) / $rate) } else { [TimeSpan]::Zero }

    Write-Progress -Activity 'Scanning domains for DNSSEC' `
        -Status ("{0}/{1} done | {2} signed | {3:N1} dom/s | ETA {4:hh\:mm\:ss}" -f `
            $processed, $total, $signedCnt, $rate, $eta) `
        -PercentComplete ([int](100 * $processed / $total))

    Write-Host ("Batch {0}: {1}/{2} processed, {3} signed so far ({4:N1} dom/s)" -f `
        $batchIndex, $processed, $total, $signedCnt, $rate) -ForegroundColor DarkGray
}

Write-Progress -Activity 'Scanning domains for DNSSEC' -Completed
$swAll.Stop()

Write-Host ""
Write-Host "Done. $processed domains in $($swAll.Elapsed.ToString('hh\:mm\:ss'))." -ForegroundColor Green
Write-Host ("DNSSEC-enabled: {0} ({1:P2})" -f $signedCnt, ($signedCnt / [Math]::Max($processed,1))) -ForegroundColor Green
Write-Host "Report written to $OutputCsv" -ForegroundColor Green
