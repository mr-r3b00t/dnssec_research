#Requires -Version 7.0
<#
.SYNOPSIS
    Scans domains for email-authentication posture: MX, SPF, DMARC and MTA-STS.

.DESCRIPTION
    Companion to Scan-Dnssec.ps1. For each domain it first looks up MX records;
    only domains that actually run mail (have a real MX) are then checked for:

      * SPF     -- a TXT record at the apex beginning "v=spf1".
      * DMARC   -- a TXT record at _dmarc.<domain> beginning "v=DMARC1"
                   (the policy tag p= is also captured: none / quarantine / reject).
      * MTA-STS -- a TXT record at _mta-sts.<domain> beginning "v=STSv1".
                   NOTE: this only proves a policy is ADVERTISED in DNS. The actual
                   policy file lives at https://mta-sts.<domain>/.well-known/mta-sts.txt
                   and is NOT fetched here (an HTTPS GET per domain is a separate job).

    DKIM is intentionally NOT checked: DKIM records live at
    <selector>._domainkey.<domain> and DNS provides no way to enumerate selectors,
    so it can only ever be guessed -- "not found" would never mean "no DKIM".

    Each TXT record is evaluated individually (its 255-char chunks joined), then
    matched by prefix -- so a domain that publishes several TXT records (e.g. SPF
    plus various site-verification strings) is parsed correctly.

    Null MX (RFC 7505: a single "." MX) is treated as "no mail" and skipped.

    Multi-threaded via ForEach-Object -Parallel, processed in batches that flush
    to the output CSV so the run is resumable (-Resume) and memory stays bounded.

.PARAMETER InputCsv
    Majestic Million CSV. Defaults to .\majestic_million.csv.

.PARAMETER OutputCsv
    Results CSV. Defaults to .\mailauth_report.csv.

.PARAMETER ThrottleLimit
    Max concurrent lookups. Default 500.

.PARAMETER BatchSize
    Domains per parallel batch before flushing. Default 20000.

.PARAMETER Server
    DNS server(s). Defaults to 1.1.1.1, 8.8.8.8, 9.9.9.9, spread per-domain
    (round-robin by stable hash) to avoid single-resolver rate-limiting.

.PARAMETER Limit
    Process only the first N domains (testing).

.PARAMETER Resume
    Skip domains already present in OutputCsv and append the rest.

.EXAMPLE
    pwsh -File .\Scan-MailAuth.ps1 -Limit 1000

.EXAMPLE
    pwsh -File .\Scan-MailAuth.ps1 -Resume
#>
[CmdletBinding()]
param(
    [string]$InputCsv      = (Join-Path $PSScriptRoot 'majestic_million.csv'),
    [string]$OutputCsv     = (Join-Path $PSScriptRoot 'mailauth_report.csv'),
    [int]   $ThrottleLimit = 500,
    [int]   $BatchSize     = 20000,
    [string[]]$Server      = @('1.1.1.1', '8.8.8.8', '9.9.9.9'),
    [int]   $Limit,
    [switch]$Resume
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputCsv)) { throw "Input CSV not found: $InputCsv" }
if (-not $IsWindows) { throw "This script relies on Resolve-DnsName, which is only available on Windows." }

Write-Host "Reading domains from $InputCsv ..." -ForegroundColor Cyan
$domains = Import-Csv -LiteralPath $InputCsv |
    Select-Object @{N = 'Rank'; E = { $_.GlobalRank } }, @{N = 'Domain'; E = { $_.Domain } }
if ($Limit -gt 0) { $domains = $domains | Select-Object -First $Limit }

Write-Host "Loaded $($domains.Count) domains." -ForegroundColor Cyan
Write-Host ("Resolver(s): {0} | ThrottleLimit: {1} | BatchSize: {2}" -f ($Server -join ', '), $ThrottleLimit, $BatchSize) -ForegroundColor Cyan

# --- Resume ------------------------------------------------------------------
if ($Resume -and (Test-Path -LiteralPath $OutputCsv)) {
    Write-Host "Resume: reading already-processed domains ..." -ForegroundColor Cyan
    $done = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]((Import-Csv -LiteralPath $OutputCsv).Domain),
        [System.StringComparer]::OrdinalIgnoreCase)
    $domains = $domains | Where-Object { -not $done.Contains($_.Domain) }
    Write-Host "Resume: $($done.Count) done, $($domains.Count) remaining." -ForegroundColor Cyan
} elseif (Test-Path -LiteralPath $OutputCsv) {
    Remove-Item -LiteralPath $OutputCsv -Force
}

$total = $domains.Count
if ($total -eq 0) { Write-Host "Nothing to do." -ForegroundColor Yellow; return }

$swAll = [System.Diagnostics.Stopwatch]::StartNew()
$processed = 0; $mxCnt = 0; $spfCnt = 0; $dmarcCnt = 0; $mtaCnt = 0; $batchIndex = 0

for ($offset = 0; $offset -lt $total; $offset += $BatchSize) {
    $batch = $domains[$offset..([Math]::Min($offset + $BatchSize, $total) - 1)]
    $batchIndex++

    $results = $batch | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $row     = $_
        $domain  = $row.Domain
        $servers = $using:Server

        $common = @{ QuickTimeout = $true; ErrorAction = 'SilentlyContinue' }
        if ($servers -and $servers.Count -gt 0) {
            $common.Server = $servers[[Math]::Abs($domain.GetHashCode()) % $servers.Count]
        }

        $hasMX = $false; $mxCount = 0; $nullMx = $false
        $spf = $false; $spfRec = ''; $dmarc = $false; $dmarcPol = ''
        $mtasts = $false; $mtaId = ''; $detail = ''

        # Local helper: return the first TXT record (chunks joined) matching a prefix.
        function Get-TxtMatch($name, $prefix, $common) {
            foreach ($rec in @(Resolve-DnsName -Type TXT -Name $name @common | Where-Object { $_.Type -eq 'TXT' })) {
                $s = -join $rec.Strings
                if ($s -like "$prefix*") { return $s }
            }
            return $null
        }

        try {
            $mx = @(Resolve-DnsName -Type MX -Name $domain @common | Where-Object { $_.Type -eq 'MX' })
            $mxCount = $mx.Count
            if ($mxCount -gt 0) {
                if ($mxCount -eq 1 -and [string]::IsNullOrEmpty($mx[0].NameExchange.TrimEnd('.'))) {
                    $nullMx = $true                      # RFC 7505 null MX
                } else {
                    $hasMX = $true
                }
            }

            if ($hasMX) {
                $s = Get-TxtMatch $domain 'v=spf1' $common
                if ($s) { $spf = $true; $spfRec = $s }

                $s = Get-TxtMatch "_dmarc.$domain" 'v=DMARC1' $common
                if ($s) {
                    $dmarc = $true
                    if ($s -match '\bp=([A-Za-z]+)') { $dmarcPol = $Matches[1].ToLower() }
                }

                $s = Get-TxtMatch "_mta-sts.$domain" 'v=STSv1' $common
                if ($s) {
                    $mtasts = $true
                    if ($s -match '\bid=([^;\s]+)') { $mtaId = $Matches[1] }
                }
            } elseif ($nullMx) {
                $detail = 'Null MX (RFC 7505: domain accepts no mail)'
            } else {
                $detail = 'No MX'
            }
        } catch {
            $detail = "Error: $($_.Exception.Message)"
        }

        [pscustomobject]@{
            Rank        = $row.Rank
            Domain      = $domain
            HasMX       = $hasMX
            MxCount     = $mxCount
            Spf         = $spf
            Dmarc       = $dmarc
            DmarcPolicy = $dmarcPol
            MtaSts      = $mtasts
            MtaStsId    = $mtaId
            SpfRecord   = $spfRec
            Detail      = $detail
        }
    }

    $results | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Append

    $processed += $batch.Count
    $mxRows     = @($results | Where-Object HasMX)
    $mxCnt     += $mxRows.Count
    $spfCnt    += @($mxRows | Where-Object Spf).Count
    $dmarcCnt  += @($mxRows | Where-Object Dmarc).Count
    $mtaCnt    += @($mxRows | Where-Object MtaSts).Count

    $rate = $processed / [Math]::Max($swAll.Elapsed.TotalSeconds, 0.001)
    $eta  = if ($rate -gt 0) { [TimeSpan]::FromSeconds(($total - $processed) / $rate) } else { [TimeSpan]::Zero }

    Write-Progress -Activity 'Scanning email-auth (MX/SPF/DMARC/MTA-STS)' `
        -Status ("{0}/{1} | {2} MX | SPF {3} DMARC {4} MTA-STS {5} | {6:N1} dom/s | ETA {7:hh\:mm\:ss}" -f `
            $processed, $total, $mxCnt, $spfCnt, $dmarcCnt, $mtaCnt, $rate, $eta) `
        -PercentComplete ([int](100 * $processed / $total))

    Write-Host ("Batch {0}: {1}/{2} | MX {3} | SPF {4} DMARC {5} MTA-STS {6} | {7:N1} dom/s" -f `
        $batchIndex, $processed, $total, $mxCnt, $spfCnt, $dmarcCnt, $mtaCnt, $rate) -ForegroundColor DarkGray
}

Write-Progress -Activity 'Scanning email-auth (MX/SPF/DMARC/MTA-STS)' -Completed
$swAll.Stop()

$pct = { param($n, $d) if ($d) { '{0:P1}' -f ($n / $d) } else { 'n/a' } }
Write-Host ""
Write-Host "Done. $processed domains in $($swAll.Elapsed.ToString('hh\:mm\:ss'))." -ForegroundColor Green
Write-Host ("Domains with MX : {0:N0}" -f $mxCnt) -ForegroundColor Green
Write-Host ("  with SPF      : {0,8:N0}  ({1} of MX domains)" -f $spfCnt,   (& $pct $spfCnt   $mxCnt)) -ForegroundColor Green
Write-Host ("  with DMARC    : {0,8:N0}  ({1} of MX domains)" -f $dmarcCnt, (& $pct $dmarcCnt $mxCnt)) -ForegroundColor Green
Write-Host ("  with MTA-STS  : {0,8:N0}  ({1} of MX domains)" -f $mtaCnt,   (& $pct $mtaCnt   $mxCnt)) -ForegroundColor Green
Write-Host "Report written to $OutputCsv" -ForegroundColor Green
