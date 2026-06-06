#Requires -Version 7.0
<#
.SYNOPSIS
    Checks DANE (TLSA records) for a list of DNSSEC-signed domains.

.DESCRIPTION
    DANE (RFC 6698) publishes TLS certificate associations as TLSA records in
    DNS, and is only trustworthy when those records are DNSSEC-signed -- so this
    is intended to run over the DNSSEC-enabled domains extracted from the DNSSEC
    scan (dnssec_enabled.csv). Two deployments are checked per domain:

      * Web  DANE : TLSA at _443._tcp.<domain>
      * SMTP DANE : MX lookup, then TLSA at _25._tcp.<each-mx-host>
                    (SMTP DANE -- by far the most deployed form -- lives on the
                     MAIL HOST names, not the domain itself.)

    Resolve-DnsName cannot query TLSA (its record-type enum has no TLSA), so this
    script includes a tiny dependency-free DNS client (raw UDP with EDNS0 and a
    TCP fallback for truncated responses) that parses TLSA answers directly. MX
    is resolved with the built-in Resolve-DnsName (which does support MX).

    NOTE: this detects the PRESENCE of TLSA records (i.e. DANE is published). It
    does not fetch the TLS certificate and verify it matches the TLSA record, nor
    re-validate the DNSSEC chain on the TLSA RRset itself.

    Multi-threaded (ForEach-Object -Parallel), batched + resumable like the other
    scanners.

.PARAMETER InputCsv   List of domains (needs a Domain column). Default .\dnssec_enabled.csv
.PARAMETER OutputCsv  Results CSV. Default .\dane_report.csv
.PARAMETER ThrottleLimit  Max concurrent lookups. Default 500.
.PARAMETER BatchSize  Domains per batch before flushing. Default 20000.
.PARAMETER Server     DNS server(s), round-robin per-domain. Default 1.1.1.1/8.8.8.8/9.9.9.9.
.PARAMETER Limit      Process only the first N (testing).
.PARAMETER Resume     Skip domains already in OutputCsv.

.EXAMPLE
    pwsh -File .\Scan-Dane.ps1
.EXAMPLE
    pwsh -File .\Scan-Dane.ps1 -Limit 500
#>
[CmdletBinding()]
param(
    [string]$InputCsv      = (Join-Path $PSScriptRoot 'dnssec_enabled.csv'),
    [string]$OutputCsv     = (Join-Path $PSScriptRoot 'dane_report.csv'),
    [int]   $ThrottleLimit = 500,
    [int]   $BatchSize     = 20000,
    [string[]]$Server      = @('1.1.1.1', '8.8.8.8', '9.9.9.9'),
    [int]   $Limit,
    [switch]$Resume
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $InputCsv)) { throw "Input CSV not found: $InputCsv" }
if (-not $IsWindows) { throw "Relies on Resolve-DnsName (MX lookups), which is Windows-only." }

Write-Host "Reading domains from $InputCsv ..." -ForegroundColor Cyan
$domains = Import-Csv -LiteralPath $InputCsv | Select-Object @{N='Rank';E={$_.Rank}}, @{N='Domain';E={$_.Domain}}
if ($Limit -gt 0) { $domains = $domains | Select-Object -First $Limit }
Write-Host "Loaded $($domains.Count) domains." -ForegroundColor Cyan
Write-Host ("Resolver(s): {0} | ThrottleLimit: {1} | BatchSize: {2}" -f ($Server -join ', '), $ThrottleLimit, $BatchSize) -ForegroundColor Cyan

if ($Resume -and (Test-Path -LiteralPath $OutputCsv)) {
    $done = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]((Import-Csv -LiteralPath $OutputCsv).Domain), [System.StringComparer]::OrdinalIgnoreCase)
    $domains = $domains | Where-Object { -not $done.Contains($_.Domain) }
    Write-Host "Resume: $($done.Count) done, $($domains.Count) remaining." -ForegroundColor Cyan
} elseif (Test-Path -LiteralPath $OutputCsv) {
    Remove-Item -LiteralPath $OutputCsv -Force
}

$total = $domains.Count
if ($total -eq 0) { Write-Host "Nothing to do." -ForegroundColor Yellow; return }

$swAll = [System.Diagnostics.Stopwatch]::StartNew()
$processed = 0; $webCnt = 0; $smtpCnt = 0; $anyCnt = 0; $batchIndex = 0

for ($offset = 0; $offset -lt $total; $offset += $BatchSize) {
    $batch = $domains[$offset..([Math]::Min($offset + $BatchSize, $total) - 1)]
    $batchIndex++

    $results = $batch | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $row     = $_
        $domain  = $row.Domain
        $servers = $using:Server
        $srv     = if ($servers.Count -gt 1) { $servers[[Math]::Abs($domain.GetHashCode()) % $servers.Count] } else { $servers[0] }

        # --- dependency-free TLSA resolver (raw UDP + TCP fallback) ---
        function Resolve-Tlsa {
            param([string]$QName, [string]$Server, [int]$TimeoutMs = 3000)
            function Skip-Name([byte[]]$b, [int]$pos) {
                # NOTE: PowerShell returns $null (not an exception) for an out-of-range
                # index, so every loop here MUST bound-check $pos or it spins forever.
                while ($pos -lt $b.Length) {
                    $len = $b[$pos]
                    if ($len -eq 0) { return $pos + 1 }
                    if (($len -band 0xC0) -eq 0xC0) { return $pos + 2 }   # compression pointer ends the name
                    $pos += 1 + $len
                }
                return $b.Length   # walked off the end of a malformed/truncated response
            }
            function Parse-Resp([byte[]]$b) {
                if ($null -eq $b -or $b.Length -lt 12) {
                    return [pscustomobject]@{ Truncated = $false; Rcode = -1; Tlsa = @() }
                }
                $tc = ($b[2] -band 0x02) -ne 0
                $rcode = $b[3] -band 0x0F
                $an = ($b[6] -shl 8) -bor $b[7]
                $pos = Skip-Name $b 12; $pos += 4
                $tlsa = @()
                for ($i = 0; $i -lt $an; $i++) {
                    $pos = Skip-Name $b $pos
                    if ($pos + 10 -gt $b.Length) { break }                # need type+class+ttl+rdlen
                    $type = ($b[$pos] -shl 8) -bor $b[$pos + 1]; $pos += 8
                    $rdlen = ($b[$pos] -shl 8) -bor $b[$pos + 1]; $pos += 2
                    if ($pos + $rdlen -gt $b.Length) { break }            # rdata would overrun buffer
                    if ($type -eq 52 -and $rdlen -ge 3) {
                        $tlsa += "{0}/{1}/{2}" -f $b[$pos], $b[$pos + 1], $b[$pos + 2]
                    }
                    $pos += $rdlen
                }
                [pscustomobject]@{ Truncated = $tc; Rcode = $rcode; Tlsa = $tlsa }
            }
            $id = Get-Random -Minimum 0 -Maximum 65535
            $hdr = [byte[]](($id -shr 8), ($id -band 0xFF), 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x01)
            $q = [System.Collections.Generic.List[byte]]::new()
            foreach ($lbl in $QName.Split('.')) {
                if ($lbl.Length -eq 0) { continue }
                $lb = [Text.Encoding]::ASCII.GetBytes($lbl); $q.Add([byte]$lb.Length); $q.AddRange($lb)
            }
            $q.Add(0); $q.AddRange([byte[]](0x00,0x34, 0x00,0x01))
            $opt = [byte[]](0x00, 0x00,0x29, 0x10,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00)
            $packet = $hdr + $q.ToArray() + $opt

            $udp = [System.Net.Sockets.UdpClient]::new()
            try {
                $udp.Client.ReceiveTimeout = $TimeoutMs
                $udp.Connect($Server, 53); [void]$udp.Send($packet, $packet.Length)
                $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                $resp = $udp.Receive([ref]$ep)
            } catch { return $null } finally { $udp.Dispose() }

            $parsed = Parse-Resp $resp
            if (-not $parsed.Truncated) { return $parsed }

            $tcp = [System.Net.Sockets.TcpClient]::new()
            try {
                $tcp.ReceiveTimeout = $TimeoutMs; $tcp.SendTimeout = $TimeoutMs
                # TcpClient.Connect has no connect timeout -- enforce one, else a
                # silent resolver can block this runspace (and the whole -Parallel).
                $iar = $tcp.BeginConnect($Server, 53, $null, $null)
                if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $parsed }
                $tcp.EndConnect($iar)
                $ns = $tcp.GetStream(); $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs
                $ns.Write([byte[]](($packet.Length -shr 8), ($packet.Length -band 0xFF)), 0, 2)
                $ns.Write($packet, 0, $packet.Length); $ns.Flush()
                $l = [byte[]]::new(2)
                if ($ns.Read($l, 0, 2) -lt 2) { return $parsed }
                $rlen = ($l[0] -shl 8) -bor $l[1]
                if ($rlen -le 0) { return $parsed }
                $buf = [byte[]]::new($rlen); $read = 0
                while ($read -lt $rlen) {
                    $n = $ns.Read($buf, $read, $rlen - $read)
                    if ($n -le 0) { break }   # peer closed -- avoid infinite spin
                    $read += $n
                }
                if ($read -lt $rlen) { return $parsed }
                return Parse-Resp $buf
            } catch { return $parsed } finally { $tcp.Dispose() }
        }

        $webDane = $false; $smtpDane = $false; $mxCount = 0; $daneMx = 0; $sample = ''; $detail = ''
        try {
            # Web DANE
            $w = Resolve-Tlsa "_443._tcp.$domain" $srv
            if ($w -and @($w.Tlsa).Count -gt 0) { $webDane = $true; $sample = $w.Tlsa[0] }

            # SMTP DANE (MX hosts)
            $mx = @(Resolve-DnsName -Type MX -Name $domain -Server $srv -QuickTimeout -ErrorAction SilentlyContinue |
                Where-Object { $_.Type -eq 'MX' })
            $mxCount = $mx.Count
            foreach ($m in $mx) {
                $h = $m.NameExchange.TrimEnd('.')
                if ([string]::IsNullOrEmpty($h)) { continue }   # null MX
                $s = Resolve-Tlsa "_25._tcp.$h" $srv
                if ($s -and @($s.Tlsa).Count -gt 0) {
                    $smtpDane = $true; $daneMx++
                    if (-not $sample) { $sample = $s.Tlsa[0] }
                }
            }
        } catch { $detail = "Error: $($_.Exception.Message)" }

        [pscustomobject]@{
            Rank        = $row.Rank
            Domain      = $domain
            AnyDane     = ($webDane -or $smtpDane)
            WebDane     = $webDane
            SmtpDane    = $smtpDane
            MxCount     = $mxCount
            DaneMxHosts = $daneMx
            TlsaSample  = $sample
            Detail      = $detail
        }
    }

    $results | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Append

    $processed += $batch.Count
    $webCnt  += @($results | Where-Object WebDane).Count
    $smtpCnt += @($results | Where-Object SmtpDane).Count
    $anyCnt  += @($results | Where-Object AnyDane).Count

    $rate = $processed / [Math]::Max($swAll.Elapsed.TotalSeconds, 0.001)
    $eta  = if ($rate -gt 0) { [TimeSpan]::FromSeconds(($total - $processed) / $rate) } else { [TimeSpan]::Zero }
    Write-Progress -Activity 'Scanning DANE (TLSA)' -PercentComplete ([int](100 * $processed / $total)) `
        -Status ("{0}/{1} | any {2} web {3} smtp {4} | {5:N1} dom/s | ETA {6:hh\:mm\:ss}" -f `
            $processed, $total, $anyCnt, $webCnt, $smtpCnt, $rate, $eta)
    Write-Host ("Batch {0}: {1}/{2} | DANE any {3} (web {4}, smtp {5}) | {6:N1} dom/s" -f `
        $batchIndex, $processed, $total, $anyCnt, $webCnt, $smtpCnt, $rate) -ForegroundColor DarkGray
}

Write-Progress -Activity 'Scanning DANE (TLSA)' -Completed
$swAll.Stop()
$pct = { param($n, $d) if ($d) { '{0:P2}' -f ($n / $d) } else { 'n/a' } }
Write-Host ""
Write-Host "Done. $processed DNSSEC-signed domains in $($swAll.Elapsed.ToString('hh\:mm\:ss'))." -ForegroundColor Green
Write-Host ("DANE (any)  : {0,6:N0}  ({1} of signed domains)" -f $anyCnt,  (& $pct $anyCnt  $processed)) -ForegroundColor Green
Write-Host ("  SMTP DANE : {0,6:N0}  ({1})" -f $smtpCnt, (& $pct $smtpCnt $processed)) -ForegroundColor Green
Write-Host ("  Web  DANE : {0,6:N0}  ({1})" -f $webCnt,  (& $pct $webCnt  $processed)) -ForegroundColor Green
Write-Host "Report written to $OutputCsv" -ForegroundColor Green
