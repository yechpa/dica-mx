<#
.SYNOPSIS
    DICA MX tool (PowerShell) - dependency-free version, for machines
    without Python or internet access for pip (just needs outbound port
    25 to the client's MX, same as telnet).

.DESCRIPTION
    Automates the 3 raw SMTP tests of the DICA MX procedure: unauthenticated
    send, spoofing, open mail relay. Resolves the MX via Resolve-DnsName
    when available, otherwise asks for the IP manually (e.g. already
    gathered via dnsdumpster / an .xlsx export).

    AUTHORIZED USE ONLY - as part of a signed client mandate.

.EXAMPLE
    .\bdika_mx.ps1
#>

[CmdletBinding()]
param(
    [string]$Domain,
    [string]$InternalEmail,
    [string]$RelayTestEmail,
    [string]$SpoofFrom = "support@amazon.com",
    [string]$MxHost,
    [string]$MxIp,
    [int]$Port = 25,
    [switch]$ConfirmAuthorized
)

$ErrorActionPreference = "Stop"

function Read-Prompt($Message, $Default = $null, [switch]$Required) {
    while ($true) {
        $suffix = if ($Default) { " [$Default]" } else { "" }
        $val = Read-Host "$Message$suffix"
        if ([string]::IsNullOrWhiteSpace($val)) {
            if ($Default) { return $Default }
            if ($Required) { Write-Host "    -> required, please enter a value." -ForegroundColor Yellow; continue }
            return $null
        }
        return $val.Trim()
    }
}

# --------------------------------------------------------------------
# Interactive mode when no domain is passed as a parameter
# --------------------------------------------------------------------
if (-not $Domain) {
    Write-Host "`n=== DICA MX interactive assistant (PowerShell) ===" -ForegroundColor Cyan
    Write-Host "(Press Enter to accept the default in [ ], or to skip a test)`n"

    $Domain         = Read-Prompt "Client domain to test (e.g. client-domain.com)" -Required
    $InternalEmail  = Read-Prompt "Internal control address on $Domain" -Required
    $RelayTestEmail = Read-Prompt "External mailbox for the relay test (Enter = skip this test)"
    $SpoofFrom      = Read-Prompt "External address to spoof" -Default $SpoofFrom
    $MxIp           = Read-Prompt "MX IP (Enter = try an automatic DNS lookup)"
    if ($MxIp) {
        $MxHost = Read-Prompt "Matching MX hostname (for HELO)" -Default $Domain
    }
}

if (-not $MxHost -or -not $MxIp) {
    Write-Host "[i] Looking up MX for $Domain ..." -ForegroundColor Cyan
    try {
        $records = Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop | Sort-Object Preference
        foreach ($r in $records) { Write-Host ("    priority {0,3}  {1}" -f $r.Preference, $r.NameExchange) }
        $best = $records | Select-Object -First 1
        if (-not $MxHost) { $MxHost = $best.NameExchange.TrimEnd('.') }
        if (-not $MxIp) {
            $a = Resolve-DnsName -Name $MxHost -Type A -ErrorAction Stop | Select-Object -First 1
            $MxIp = $a.IPAddress
        }
    } catch {
        Write-Host "[!] Automatic DNS lookup failed ($($_.Exception.Message))." -ForegroundColor Yellow
        Write-Host "    Enter the MX IP and hostname manually (e.g. from a dnsdumpster export)."
        if (-not $MxIp)   { $MxIp   = Read-Prompt "MX IP" -Required }
        if (-not $MxHost) { $MxHost = Read-Prompt "MX hostname (for HELO)" -Default $Domain }
    }
}
Write-Host "[i] MX selected: $MxHost -> $MxIp`n" -ForegroundColor Cyan

# --------------------------------------------------------------------
# DNS posture check (SPF/DMARC) - passive, read-only, no SMTP connection.
# Context for interpreting the active tests below: a tested domain's own
# DMARC policy explains why unauthenticated/self-impersonation is blocked
# or not, and the spoofed domain's own DMARC policy sets the bar for what
# a compliant receiving gateway should do with the spoofing test (p=reject
# should SMTP-reject; p=quarantine should accept then filter downstream;
# p=none means no expectation either way).
# --------------------------------------------------------------------
function Get-SpfRecord($LookupDomain) {
    try {
        $txts = Resolve-DnsName -Name $LookupDomain -Type TXT -ErrorAction Stop
        $spf = $txts | Where-Object { ($_.Strings -join '') -match '^v=spf1' } | Select-Object -First 1
        if ($spf) { return ($spf.Strings -join '') }
        return $null
    } catch {
        if ($_.Exception.Message -match 'does not exist|Non-existent') { return $null }
        return "(check unavailable: $($_.Exception.Message))"
    }
}

function Get-DmarcRecord($LookupDomain) {
    try {
        $txts = Resolve-DnsName -Name "_dmarc.$LookupDomain" -Type TXT -ErrorAction Stop
        $dmarc = $txts | Where-Object { ($_.Strings -join '') -match '^v=DMARC1' } | Select-Object -First 1
        if ($dmarc) { return ($dmarc.Strings -join '') }
        return $null
    } catch {
        if ($_.Exception.Message -match 'does not exist|Non-existent') { return $null }
        return "(check unavailable: $($_.Exception.Message))"
    }
}

# Approximate SPF "DNS lookup" count (the include:/a/mx/ptr/exists/redirect
# mechanisms that each cost one lookup against the RFC 7208 limit of 10).
# This only counts TOP-LEVEL mechanisms in the record itself -- it does not
# recursively resolve each include's own lookups, so treat a result close
# to or over 10 as "worth investigating properly", not as a precise count.
function Get-SpfLookupCount($SpfRecord) {
    if (-not $SpfRecord -or $SpfRecord -match '^\(check unavailable') { return $null }
    $count = 0
    foreach ($term in ($SpfRecord -split '\s+')) {
        $t = $term -replace '^[+\-~?]', ''
        if ($t -match '^(include:|a($|:|/)|mx($|:|/)|ptr($|:)|exists:|redirect=)') { $count++ }
    }
    return $count
}

# --------------------------------------------------------------------
# MX blacklist check - is the CLIENT's own MX IP listed on a major DNSBL?
# Independent finding from the active SMTP tests: a blacklisted MX means
# the client's own outbound/bounce traffic (or a past compromise) is
# already flagged by other mail providers, regardless of how the SMTP
# tests below turn out.
# --------------------------------------------------------------------
function Test-MxBlacklist($Ip) {
    $octets = $Ip -split '\.'
    if ($octets.Count -ne 4) { return @() }
    $reversed = "$($octets[3]).$($octets[2]).$($octets[1]).$($octets[0])"
    $zones = @("zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.org", "psbl.surriel.com", "cbl.abuseat.org")
    $hits = @()
    foreach ($zone in $zones) {
        try {
            Resolve-DnsName -Name "$reversed.$zone" -Type A -ErrorAction Stop | Out-Null
            $hits += $zone
        } catch { }  # NXDOMAIN = not listed on this zone, expected
    }
    return $hits
}

$spoofDomain = ($SpoofFrom -split '@')[-1]

Write-Host "--- DNS posture check (SPF/DMARC) ---" -ForegroundColor Cyan
$clientSpf    = Get-SpfRecord $Domain
$clientDmarc  = Get-DmarcRecord $Domain
Write-Host "  $Domain SPF    : $(if ($clientSpf) { $clientSpf } else { '(none found)' })"
Write-Host "  $Domain DMARC  : $(if ($clientDmarc) { $clientDmarc } else { '(none found)' })"

$spoofSpf   = Get-SpfRecord $spoofDomain
$spoofDmarc = Get-DmarcRecord $spoofDomain
Write-Host "  $spoofDomain SPF    : $(if ($spoofSpf) { $spoofSpf } else { '(none found)' })"
Write-Host "  $spoofDomain DMARC  : $(if ($spoofDmarc) { $spoofDmarc } else { '(none found)' })`n"

$spfLookupCount = Get-SpfLookupCount $clientSpf

Write-Host "--- MX blacklist check ($MxIp) ---" -ForegroundColor Cyan
$blacklistHits = Test-MxBlacklist $MxIp
if ($blacklistHits.Count -gt 0) {
    Write-Host "  LISTED on: $($blacklistHits -join ', ')" -ForegroundColor Red
} else {
    Write-Host "  Not listed on any checked DNSBL ($(( @('zen.spamhaus.org','bl.spamcop.net','b.barracudacentral.org','dnsbl.sorbs.org','psbl.surriel.com','cbl.abuseat.org')) -join ', '))"
}
Write-Host ""

# --------------------------------------------------------------------
# Findings collected for the Monday.com import (actionable items only --
# OK verdicts are not findings, nothing to action on those).
# --------------------------------------------------------------------
$findings = @()
function Add-Finding($Name, $Severity, $Description, $Recommendation) {
    $script:findings += [PSCustomObject]@{
        Name = $Name; Severity = $Severity; Description = $Description; Recommendation = $Recommendation
    }
}

if ($blacklistHits.Count -gt 0) {
    Add-Finding "MX IP listed on a DNSBL" "High" `
        "$MxIp ($MxHost) is listed on: $($blacklistHits -join ', ')." `
        "Investigate why the client's own MX IP is blacklisted (possible past abuse/compromise) and request delisting once resolved."
}
if (-not $clientDmarc) {
    Add-Finding "No DMARC record on $Domain" "High" `
        "No DMARC TXT record found at _dmarc.$Domain." `
        "Publish a DMARC record (start at p=quarantine, move to p=reject once monitored) to prevent impersonation of $Domain."
} elseif ($clientDmarc -match '^\(check unavailable') {
    Add-Finding "DMARC check could not be completed for $Domain" "Info" $clientDmarc "Re-run the DNS posture check once connectivity/resolver issues are resolved."
}
if (-not $clientSpf) {
    Add-Finding "No SPF record on $Domain" "Medium" `
        "No SPF TXT record found for $Domain." `
        "Publish an SPF record listing all legitimate sending sources for $Domain."
} elseif ($spfLookupCount -ne $null -and $spfLookupCount -ge 10) {
    Add-Finding "SPF record near/over the 10-lookup limit" "Medium" `
        "$Domain SPF has approximately $spfLookupCount top-level DNS-lookup mechanisms (include/a/mx/ptr/exists/redirect); RFC 7208 caps this at 10, beyond which SPF evaluation returns permerror and effectively stops protecting the domain." `
        "Flatten/reduce the SPF record's includes to stay under the 10-lookup limit."
}

$dnsPosture = [PSCustomObject]@{
    ClientDomain = $Domain; ClientSpf = $clientSpf; ClientDmarc = $clientDmarc
    SpoofDomain  = $spoofDomain; SpoofSpf = $spoofSpf; SpoofDmarc = $spoofDmarc
    SpfLookupCount = $spfLookupCount; MxBlacklistHits = $blacklistHits
}

Write-Host "--- Summary ---"
Write-Host "  Domain          : $Domain"
Write-Host "  Internal mailbox: $InternalEmail"
Write-Host "  Relay test      : $(if ($RelayTestEmail) { $RelayTestEmail } else { '(skipped)' })"
Write-Host "  Spoof From      : $SpoofFrom"
Write-Host "  MX              : $MxHost ($MxIp)`n"

if (-not $ConfirmAuthorized) {
    $ans = Read-Host "Do you confirm you have a signed client mandate authorizing this test? (type 'yes' to continue)"
    if ($ans.Trim().ToLower() -notin @("yes", "y", "oui")) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 1
    }
}

# --------------------------------------------------------------------
# Raw SMTP transaction over a TCP socket (no external module required)
# --------------------------------------------------------------------
function Invoke-SmtpTest {
    param(
        [string]$Key, [string]$Title,
        [string]$MailFrom, [string]$RcptTo,
        [string]$Subject, [string]$Body,
        [string]$FromName = "Integrity", [string]$ToName = "Client"
    )

    $transcript = [System.Collections.Generic.List[string]]::new()
    $finalCode = $null

    function Read-SmtpLine($reader) {
        # An SMTP response can span multiple lines ("250-..." then "250 ...");
        # keep reading until the final line (4th character is a space, not '-').
        $last = $null
        do {
            $last = $reader.ReadLine()
            if ($null -eq $last) { break }
        } while ($last.Length -ge 4 -and $last[3] -eq '-')
        return $last
    }

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = 15000
        $client.SendTimeout = 15000
        $client.Connect($MxIp, $Port)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.NewLine = "`r`n"
        $writer.AutoFlush = $true

        $greeting = Read-SmtpLine $reader
        $transcript.Add("CONNECT -> $greeting")
        $finalCode = [int]($greeting.Substring(0,3))
        if ($finalCode -ge 400) { throw "stop" }

        $writer.WriteLine("HELO $Domain")
        $resp = Read-SmtpLine $reader
        $transcript.Add("HELO $Domain -> $resp")
        $finalCode = [int]($resp.Substring(0,3))
        if ($finalCode -ge 400) { throw "stop" }

        $writer.WriteLine("MAIL FROM:<$MailFrom>")
        $resp = Read-SmtpLine $reader
        $transcript.Add("MAIL FROM:<$MailFrom> -> $resp")
        $finalCode = [int]($resp.Substring(0,3))
        if ($finalCode -ge 400) { throw "stop" }

        $writer.WriteLine("RCPT TO:<$RcptTo>")
        $resp = Read-SmtpLine $reader
        $transcript.Add("RCPT TO:<$RcptTo> -> $resp")
        $finalCode = [int]($resp.Substring(0,3))
        if ($finalCode -ge 400) { throw "stop" }

        $writer.WriteLine("DATA")
        $resp = Read-SmtpLine $reader
        $transcript.Add("DATA -> $resp")

        $msg = @"
From: $FromName <$MailFrom>
To: $ToName <$RcptTo>
Subject: $Subject

$Body
.
"@
        foreach ($line in ($msg -split "`n")) { $writer.WriteLine($line.TrimEnd("`r")) }
        $resp = Read-SmtpLine $reader
        $transcript.Add("DATA + message body -> $resp")
        $finalCode = [int]($resp.Substring(0,3))

        $writer.WriteLine("QUIT")
        $client.Close()
    } catch {
        if ($_.Exception.Message -ne "stop") {
            $transcript.Add("NETWORK ERROR -> $($_.Exception.Message)")
            $finalCode = -1
        }
    }

    $verdict = switch ($true) {
        ($null -eq $finalCode) { "NOT RUN"; break }
        ($finalCode -eq -1) { "NETWORK ERROR"; break }
        ($Key -eq "relay" -and $finalCode -ge 400) { "OK - relay refused (code $finalCode, good sign)"; break }
        ($Key -eq "relay") { "RISK - relay accepted (code $finalCode)"; break }
        ($finalCode -lt 300) { "RISK - message accepted (code $finalCode)"; break }
        default { "OK - message rejected (code $finalCode)" }
    }

    return [PSCustomObject]@{
        Key = $Key; Title = $Title; MailFrom = $MailFrom; RcptTo = $RcptTo
        Transcript = $transcript; FinalCode = $finalCode; Verdict = $verdict
    }
}

$disclaimer = "Hello,`n`nThis is a test performed by Integrity. If you receive this email, please send us a screenshot (and let us know whether it landed in your inbox, junk, or spam folder).`n`nThank you."

$results = @()

Write-Host "--- Unauthenticated send test ---" -ForegroundColor Cyan
$r = Invoke-SmtpTest -Key "unauth" -Title "Unauthenticated send test" `
        -MailFrom $InternalEmail -RcptTo $InternalEmail `
        -Subject "Integrity Unauthenticated Test" -Body $disclaimer
$r.Transcript | ForEach-Object { Write-Host "    $_" }
Write-Host "    => $($r.Verdict)`n"
$results += $r

Write-Host "--- Spoofing test ---" -ForegroundColor Cyan
$r = Invoke-SmtpTest -Key "spoof" -Title "Spoofing test" `
        -MailFrom $SpoofFrom -RcptTo $InternalEmail `
        -Subject "Integrity Spoofing Test" -Body $disclaimer
$r.Transcript | ForEach-Object { Write-Host "    $_" }
Write-Host "    => $($r.Verdict)`n"
$results += $r

if ($RelayTestEmail) {
    Write-Host "--- Open mail relay test ---" -ForegroundColor Cyan
    $relayBody = "Hello,`n`nThis is a test performed by Integrity. If you receive this email, the MX that was tested can be used as a mail relay.`n`nThank you."
    $r = Invoke-SmtpTest -Key "relay" -Title "Open mail relay test" `
            -MailFrom $InternalEmail -RcptTo $RelayTestEmail `
            -Subject "Integrity Mail Relay Test" -Body $relayBody
    $r.Transcript | ForEach-Object { Write-Host "    $_" }
    Write-Host "    => $($r.Verdict)`n"
    $results += $r
}

foreach ($r in $results) {
    if ($r.Verdict -like "RISK*") {
        Add-Finding "$($r.Title) - accepted" "High" `
            "$($r.Title) was accepted by the MX ($($r.Verdict))." `
            "Review mail gateway rules to block/quarantine this scenario; see the transcript in the JSON log for the exact SMTP exchange."
    }
}

# --------------------------------------------------------------------
# Report + log, both in English
# --------------------------------------------------------------------
$outDir = Join-Path $PSScriptRoot "dica_mx_reports"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$slug = $Domain -replace '\.', '_'

$logPath = Join-Path $outDir "$slug`_$stamp`_log.json"
$reportPath = Join-Path $outDir "$slug`_$stamp`_report.txt"
$findingsPath = Join-Path $outDir "$slug`_$stamp`_findings_monday.csv"

[PSCustomObject]@{
    DnsPosture = $dnsPosture
    Tests = ($results | Select-Object Key, Title, MailFrom, RcptTo, FinalCode, Verdict, @{N='Transcript';E={$_.Transcript}})
    Findings = $findings
} | ConvertTo-Json -Depth 5 | Set-Content -Path $logPath -Encoding UTF8

$reportLines = @()
$reportLines += "Subject: MX Server Test Summary - $Domain - $(Get-Date -Format 'dd/MM/yyyy')"
$reportLines += ""
$reportLines += "Domain tested: $Domain"
$reportLines += "MX tested: $MxHost ($MxIp)"
$reportLines += ""
$reportLines += "--- DNS posture check (SPF/DMARC) ---"
$reportLines += "$Domain SPF: $(if ($clientSpf) { $clientSpf } else { '(none found)' })"
$reportLines += "$Domain DMARC: $(if ($clientDmarc) { $clientDmarc } else { '(none found)' })"
$reportLines += "$spoofDomain SPF: $(if ($spoofSpf) { $spoofSpf } else { '(none found)' })"
$reportLines += "$spoofDomain DMARC: $(if ($spoofDmarc) { $spoofDmarc } else { '(none found)' })"
$reportLines += ""
$reportLines += "--- MX blacklist check ($MxIp) ---"
$reportLines += $(if ($blacklistHits.Count -gt 0) { "LISTED on: $($blacklistHits -join ', ')" } else { "Not listed on any checked DNSBL" })
$reportLines += ""
foreach ($r in $results) {
    $reportLines += "--- $($r.Title) ---"
    $reportLines += "Result: $($r.Verdict)"
    $reportLines += ""
}
$reportLines -join "`n" | Set-Content -Path $reportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    $findings | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding UTF8
} else {
    "Name,Severity,Description,Recommendation" | Set-Content -Path $findingsPath -Encoding UTF8
}

Write-Host "[OK] JSON log       : $logPath" -ForegroundColor Green
Write-Host "[OK] Report         : $reportPath" -ForegroundColor Green
Write-Host "[OK] Findings (Monday import, $($findings.Count) item(s)): $findingsPath" -ForegroundColor Green
