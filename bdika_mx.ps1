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

# --------------------------------------------------------------------
# Report + log, both in English
# --------------------------------------------------------------------
$outDir = Join-Path $PSScriptRoot "dica_mx_reports"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$slug = $Domain -replace '\.', '_'

$logPath = Join-Path $outDir "$slug`_$stamp`_log.json"
$reportPath = Join-Path $outDir "$slug`_$stamp`_report.txt"

$results | Select-Object Key, Title, MailFrom, RcptTo, FinalCode, Verdict, @{N='Transcript';E={$_.Transcript}} |
    ConvertTo-Json -Depth 4 | Set-Content -Path $logPath -Encoding UTF8

$reportLines = @()
$reportLines += "Subject: MX Server Test Summary - $Domain - $(Get-Date -Format 'dd/MM/yyyy')"
$reportLines += ""
$reportLines += "Domain tested: $Domain"
$reportLines += "MX tested: $MxHost ($MxIp)"
$reportLines += ""
foreach ($r in $results) {
    $reportLines += "--- $($r.Title) ---"
    $reportLines += "Result: $($r.Verdict)"
    $reportLines += ""
}
$reportLines -join "`n" | Set-Content -Path $reportPath -Encoding UTF8

Write-Host "[OK] JSON log   : $logPath" -ForegroundColor Green
Write-Host "[OK] Report     : $reportPath" -ForegroundColor Green
