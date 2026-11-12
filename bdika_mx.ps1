<#
.SYNOPSIS
    Outil DICA MX (PowerShell) - version sans dependance, pour machine
    sans Python ni acces Internet pour pip (juste le port 25 sortant vers
    le MX du client, comme telnet).

.DESCRIPTION
    Automatise les 3 tests SMTP bruts de la procedure DICA MX :
    non authentifie, usurpation (spoofing), relais ouvert.
    Resout le MX via Resolve-DnsName si disponible, sinon demande l'IP
    manuellement (ex: deja recuperee via dnsdumpster/export .xlsx).

    USAGE RESERVE a des tests autorises, dans le cadre d'un mandat client
    signe.

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
            if ($Required) { Write-Host "    -> requis, merci de saisir une valeur." -ForegroundColor Yellow; continue }
            return $null
        }
        return $val.Trim()
    }
}

# --------------------------------------------------------------------
# Mode interactif si pas de domaine fourni en parametre
# --------------------------------------------------------------------
if (-not $Domain) {
    Write-Host "`n=== Assistant interactif - DICA MX (PowerShell) ===" -ForegroundColor Cyan
    Write-Host "(Entree sans rien taper = valeur par defaut entre [ ], ou saute le test)`n"

    $Domain         = Read-Prompt "Domaine du client a tester (ex: client-domaine.com)" -Required
    $InternalEmail  = Read-Prompt "Adresse interne de controle sur $Domain" -Required
    $RelayTestEmail = Read-Prompt "Boite externe pour le test de relais (Entree = sauter ce test)"
    $SpoofFrom      = Read-Prompt "Adresse externe usurpee pour le spoofing" -Default $SpoofFrom
    $MxIp           = Read-Prompt "IP du MX (Entree = tenter un lookup DNS automatique)"
    if ($MxIp) {
        $MxHost = Read-Prompt "Hostname MX correspondant (pour le HELO)" -Default $Domain
    }
}

if (-not $MxHost -or -not $MxIp) {
    Write-Host "[i] Lookup MX pour $Domain ..." -ForegroundColor Cyan
    try {
        $records = Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop | Sort-Object Preference
        foreach ($r in $records) { Write-Host ("    priorite {0,3}  {1}" -f $r.Preference, $r.NameExchange) }
        $best = $records | Select-Object -First 1
        if (-not $MxHost) { $MxHost = $best.NameExchange.TrimEnd('.') }
        if (-not $MxIp) {
            $a = Resolve-DnsName -Name $MxHost -Type A -ErrorAction Stop | Select-Object -First 1
            $MxIp = $a.IPAddress
        }
    } catch {
        Write-Host "[!] Lookup DNS automatique impossible ($($_.Exception.Message))." -ForegroundColor Yellow
        Write-Host "    Entre l'IP et le hostname du MX manuellement (ex: via l'export dnsdumpster)."
        if (-not $MxIp)   { $MxIp   = Read-Prompt "IP du MX" -Required }
        if (-not $MxHost) { $MxHost = Read-Prompt "Hostname MX (pour HELO)" -Default $Domain }
    }
}
Write-Host "[i] MX retenu : $MxHost -> $MxIp`n" -ForegroundColor Cyan

Write-Host "--- Recapitulatif ---"
Write-Host "  Domaine        : $Domain"
Write-Host "  Boite interne  : $InternalEmail"
Write-Host "  Test relais    : $(if ($RelayTestEmail) { $RelayTestEmail } else { '(saute)' })"
Write-Host "  Spoof From     : $SpoofFrom"
Write-Host "  MX             : $MxHost ($MxIp)`n"

if (-not $ConfirmAuthorized) {
    $ans = Read-Host "Confirmes-tu disposer d'un mandat client signe autorisant ce test ? (taper 'oui' pour continuer)"
    if ($ans.Trim().ToLower() -notin @("oui", "yes", "y")) {
        Write-Host "Annule." -ForegroundColor Yellow
        exit 1
    }
}

# --------------------------------------------------------------------
# Transaction SMTP brute sur socket TCP (pas de module externe requis)
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
        # Une reponse SMTP peut etre multi-ligne ("250-..." puis "250 ...") ;
        # on lit jusqu'a la ligne finale (4e caractere = espace, pas '-').
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

        $writer.WriteLine("HELO $MxHost".Replace($MxHost, $Domain))  # HELO <notre domaine>, pas celui du MX
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
        $transcript.Add("DATA + corps du message -> $resp")
        $finalCode = [int]($resp.Substring(0,3))

        $writer.WriteLine("QUIT")
        $client.Close()
    } catch {
        if ($_.Exception.Message -ne "stop") {
            $transcript.Add("ERREUR RESEAU -> $($_.Exception.Message)")
            $finalCode = -1
        }
    }

    $verdict = switch ($true) {
        ($null -eq $finalCode) { "NON EXECUTE"; break }
        ($finalCode -eq -1) { "ERREUR RESEAU"; break }
        ($Key -eq "relay" -and $finalCode -ge 400) { "OK - relais refuse (code $finalCode, bon signe)"; break }
        ($Key -eq "relay") { "RISQUE - relais accepte (code $finalCode)"; break }
        ($finalCode -lt 300) { "RISQUE - message accepte (code $finalCode)"; break }
        default { "OK - message refuse (code $finalCode)" }
    }

    return [PSCustomObject]@{
        Key = $Key; Title = $Title; MailFrom = $MailFrom; RcptTo = $RcptTo
        Transcript = $transcript; FinalCode = $finalCode; Verdict = $verdict
    }
}

$disclaimer = "Bonjour,`n`nCeci est un test realise par Integrity. Si vous recevez cet email, merci de nous renvoyer une capture d'ecran (et de preciser s'il est arrive en boite de reception, indesirables ou spam).`n`nMerci."

$results = @()

Write-Host "--- Test non authentifie ---" -ForegroundColor Cyan
$r = Invoke-SmtpTest -Key "unauth" -Title "Test non authentifie" `
        -MailFrom $InternalEmail -RcptTo $InternalEmail `
        -Subject "Integrity Unauthenticated Test" -Body $disclaimer
$r.Transcript | ForEach-Object { Write-Host "    $_" }
Write-Host "    => $($r.Verdict)`n"
$results += $r

Write-Host "--- Test d'usurpation (spoofing) ---" -ForegroundColor Cyan
$r = Invoke-SmtpTest -Key "spoof" -Title "Test d'usurpation (spoofing)" `
        -MailFrom $SpoofFrom -RcptTo $InternalEmail `
        -Subject "Integrity Spoofing Test" -Body $disclaimer
$r.Transcript | ForEach-Object { Write-Host "    $_" }
Write-Host "    => $($r.Verdict)`n"
$results += $r

if ($RelayTestEmail) {
    Write-Host "--- Test de relais ouvert (mail relay) ---" -ForegroundColor Cyan
    $relayBody = "Bonjour,`n`nCeci est un test realise par Integrity. Si vous recevez cet email, le MX teste peut etre utilise comme relais de courrier.`n`nMerci."
    $r = Invoke-SmtpTest -Key "relay" -Title "Test de relais ouvert (mail relay)" `
            -MailFrom $InternalEmail -RcptTo $RelayTestEmail `
            -Subject "Integrity Mail Relay Test" -Body $relayBody
    $r.Transcript | ForEach-Object { Write-Host "    $_" }
    Write-Host "    => $($r.Verdict)`n"
    $results += $r
}

# --------------------------------------------------------------------
# Rapport + mail de prevenance (bilingue EN/HE, un seul fichier chacun)
# --------------------------------------------------------------------
$outDir = Join-Path $PSScriptRoot "dica_mx_reports"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$slug = $Domain -replace '\.', '_'

$logPath = Join-Path $outDir "$slug`_$stamp`_log.json"
$reportPath = Join-Path $outDir "$slug`_$stamp`_rapport.txt"

$results | Select-Object Key, Title, MailFrom, RcptTo, FinalCode, Verdict, @{N='Transcript';E={$_.Transcript}} |
    ConvertTo-Json -Depth 4 | Set-Content -Path $logPath -Encoding UTF8

# Le rapport client est toujours en anglais (destinataires israeliens,
# le francais ne sert qu'en interne) -- titres et verdicts retraduits ici,
# independamment des messages console ci-dessus.
$englishTitle = @{
    "unauth" = "Unauthenticated send test"
    "spoof"  = "Spoofing test"
    "relay"  = "Open mail relay test"
}

function Get-EnglishVerdict($r) {
    if ($null -eq $r.FinalCode) { return "NOT RUN" }
    if ($r.FinalCode -eq -1) { return "NETWORK ERROR" }
    if ($r.Key -eq "relay") {
        if ($r.FinalCode -ge 400) { return "OK - relay refused (code $($r.FinalCode), good sign)" }
        return "RISK - relay accepted (code $($r.FinalCode))"
    }
    if ($r.FinalCode -lt 300) { return "RISK - message accepted (code $($r.FinalCode))" }
    return "OK - message rejected (code $($r.FinalCode))"
}

$reportLines = @()
$reportLines += "Subject: MX Server Test Summary - $Domain - $(Get-Date -Format 'dd/MM/yyyy')"
$reportLines += ""
$reportLines += "Domain tested: $Domain"
$reportLines += "MX tested: $MxHost ($MxIp)"
$reportLines += ""
foreach ($r in $results) {
    $title = if ($englishTitle.ContainsKey($r.Key)) { $englishTitle[$r.Key] } else { $r.Title }
    $reportLines += "--- $title ---"
    $reportLines += "Result: $(Get-EnglishVerdict $r)"
    $reportLines += ""
}
$reportLines -join "`n" | Set-Content -Path $reportPath -Encoding UTF8

Write-Host "[OK] Log JSON      : $logPath" -ForegroundColor Green
Write-Host "[OK] Rapport client: $reportPath" -ForegroundColor Green
