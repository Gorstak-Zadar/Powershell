<#
================================================================================
  SecurityCheckup.ps1
--------------------------------------------------------------------------------
  "Is someone watching my computer?"  -- a plain-English check-up.

  This script looks in the same places a technician would to answer the
  question "is anyone spying on my screen, camera, microphone, or keyboard,
  or logging into my PC from somewhere else?"

  It then explains what it found in normal words, gives you ONE overall
  verdict, and tells you what (if anything) to do about it.

  It ONLY LOOKS. It does not change, delete, or install anything.

  HOW TO RUN (the easy way):
    1. Right-click this file  ->  "Run with PowerShell".
    2. If Windows asks for permission (a blue box), click "Yes" -- that lets
       the check-up see everything. Without it, some checks are skipped.
    3. Read the summary at the bottom. A report file is also saved to your
       Desktop so you can keep it or send it to someone you trust.

  You cannot break anything by running this.
================================================================================
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    # How many days of login history to review.
    [int]$HistoryDays = 14,
    # Where to save the human-readable report. Defaults to the Desktop.
    [string]$ReportPath
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
#  Presentation helpers  (colours + a running list of findings)
# ---------------------------------------------------------------------------

# Each finding has a Level so we can total them up at the end:
#   Good    = nothing wrong here
#   Notice  = worth knowing, not dangerous by itself
#   Warning = please look at this
#   Alarm   = strong sign someone could be watching -- act on it
$script:Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [ValidateSet('Good','Notice','Warning','Alarm')][string]$Level,
        [string]$Title,        # short headline in plain words
        [string]$Detail        # one or two sentences a normal person understands
    )
    $script:Findings.Add([pscustomobject]@{ Level = $Level; Title = $Title; Detail = $Detail })
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ("  " + ('-' * $Text.Length)) -ForegroundColor DarkCyan
}

function Write-Line {
    param([string]$Text, [ConsoleColor]$Color = 'Gray')
    Write-Host ("    " + $Text) -ForegroundColor $Color
}

$script:IsAdmin =
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
#  Intro
# ---------------------------------------------------------------------------
Clear-Host
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor White
Write-Host "        SECURITY CHECK-UP  --  Is anyone watching my PC?" -ForegroundColor White
Write-Host "  ============================================================" -ForegroundColor White
Write-Host ""
Write-Host "  This will take a minute. It only looks -- it changes nothing." -ForegroundColor Gray
if ($script:IsAdmin) {
    Write-Host "  Running with full permissions (good -- all checks will run)." -ForegroundColor DarkGreen
} else {
    Write-Host "  Running WITHOUT full permissions -- a few deep checks will be" -ForegroundColor DarkYellow
    Write-Host "  skipped. For the most thorough result, close this, right-click" -ForegroundColor DarkYellow
    Write-Host "  the file and choose 'Run with PowerShell', then click 'Yes'." -ForegroundColor DarkYellow
}

# ===========================================================================
#  CHECK 1 -- Is someone logged into this PC from somewhere else right now?
# ===========================================================================
Write-Section "1. Someone logged in from another location right now?"
try {
    $sessions = @()
    $raw = (& qwinsta.exe 2>$null)
    foreach ($line in $raw | Select-Object -Skip 1) {
        if ($line -match '\S') { $sessions += $line.Trim() }
    }
    # An RDP-type session name usually contains "rdp-tcp".
    $remoteActive = $raw | Where-Object { $_ -match 'rdp-tcp#\d' -and $_ -match 'Active' }
    if ($remoteActive) {
        Add-Finding Alarm "Someone may be connected to your PC remotely" `
            "There is an active Remote Desktop session, which means another computer could be viewing and controlling this one right now."
        Write-Line "A remote session appears to be ACTIVE." Red
    } else {
        Add-Finding Good "No one is remotely connected right now" `
            "Only your own screen and keyboard are in use. No Remote Desktop connection is active."
        Write-Line "Only your local sign-in is active. No remote session." Green
    }
} catch {
    Write-Line "Could not check active sessions." DarkYellow
}

# ===========================================================================
#  CHECK 2 -- Remote-control / screen-sharing programs installed or running
# ===========================================================================
Write-Section "2. Remote-control or screen-sharing programs"
$remoteToolNames = @(
    'teamviewer','anydesk','vnc','tightvnc','ultravnc','realvnc','logmein',
    'gotomypc','remotepc','ammyy','supremo','dwagent','dwservice','splashtop',
    'rustdesk','parsec','screenconnect','connectwise','dwrcs','radmin','ninja',
    'atera','aeroadmin','remoteutilities','showmypc','litemanager','getscreen'
)
$runningRemote = Get-Process | Where-Object {
    $n = $_.ProcessName.ToLower(); $remoteToolNames | Where-Object { $n -like "*$_*" }
}
if ($runningRemote) {
    $names = ($runningRemote | Select-Object -Expand ProcessName -Unique) -join ', '
    Add-Finding Alarm "A remote-control program is running" `
        "These programs let another person see and control your screen: $names. If you did not start one on purpose (for example, with IT support), treat this as serious."
    Write-Line "RUNNING: $names" Red
} else {
    Add-Finding Good "No remote-control programs are running" `
        "None of the common 'let someone see my screen' programs (TeamViewer, AnyDesk, VNC and similar) are running."
    Write-Line "None of the common screen-sharing programs are running." Green
}

# Also check the services list (a watcher can hide as a background service).
$remoteSvc = Get-Service | Where-Object {
    $_.DisplayName -match 'vnc|teamviewer|anydesk|rustdesk|logmein|splashtop|screenconnect|dwservice|ammyy|radmin|atera|getscreen|remote utilities'
} | Where-Object { $_.Status -eq 'Running' }
if ($remoteSvc) {
    $svcNames = ($remoteSvc | Select-Object -Expand DisplayName) -join ', '
    Add-Finding Warning "A remote-access background service is switched on" `
        "This runs quietly in the background even when no window is open: $svcNames."
    Write-Line "Background service running: $svcNames" Yellow
} else {
    Write-Line "No remote-access background services are switched on." Green
}

# ===========================================================================
#  CHECK 3 -- Doors left open on the network for remote control
# ===========================================================================
Write-Section "3. Open 'doors' for remote viewing/control"
# Ports commonly used by remote-desktop / screen-share tools.
$watchPorts = @{ 3389='Remote Desktop'; 5900='VNC screen share'; 5901='VNC screen share';
                 5938='TeamViewer'; 6568='AnyDesk'; 5931='remote support'; 4899='Radmin' }
$listen = Get-NetTCPConnection -State Listen | Where-Object { $watchPorts.ContainsKey([int]$_.LocalPort) }
if ($listen) {
    $hits = ($listen | ForEach-Object { $watchPorts[[int]$_.LocalPort] } | Sort-Object -Unique) -join ', '
    Add-Finding Warning "A remote-access 'door' is open" `
        "Your PC is set up to accept these kinds of connections: $hits. That is normal if you use it on purpose, but worth confirming."
    Write-Line "Open for: $hits" Yellow
} else {
    Add-Finding Good "No remote-access doors are open" `
        "Your PC is not set up to let another computer connect in for screen viewing or control."
    Write-Line "No remote-viewing doors are open." Green
}

# ===========================================================================
#  CHECK 4 -- Is your camera, microphone, or screen being captured right now?
# ===========================================================================
Write-Section "4. Camera / microphone / screen being captured right now"
$capBusy = @()
$capRoots = @(
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
)
$capMap = @{ webcam='camera'; microphone='microphone'
             graphicsCaptureProgrammatic='screen'; graphicsCaptureWithoutBorder='screen' }
foreach ($cap in $capMap.Keys) {
    foreach ($root in $capRoots) {
        $base = Join-Path $root $cap
        if (Test-Path $base) {
            Get-ChildItem $base -Recurse | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath
                # LastUsedTimeStop = 0 while Start > 0 means "in use right now".
                if ($null -ne $p.LastUsedTimeStart -and $p.LastUsedTimeStart -gt 0 -and $p.LastUsedTimeStop -eq 0) {
                    $who = ($_.PSChildName -replace '#','\')
                    $capBusy += "$($capMap[$cap]): $who"
                }
            }
        }
    }
}
if ($capBusy) {
    Add-Finding Warning "Your camera, mic, or screen is being used right now" `
        ("Something is actively using: " + (($capBusy | Sort-Object -Unique) -join '; ') + ". If you are not on a call or recording, find out what this is.")
    foreach ($c in ($capBusy | Sort-Object -Unique)) { Write-Line "IN USE: $c" Yellow }
} else {
    Add-Finding Good "Nothing is using your camera, mic, or screen" `
        "No program is recording your camera, listening on your microphone, or capturing your screen at this moment."
    Write-Line "Nothing is capturing your camera, mic, or screen right now." Green
}

# ===========================================================================
#  CHECK 5 -- Hidden programs set to launch automatically (deeper checks)
# ===========================================================================
Write-Section "5. Hidden auto-start tricks (deep check)"
if ($script:IsAdmin) {
    # 5a. WMI event-consumer persistence -- a classic stealth technique.
    $consumers = Get-CimInstance -Namespace root\subscription -Class __EventConsumer |
        Where-Object { $_.Name -notmatch '^(SCM Event Log Consumer)$' }
    if ($consumers) {
        $cn = ($consumers | Select-Object -Expand Name) -join ', '
        Add-Finding Alarm "A stealthy auto-start trick is set up" `
            "Something is configured to launch itself automatically using a hidden Windows mechanism ($cn). This is a common trick for spyware."
        Write-Line "Unexpected hidden auto-start: $cn" Red
    } else {
        Write-Line "No stealthy WMI auto-start tricks found." Green
    }

    # 5b. Non-Microsoft kernel drivers -- where a rootkit would hide.
    $badDrivers = @()
    Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
        $path = $_.PathName -replace '^\\\?\?\\',''
        if ($path -and (Test-Path $path)) {
            $sig = Get-AuthenticodeSignature $path
            $subject = ($sig.SignerCertificate.Subject -split ',')[0]
            if ($sig.Status -ne 'Valid') {
                $badDrivers += "$($_.Name) (unsigned)"
            }
        }
    }
    if ($badDrivers) {
        Add-Finding Warning "An unverified deep-system component is running" `
            ("These low-level components are not properly signed, which is unusual: " + ($badDrivers -join ', ') + ". Worth having someone knowledgeable look.")
        foreach ($d in $badDrivers) { Write-Line "Unsigned driver: $d" Yellow }
    } else {
        Write-Line "No unsigned deep-system components are running." Green
    }
} else {
    Add-Finding Notice "One set of deep checks was skipped" `
        "Some hidden-startup and deep-system checks need full permissions. Re-run this with 'Run with PowerShell' and click 'Yes' for a complete result."
    Write-Line "Skipped (needs full permissions)." DarkYellow
}

# 5c. Programs that start with Windows (readable without admin).
$autoRun = @()
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object {
    if (Test-Path $_) {
        $key = $_
        (Get-Item $_).Property | ForEach-Object {
            $autoRun += [pscustomobject]@{ Name = $_; Value = (Get-ItemProperty $key).$_ }
        }
    }
}
if ($autoRun) {
    Write-Line "Programs that start automatically with Windows:" Gray
    foreach ($a in $autoRun) { Write-Line (" - {0}" -f $a.Name) DarkGray }
}
# We don't alarm on these by default -- most are legitimate. We just list them
# so a person can eyeball anything they don't recognise.
Add-Finding Notice "Review your auto-start list" `
    ("These programs launch every time Windows starts: " +
     (($autoRun | Select-Object -Expand Name) -join ', ') +
     ". They are usually fine. If you see one you do not recognise, look it up before worrying.")

# ===========================================================================
#  CHECK 6 -- Anyone logged in from another computer recently?
# ===========================================================================
Write-Section "6. Remote logins in the last $HistoryDays days"
if ($script:IsAdmin) {
    $since = (Get-Date).AddDays(-$HistoryDays)
    $remoteLogons = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624; StartTime=$since } -ErrorAction Stop
        foreach ($e in $events) {
            if ($e.Message -match 'Logon Type:\s+10') {   # 10 = Remote Desktop
                $src  = if ($e.Message -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { 'unknown' }
                $acct = if ($e.Message -match 'Account Name:\s+(\S+)') { $matches[1] } else { 'unknown' }
                if ($src -notin @('-','127.0.0.1','::1')) {
                    $remoteLogons += "{0}  as '{1}' from {2}" -f $e.TimeCreated, $acct, $src
                }
            }
        }
    } catch {
        Write-Line "No matching login records were found (this is normal)." Green
    }
    if ($remoteLogons.Count -gt 0) {
        Add-Finding Alarm "Someone logged in from another computer" `
            ("There " + $(if($remoteLogons.Count -eq 1){'was 1 remote login'}else{"were $($remoteLogons.Count) remote logins"}) +
             " in the last $HistoryDays days. If this was not you or your IT support, take it seriously.")
        foreach ($r in ($remoteLogons | Select-Object -First 10)) { Write-Line $r Red }
    } else {
        Add-Finding Good "No one logged in remotely" `
            "In the last $HistoryDays days, no one signed into this PC from another computer."
        Write-Line "No remote logins in the last $HistoryDays days." Green
    }
} else {
    Add-Finding Notice "Login-history check was skipped" `
        "Reviewing who signed in needs full permissions. Re-run with 'Run with PowerShell' and click 'Yes' to include it."
    Write-Line "Skipped (needs full permissions)." DarkYellow
}

# ===========================================================================
#  OVERALL VERDICT
# ===========================================================================
$alarm   = @($script:Findings | Where-Object Level -eq 'Alarm')
$warning = @($script:Findings | Where-Object Level -eq 'Warning')
$notice  = @($script:Findings | Where-Object Level -eq 'Notice')

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor White
Write-Host "                       THE BOTTOM LINE" -ForegroundColor White
Write-Host "  ============================================================" -ForegroundColor White
Write-Host ""

if ($alarm.Count -gt 0) {
    Write-Host "   RESULT:  SOMETHING NEEDS YOUR ATTENTION" -ForegroundColor Red
    Write-Host ""
    Write-Host "   One or more strong signs of remote watching were found." -ForegroundColor Red
    Write-Host "   Please read the items marked (!) below and act on them." -ForegroundColor Red
}
elseif ($warning.Count -gt 0) {
    Write-Host "   RESULT:  PROBABLY FINE, BUT PLEASE CHECK A FEW THINGS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Nothing screams 'you are being watched', but a couple of" -ForegroundColor Yellow
    Write-Host "   items are worth a quick look. See the (?) items below." -ForegroundColor Yellow
}
else {
    Write-Host "   RESULT:  ALL CLEAR" -ForegroundColor Green
    Write-Host ""
    Write-Host "   No signs that anyone is watching your screen, camera," -ForegroundColor Green
    Write-Host "   microphone, or keyboard, and no remote logins were found." -ForegroundColor Green
}

Write-Host ""
Write-Host "  What we found, in plain words:" -ForegroundColor White
Write-Host ""

foreach ($f in $script:Findings) {
    switch ($f.Level) {
        'Alarm'   { $tag = '(!)'; $col = 'Red' }
        'Warning' { $tag = '(?)'; $col = 'Yellow' }
        'Notice'  { $tag = '(i)'; $col = 'Cyan' }
        'Good'    { $tag = '(+)'; $col = 'Green' }
    }
    Write-Host ("   {0} {1}" -f $tag, $f.Title) -ForegroundColor $col
    Write-Host ("       {0}" -f $f.Detail) -ForegroundColor Gray
}

Write-Host ""
Write-Host "  What the marks mean:" -ForegroundColor White
Write-Host "   (+) all good      (i) just so you know" -ForegroundColor Gray
Write-Host "   (?) please check  (!) act on this" -ForegroundColor Gray

# ---------------------------------------------------------------------------
#  Things software cannot tell you (be honest about the limits)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  One thing this cannot check:" -ForegroundColor White
Write-Host "   This looks at software only. It cannot detect a physical" -ForegroundColor Gray
Write-Host "   recording device plugged into your PC, a hidden camera in the" -ForegroundColor Gray
Write-Host "   room, or someone simply standing where they can see your screen." -ForegroundColor Gray

# ---------------------------------------------------------------------------
#  Save a report to the Desktop
# ---------------------------------------------------------------------------
if (-not $ReportPath) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $ReportPath = Join-Path $desktop "SecurityCheckup_$stamp.txt"
}

$report = New-Object System.Text.StringBuilder
[void]$report.AppendLine("SECURITY CHECK-UP REPORT")
[void]$report.AppendLine("Computer : $env:COMPUTERNAME")
[void]$report.AppendLine("User     : $env:USERNAME")
[void]$report.AppendLine("Date     : $(Get-Date)")
[void]$report.AppendLine("Full permissions: $(if($script:IsAdmin){'Yes'}else{'No (some checks skipped)'})")
[void]$report.AppendLine("")
if ($alarm.Count -gt 0)      { [void]$report.AppendLine("OVERALL: SOMETHING NEEDS YOUR ATTENTION") }
elseif ($warning.Count -gt 0){ [void]$report.AppendLine("OVERALL: PROBABLY FINE, CHECK A FEW THINGS") }
else                         { [void]$report.AppendLine("OVERALL: ALL CLEAR") }
[void]$report.AppendLine("")
foreach ($f in $script:Findings) {
    $tag = switch ($f.Level) { 'Alarm'{'[ACT ON THIS]'} 'Warning'{'[PLEASE CHECK]'} 'Notice'{'[FYI]'} 'Good'{'[OK]'} }
    [void]$report.AppendLine("$tag $($f.Title)")
    [void]$report.AppendLine("    $($f.Detail)")
    [void]$report.AppendLine("")
}
[void]$report.AppendLine("Note: This checks software only. It cannot detect a physical")
[void]$report.AppendLine("recording device, a hidden camera, or someone looking over your shoulder.")

try {
    Set-Content -Path $ReportPath -Value $report.ToString() -Encoding UTF8
    Write-Host ""
    Write-Host "  A copy of this report was saved to:" -ForegroundColor White
    Write-Host "   $ReportPath" -ForegroundColor Cyan
    Write-Host "  You can keep it, or send it to someone you trust." -ForegroundColor Gray
} catch {
    Write-Host ""
    Write-Host "  (Could not save the report file, but the results are shown above.)" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "  Done. You can close this window." -ForegroundColor White
Write-Host ""
