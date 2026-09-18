<#
================================================================================
  Guardian.ps1
--------------------------------------------------------------------------------
  A resident intruder guard for a SINGLE-PERSON HOME PC.

  The assumption for a home PC is simple: nobody should ever be logging into or
  controlling this machine from somewhere else. So Guardian watches for remote
  access in near-real-time and, by default, ACTS ON IT AUTOMATICALLY --
  disconnects the remote session, kills the remote-control program, stops the
  remote-access service, and firewalls the source IP.

  Because you sit physically at this PC, auto-eviction is safe for you: you keep
  your own keyboard and screen no matter what it blocks. The one genuinely risky
  action -- disabling a user account -- is OFF by default and, even if you turn
  it on, Guardian will NEVER disable the account currently signed in at the
  console (you).

  --------------------------------------------------------------------------------
  EVERYTHING IS ON BY DEFAULT. Out of the box this is fully automatic.
  If you ever want it to only watch and warn, run with:  -Mode Monitor
  --------------------------------------------------------------------------------

  ONE FILE. It is the monitor AND its own installer.

    Run it now, in this window (foreground):
        right-click -> Run with PowerShell (as admin)

    Make it resident (starts at every boot, runs as SYSTEM):
        .\Guardian.ps1 -Install

    Check / remove the resident task:
        .\Guardian.ps1 -Status
        .\Guardian.ps1 -Uninstall

    Watch once and exit (for testing):
        .\Guardian.ps1 -Once

  HONEST LIMITS:
    Guardian catches commodity remote access -- a forgotten AnyDesk, an RDP
    login from a strange IP, a screen-share service left running. It is NOT an
    antivirus/EDR and cannot reliably evict kernel-level malware or a rootkit.
    Keep a real antivirus alongside it; treat Guardian as a tripwire.
================================================================================
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    # ---- What Guardian does when it finds remote access --------------------
    # Aggressive = evict automatically (DEFAULT, fully automatic).
    # Monitor    = watch + alert only, change nothing.
    [ValidateSet('Aggressive','Monitor')]
    [string]$Mode = 'Aggressive',

    # ---- Response actions (ALL ON by default, except disableAccount) -------
    [bool]$DisconnectRdpSessions = $true,
    [bool]$StopRemoteServices    = $true,
    [bool]$KillRemotePrograms    = $true,
    [bool]$FirewallBlockSourceIp = $true,
    # OFF by default: the only action that can lock you out. Even when $true,
    # Guardian never disables the console (currently signed-in) user.
    [bool]$DisableAccount        = $false,

    # ---- Alerts ------------------------------------------------------------
    [bool]$ToastAlerts    = $true,
    [bool]$EventLogAlerts = $true,

    # ---- Tuning ------------------------------------------------------------
    [int]$PollSeconds = 20,

    # Source IPs that are NEVER treated as intruders. For a single-person home
    # PC this is just loopback -- even LAN remote access is unexpected.
    [string[]]$AllowIpRanges = @('127.0.0.1','::1'),

    # Remote-control tools you use ON PURPOSE (process-name fragments, no .exe).
    # Empty by default: a home PC normally runs none of these.
    [string[]]$AllowPrograms = @(),

    # Where logs/state go.
    [string]$DataDir,

    # ---- Run modes ---------------------------------------------------------
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$Once,

    [string]$TaskName = 'Guardian'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir  = Split-Path -Parent $ScriptPath
if (-not $DataDir) { $DataDir = Join-Path $env:ProgramData 'Guardian' }
if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
$LogFile = Join-Path $DataDir 'guardian.log'

$script:IsAdmin =
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Deny-list of known remote-control / screen-share tools (process-name fragments).
$script:DenyPrograms = @(
    'teamviewer','anydesk','vnc','tightvnc','ultravnc','realvnc','logmein',
    'gotomypc','remotepc','ammyy','supremo','dwagent','dwservice','splashtop',
    'rustdesk','parsec','screenconnect','connectwise','dwrcs','radmin',
    'aeroadmin','remoteutilities','showmypc','litemanager','getscreen'
)

# ---------------------------------------------------------------------------
#  Logging + notification
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [ValidateSet('INFO','DETECT','ACTION','WARN','ERROR')][string]$Level = 'INFO',
        [string]$Message
    )
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) {
        'DETECT' { 'Yellow' } 'ACTION' { 'Red' } 'WARN' { 'DarkYellow' }
        'ERROR'  { 'Magenta' } default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}

function Ensure-EventSource {
    if (-not $script:IsAdmin) { return }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('Guardian')) {
            [System.Diagnostics.EventLog]::CreateEventSource('Guardian','Application')
        }
    } catch { }
}

function Send-Notice {
    param(
        [string]$Title,
        [string]$Message,
        [ValidateSet('Info','Warning','Error')][string]$Kind = 'Warning'
    )
    if ($EventLogAlerts) {
        try {
            $etype = switch ($Kind) { 'Error' {'Error'} 'Warning' {'Warning'} default {'Information'} }
            Write-EventLog -LogName Application -Source 'Guardian' -EventId 7001 `
                -EntryType $etype -Message "$Title`n$Message"
        } catch { }
    }
    if ($ToastAlerts) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $ni = New-Object System.Windows.Forms.NotifyIcon
            $ni.Icon = [System.Drawing.SystemIcons]::Shield
            $ni.Visible = $true
            $tipIcon = switch ($Kind) { 'Error' {'Error'} 'Warning' {'Warning'} default {'Info'} }
            $ni.ShowBalloonTip(8000, $Title, $Message, $tipIcon)
            Start-Sleep -Milliseconds 200
        } catch { }
    }
}

# ---------------------------------------------------------------------------
#  Allowlist helpers
# ---------------------------------------------------------------------------
function Test-IpInRange {
    param([string]$Ip, [string]$Range)
    if ([string]::IsNullOrWhiteSpace($Ip) -or [string]::IsNullOrWhiteSpace($Range)) { return $false }
    if ($Ip -eq $Range) { return $true }
    try {
        if ($Range -notmatch '/') {
            return ([System.Net.IPAddress]::Parse($Ip)).Equals([System.Net.IPAddress]::Parse($Range))
        }
        $parts   = $Range.Split('/')
        $netAddr = [System.Net.IPAddress]::Parse($parts[0])
        $prefix  = [int]$parts[1]
        $ipAddr  = [System.Net.IPAddress]::Parse($Ip)
        if ($ipAddr.AddressFamily -ne $netAddr.AddressFamily) { return $false }

        $ipBytes  = $ipAddr.GetAddressBytes()
        $netBytes = $netAddr.GetAddressBytes()
        $bits = $prefix
        for ($i = 0; $i -lt $ipBytes.Length; $i++) {
            if ($bits -le 0) { break }
            $take = [Math]::Min(8, $bits)
            $mask = [byte](0xFF -shl (8 - $take) -band 0xFF)
            if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask)) { return $false }
            $bits -= 8
        }
        return $true
    } catch { return $false }
}

function Test-IpAllowed {
    param([string]$Ip)
    foreach ($r in @($AllowIpRanges)) { if (Test-IpInRange -Ip $Ip -Range $r) { return $true } }
    return $false
}

function Test-ProgramAllowed {
    param([string]$ProcName)
    $n = $ProcName.ToLower()
    foreach ($p in @($AllowPrograms)) { if ($p -and $n -like "*$($p.ToLower())*") { return $true } }
    return $false
}

function Test-ProgramDenied {
    param([string]$ProcName)
    $n = $ProcName.ToLower()
    foreach ($p in $script:DenyPrograms) { if ($n -like "*$($p.ToLower())*") { return $true } }
    return $false
}

function Get-ConsoleUser {
    # The account signed in at the physical console -- the one we must never lock out.
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.UserName) { return ($cs.UserName -split '\\')[-1] }
    } catch { }
    return $env:USERNAME
}

# ---------------------------------------------------------------------------
#  Response actions -- gated by $Mode and the per-action switches
# ---------------------------------------------------------------------------
function Should-Act { return $Mode -eq 'Aggressive' }

function Invoke-DisconnectRdp {
    param([string]$SessionId, [string]$Reason)
    if (-not $DisconnectRdpSessions) { Write-Log WARN "DisconnectRdpSessions off; not acting ($Reason)"; return }
    if (-not $script:IsAdmin) { Write-Log WARN "Not admin; cannot disconnect RDP session ($Reason)"; return }
    try {
        & tsdiscon.exe $SessionId 2>$null
        Write-Log ACTION "Disconnected RDP session $SessionId. Reason: $Reason"
        Send-Notice -Title 'Guardian: remote session disconnected' -Message $Reason -Kind Error
    } catch {
        Write-Log ERROR "Failed to disconnect RDP session ${SessionId}: $($_.Exception.Message)"
    }
}

function Invoke-StopService {
    param([string]$ServiceName, [string]$Reason)
    if (-not $StopRemoteServices) { Write-Log WARN "StopRemoteServices off; not acting ($Reason)"; return }
    if (-not $script:IsAdmin) { Write-Log WARN "Not admin; cannot stop service $ServiceName ($Reason)"; return }
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        Write-Log ACTION "Stopped service '$ServiceName'. Reason: $Reason"
        Send-Notice -Title 'Guardian: remote-access service stopped' -Message "$ServiceName -- $Reason" -Kind Error
    } catch {
        Write-Log ERROR "Failed to stop service '$ServiceName': $($_.Exception.Message)"
    }
}

function Invoke-KillProcess {
    param($Process, [string]$Reason)
    if (-not $KillRemotePrograms) { Write-Log WARN "KillRemotePrograms off; not acting ($Reason)"; return }
    try {
        Stop-Process -Id $Process.Id -Force -ErrorAction Stop
        Write-Log ACTION "Killed process '$($Process.ProcessName)' (PID $($Process.Id)). Reason: $Reason"
        Send-Notice -Title 'Guardian: remote-control program stopped' -Message "$($Process.ProcessName) -- $Reason" -Kind Error
    } catch {
        Write-Log ERROR "Failed to kill process '$($Process.ProcessName)': $($_.Exception.Message)"
    }
}

function Invoke-FirewallBlockIp {
    param([string]$Ip, [string]$Reason)
    if (-not $FirewallBlockSourceIp) { Write-Log WARN "FirewallBlockSourceIp off; not acting ($Reason)"; return }
    if (-not $script:IsAdmin) { Write-Log WARN "Not admin; cannot firewall $Ip ($Reason)"; return }
    if ([string]::IsNullOrWhiteSpace($Ip) -or $Ip -in @('-','unknown')) { return }
    $ruleName = "Guardian block $Ip"
    try {
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block `
                -RemoteAddress $Ip -Profile Any -ErrorAction Stop | Out-Null
            Write-Log ACTION "Firewall now blocks inbound from $Ip. Reason: $Reason"
            Send-Notice -Title 'Guardian: source IP blocked' -Message "$Ip -- $Reason" -Kind Error
        }
    } catch {
        Write-Log ERROR "Failed to add firewall block for ${Ip}: $($_.Exception.Message)"
    }
}

function Invoke-DisableAccount {
    param([string]$Account, [string]$Reason)
    if (-not $DisableAccount) { return }
    if (-not $script:IsAdmin) { Write-Log WARN "Not admin; cannot disable account $Account"; return }
    # Never disable the account signed in at the console -- that would lock YOU out.
    $console = Get-ConsoleUser
    if ($Account -ieq $console) {
        Write-Log WARN "Refusing to disable '$Account': it is the console (signed-in) user."
        return
    }
    try {
        Disable-LocalUser -Name $Account -ErrorAction Stop
        Write-Log ACTION "Disabled local account '$Account'. Reason: $Reason"
        Send-Notice -Title 'Guardian: account disabled' -Message "$Account -- $Reason" -Kind Error
    } catch {
        Write-Log ERROR "Could not disable account '$Account': $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
#  Detectors -- each returns threat objects
#  threat = @{ Kind; Detail; Account; SourceIp; Process; Service; SessionId }
# ---------------------------------------------------------------------------
function Get-RemoteSessionThreats {
    $threats = @()
    try {
        $raw = (& qwinsta.exe 2>$null)
        foreach ($line in ($raw | Select-Object -Skip 1)) {
            if ($line -match 'rdp-tcp#\d' -and $line -match 'Active') {
                $sid = if ($line -match '\s(\d+)\s+Active') { $matches[1] } else { $null }
                $threats += [pscustomobject]@{
                    Kind='RdpSession'; Detail=("Active Remote Desktop session ($line)").Trim()
                    Account=$null; SourceIp=$null; Process=$null; Service=$null; SessionId=$sid
                }
            }
        }
    } catch { }
    return $threats
}

function Get-RemoteToolThreats {
    $threats = @()
    try {
        foreach ($proc in (Get-Process)) {
            if (Test-ProgramDenied -ProcName $proc.ProcessName) {
                $threats += [pscustomobject]@{
                    Kind='RemoteToolProcess'; Detail="Remote-control program running: $($proc.ProcessName)"
                    Account=$null; SourceIp=$null; Process=$proc; Service=$null; SessionId=$null
                }
            }
        }
    } catch { }
    return $threats
}

function Get-RemoteServiceThreats {
    $threats = @()
    try {
        Get-Service | Where-Object {
            $_.Status -eq 'Running' -and
            $_.DisplayName -match 'vnc|teamviewer|anydesk|rustdesk|logmein|splashtop|screenconnect|dwservice|ammyy|radmin|atera|getscreen|remote utilities'
        } | ForEach-Object {
            $threats += [pscustomobject]@{
                Kind='RemoteService'; Detail="Remote-access service running: $($_.DisplayName)"
                Account=$null; SourceIp=$null; Process=$null; Service=$_; SessionId=$null
            }
        }
    } catch { }
    return $threats
}

function Get-RemoteLogonThreats {
    param([datetime]$Since)
    $threats = @()
    if (-not $script:IsAdmin) { return $threats }
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624; StartTime=$Since } -ErrorAction Stop
        foreach ($e in $events) {
            if ($e.Message -match 'Logon Type:\s+10') {
                $src  = if ($e.Message -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { 'unknown' }
                $acct = if ($e.Message -match 'Account Name:\s+(\S+)')          { $matches[1] } else { 'unknown' }
                if ($src -in @('-','127.0.0.1','::1')) { continue }
                $threats += [pscustomobject]@{
                    Kind='RemoteLogon'; Detail="Remote logon as '$acct' from $src at $($e.TimeCreated)"
                    Account=$acct; SourceIp=$src; Process=$null; Service=$null; SessionId=$null
                }
            }
        }
    } catch { }
    return $threats
}

# ---------------------------------------------------------------------------
#  Classify + respond
# ---------------------------------------------------------------------------
function Resolve-Threat {
    param($Threat)

    # Allowlist: if this is something you permitted, note it and stop.
    $allowed = $false; $why = ''
    switch ($Threat.Kind) {
        'RemoteToolProcess' {
            if (Test-ProgramAllowed -ProcName $Threat.Process.ProcessName) { $allowed=$true; $why='program on allowlist' }
        }
        'RemoteLogon' {
            if (Test-IpAllowed -Ip $Threat.SourceIp) { $allowed=$true; $why='source IP on allowlist' }
        }
    }
    if ($allowed) { Write-Log INFO "ALLOWED ($why): $($Threat.Detail)"; return }

    # Real detection.
    Write-Log DETECT $Threat.Detail
    Send-Notice -Title 'Guardian: possible intrusion detected' -Message $Threat.Detail -Kind Warning

    if (-not (Should-Act)) {
        Write-Log INFO "Mode is 'Monitor' -- alert only, no action taken."
        return
    }

    switch ($Threat.Kind) {
        'RemoteToolProcess' {
            Invoke-KillProcess -Process $Threat.Process -Reason $Threat.Detail
        }
        'RemoteLogon' {
            Invoke-FirewallBlockIp -Ip $Threat.SourceIp -Reason $Threat.Detail
            Invoke-DisableAccount  -Account $Threat.Account -Reason $Threat.Detail
        }
        'RdpSession' {
            if ($Threat.SessionId) { Invoke-DisconnectRdp -SessionId $Threat.SessionId -Reason $Threat.Detail }
        }
        'RemoteService' {
            Invoke-StopService -ServiceName $Threat.Service.Name -Reason $Threat.Detail
        }
    }
}

function Invoke-Pass {
    $since = (Get-Date).AddMinutes(-2)
    $threats = @()
    $threats += Get-RemoteSessionThreats
    $threats += Get-RemoteToolThreats
    $threats += Get-RemoteServiceThreats
    $threats += Get-RemoteLogonThreats -Since $since
    foreach ($t in $threats) {
        try { Resolve-Threat -Threat $t } catch { Write-Log ERROR "Error handling threat: $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
#  Install / Uninstall / Status  (this single file is its own installer)
# ---------------------------------------------------------------------------
function Show-Status {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        Write-Host "Guardian task is INSTALLED." -ForegroundColor Green
        Write-Host "  State         : $($task.State)"
        Write-Host "  Last run time : $($info.LastRunTime)"
        Write-Host "  Last result   : $($info.LastTaskResult)"
        Write-Host "  Next run time : $($info.NextRunTime)"
    } else {
        Write-Host "Guardian task is NOT installed." -ForegroundColor Yellow
    }
}

function Install-Guardian {
    if (-not $script:IsAdmin) {
        Write-Host "Install must be run as Administrator. Right-click the file -> Run with PowerShell, click Yes." -ForegroundColor Red
        return
    }
    Write-Host "Installing Guardian as a resident scheduled task (runs as SYSTEM, at every boot)..." -ForegroundColor Cyan

    $psExe   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argLine = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""

    $action    = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -WorkingDirectory $ScriptDir
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero)

    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Write-Host "Replacing existing Guardian task." -ForegroundColor Yellow
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description 'Resident intruder guard for a single-person home PC (Guardian.ps1).' | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "Installed and started -- no reboot needed." -ForegroundColor Green
        Write-Host "  Logs : $LogFile" -ForegroundColor Gray
        Write-Host "  Mode : Aggressive (fully automatic). Run with -Mode Monitor to only watch." -ForegroundColor Gray
        Write-Host "  Stop : .\Guardian.ps1 -Uninstall" -ForegroundColor DarkGray
    } catch {
        Write-Host "Install failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Uninstall-Guardian {
    if (-not $script:IsAdmin) {
        Write-Host "Uninstall must be run as Administrator." -ForegroundColor Red
        return
    }
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { Write-Host "Guardian task is not installed. Nothing to remove." -ForegroundColor Yellow; return }
    try {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed Guardian task. It is no longer resident." -ForegroundColor Green
        Write-Host "(Any firewall block rules named 'Guardian block ...' remain; remove them in Windows Defender Firewall if you like.)" -ForegroundColor Gray
    } catch {
        Write-Host "Failed to remove task: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===========================================================================
#  ENTRY POINT
# ===========================================================================
if ($Status)    { Show-Status;        return }
if ($Uninstall) { Uninstall-Guardian; return }
if ($Install)   { Install-Guardian;   return }

Ensure-EventSource
Write-Log INFO "Guardian starting. Mode=$Mode. Admin=$($script:IsAdmin). Data=$DataDir"
if (-not $script:IsAdmin) {
    Write-Log WARN "Running WITHOUT admin -- remote-logon detection and most actions are limited. Use -Install to run resident as SYSTEM."
}
if ($Mode -eq 'Aggressive') {
    Write-Log INFO "Fully automatic: detected remote access will be evicted (sessions dropped, tools killed, services stopped, source IPs blocked)."
} else {
    Write-Log INFO "Monitor mode: watching and alerting only. Nothing will be changed."
}

# Near-real-time: subscribe to new 4624 events so remote logons are caught instantly.
$logonSub = $null
if ($script:IsAdmin -and -not $Once) {
    try {
        $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
            'Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName,
            '*[System[(EventID=4624)]]')
        $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($q)
        $logonSub = Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -Action {
            try {
                $rec = $Event.SourceEventArgs.EventRecord
                $msg = $rec.FormatDescription()
                if ($msg -match 'Logon Type:\s+10') {
                    $src  = if ($msg -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { 'unknown' }
                    $acct = if ($msg -match 'Account Name:\s+(\S+)')          { $matches[1] } else { 'unknown' }
                    if ($src -notin @('-','127.0.0.1','::1')) {
                        Resolve-Threat -Threat ([pscustomobject]@{
                            Kind='RemoteLogon'; Detail="LIVE remote logon as '$acct' from $src"
                            Account=$acct; SourceIp=$src; Process=$null; Service=$null; SessionId=$null
                        })
                    }
                }
            } catch { }
        }
        $watcher.Enabled = $true
        Write-Log INFO "Live logon watcher active (Security 4624)."
    } catch {
        Write-Log WARN "Could not start live logon watcher; polling only: $($_.Exception.Message)"
    }
}

if ($Once) {
    Invoke-Pass
    Write-Log INFO "Single pass complete (-Once). Exiting."
    return
}

try {
    while ($true) {
        Invoke-Pass
        $sleep = if ($PollSeconds -lt 5) { 5 } else { $PollSeconds }
        Start-Sleep -Seconds $sleep
    }
} finally {
    if ($logonSub) { Unregister-Event -SubscriptionId $logonSub.Id -ErrorAction SilentlyContinue }
    Write-Log INFO "Guardian stopped."
}
