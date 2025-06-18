<#
.DESCRIPTION
    Interactive Windows troubleshooting helper that saves all collected data
    into a time-stamped folder of your choice.

    ── What does it collect?
      • System information snapshot (.txt)
      • Windows event logs (.evtx)
      • Network ETL trace (.etl)
      • Performance Monitor log (.blg)

    ── How does it work?
      At launch you pick one of three scenarios:

        ▸ Scenario 1 – System info and Event Logs only  
          Collects system-info plus windows Application, System and Security logs
          from the last seven days.  (No tracing.)

        ▸ Scenario 2 – Traces only  
          Starts a high-level network ETL trace together with lightweight
          PerfMon counters while you reproduce the issue, then stops and saves
          the trace.  (No windows event logs or system-info export.)

        ▸ Scenario 3 – Traces + Event Logs (including CAPI2 Log)  
          Enables the CAPI2 windows event log, runs the same trace and
          PerfMon session as Scenario 2, then additionally exports all items
          from Scenario 1 once tracing stops.  This is the most extended
          capture.

      All output is written to “MSTraces_<yyyyMMdd-HHmmss>” under the base
      folder you specify.

.SYNOPSIS
    Collect Windows diagnostics for one of three scenarios:
      1) System info and Event Logs only, 2) live traces, or 3) combined live traces + Event logs(including CAPI2 Log).

.AUTHOR
    Alexis Touet

.VERSION
    v0.7
#>

###########################################################################
# Quick-start summary                                                      #
###########################################################################
function Show-ScriptSummary {
    param()

    Write-Host ""
    Write-Host " Windows Troubleshooting Data Collector  v0.7" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────────────────────────────"
    Write-Host "▪ Scenario 1  –  System info + Application / System / Security" `
               "logs from the last 7 days."
    Write-Host "▪ Scenario 2  –  Live network ETL trace + lightweight PerfMon."
    Write-Host "▪ Scenario 3  –  Scenario 2 trace PLUS CAPI2 log and all items" `
               "from Scenario 1 (full capture)."
    Write-Host ""
    Write-Host "All output is saved to a time-stamped sub-folder called" `
               "'MSTraces_<yyyyMMdd-HHmmss>' under the base path you choose."
    Write-Host "───────────────────────────────────────────────────────────────"
    Write-Host ""
}

# Show the banner right away
Show-ScriptSummary


# Step 0: Check for Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

# Step 1: Prompt for user selection (Three Scenarios)
Write-Host "`nPlease select what option you would like to perform:"
Write-Host "1. Scenario 1: Collect system info and Windows event logs"
Write-Host "2. Scenario 2: Collect network trace and performance monitor whilst reproducing an issue"
Write-Host "3. Scenario 3: Collect network trace + CAPI2 log + performance monitor whilst reproducing an issue, then collect Windows event logs and system info"
$selection = Read-Host "Enter your choice (1, 2, or 3)"

$doSystemInfo = $false
$doTraceOnly = $false
$doTraceAndLogs = $false

switch ($selection.ToLower()) {
    "1" { $doSystemInfo = $true }
    "2" { $doTraceOnly = $true }
    "3" { $doTraceAndLogs = $true }
    default {
        Write-Host "Invalid selection. Exiting." -ForegroundColor Red
        exit
    }
}

# Step 2: Ask user where to save logs (mandatory input)
Write-Host "`n[Step 2] Please specify the base folder where logs should be saved."
Write-Host "Example: C:\Temp\Traces"

do {
    $basePath = Read-Host "Enter the base folder path"
    if ([string]::IsNullOrWhiteSpace($basePath)) {
        Write-Host "❌ Path cannot be empty. Please enter a valid folder path." -ForegroundColor Red
        $basePath = $null
        continue
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logPath = Join-Path $basePath "MSTraces_$timestamp"

    try {
        if (-not (Test-Path $logPath)) {
            Write-Host "Creating directory: $logPath"
            New-Item -Path $logPath -ItemType Directory -Force | Out-Null
        }
        Write-Host "✅ Logs will be saved to: $logPath" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to create or access the directory: $_" -ForegroundColor Red
        $logPath = $null
    }
} while (-not $logPath)

# Step 3: Scenario 1 - System Info and Event Logs
if ($doSystemInfo) {
    $logDays = 7
    Write-Host "`n[Step 3] Collecting system information..."
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
    $cpuCores = (Get-WmiObject Win32_Processor).NumberOfCores
    $vCores = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
    $ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $webproxy = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
    $proxyEnabled = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable
    $winhttpProxy = netsh winhttp show proxy | Out-String
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    try {
        $reg = Get-ItemProperty -Path $regPath -ErrorAction Stop
    } catch {
        Write-Error "Failed to read registry path ${regPath}: $_"
        return
    }
    [int]$buildMajor = 0
    [int]$buildRevision = 0
    if ($reg.PSObject.Properties.Name -contains 'CurrentBuildNumber') {
        $buildMajor = [int]$reg.CurrentBuildNumber
    }
    if ($reg.PSObject.Properties.Name -contains 'UBR') {
        $buildRevision = [int]$reg.UBR
    }
    $versionObj = [System.Environment]::OSVersion.Version
    [int]$major = $versionObj.Major
    [int]$minor = $versionObj.Minor
    $fullBuild = "$major.$minor.$buildMajor.$buildRevision"
    $winName = "Build $buildMajor"
    $dotnet = $null
    try {
        $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name InstallPath,Release -ErrorAction Stop
        $dotnet = switch -regex ($reg.Release) {
            "378389" { "4.5" }
            "378675|378758" { "4.5.1" }
            "379893" { "4.5.2" }
            "393295|393297" { "4.6" }
            "394254|394271" { "4.6.1" }
            "394802|394806" { "4.6.2" }
            "460798|460805" { "4.7" }
            "461308|461310" { "4.7.1" }
            "461808|461814" { "4.7.2" }
            "528040|528049" { "4.8" }
            "533320" { "4.8.1" }
            {$_ -gt 533320} { "Newer than 4.8.1+" }
        }
    } catch {
        $dotnet = "Not found"
    }
    $firewall = netsh advfirewall show allprofiles | Out-String
    $programs = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object { $_.DisplayName }
    $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName
    $sysInfo = @"
IP Address: $ip
CPU Cores: $cpuCores
vCores: $vCores
RAM: $ram GB
IE Proxy Server: $webproxy
Proxy Enabled: $proxyEnabled
WinHTTP Proxy Settings:
$winhttpProxy
Windows Version: $winName
Full Build: $fullBuild
.NET Version: $dotnet
Firewall:
$firewall
Antivirus: $($antivirus.displayName)
Installed Programs:
$($programs | Format-Table | Out-String)
"@
    $sysInfo | Out-File "$logPath\SystemInfo_$timestamp.txt"
}

# Step 4: Scenario 2 and 3 - Tracing
if ($doTraceOnly -or $doTraceAndLogs) {
    $perfmonName = "Perfmon_$timestamp"
    $perfLog = "$logPath\$perfmonName.blg"
    $traceFile = "$logPath\Trace_$env:COMPUTERNAME_$timestamp.etl"

    if ($doTraceAndLogs) {
        Write-Host "`n[Step 4] Enabling CAPI2 event log..."
        wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true
    }

    do {
        $startInput = Read-Host "Type 'start' when you're ready to begin tracing"
    } while ($startInput.ToLower() -ne "start")

    if (logman query $perfmonName -ets > $null 2>&1) {
        logman delete $perfmonName -ets
    }
    logman create counter $perfmonName `
        -counters "\Processor(_Total)\% Processor Time" `
                  "\Memory\Available MBytes" `
                  "\Memory\Committed Bytes" `
                  "\PhysicalDisk(_Total)\% Idle Time" `
                  "\PhysicalDisk(_Total)\Current Disk Queue Length" `
        -f bin -o "$perfLog" -si 00:00:05
    logman start $perfmonName

    netsh trace start scenario=netconnection,internetclient capture=yes overwrite=yes maxsize=4096 filemode=circular tracefile="$traceFile" `
        provider="Microsoft-Windows-NDIS" keywords=0xffffffffffffffff level=0xff `
        provider="Microsoft-Windows-TCPIP" keywords=0x80007fff000000ff level=0x5 `
        provider="{EB004A05-9B1A-11D4-9123-0050047759BC}" keywords=0x3ffff level=0x5 `
        provider="Microsoft-Windows-Winsock-AFD" keywords=0x800000000000003f level=0x5 `
        provider="{B40AEF77-892A-46F9-9109-438E399BB894}" keywords=0xffffffffffffffff level=0xff

    do {
        $stopInput = Read-Host "Type 'stop' when you're done reproducing the issue"
    } while ($stopInput.ToLower() -ne "stop")

    Write-Host "`nStopping Perfmon and ETL trace..."
    logman stop $perfmonName
    netsh trace stop

    if ($doTraceAndLogs) {
        Write-Host "`nDisabling CAPI2 event log..."
        wevtutil sl Microsoft-Windows-CAPI2/Operational /e:false
    }

    Write-Host "`n✅ Tracing complete. Logs saved to: $logPath" -ForegroundColor Green
}

# Step 5: Export Windows Event Logs
if ($doSystemInfo -or $doTraceAndLogs) {
    Write-Host "`n[Step 5] Exporting Windows event logs..."
    $logs = @("Application", "System", "Security")
    if ($doTraceAndLogs) {
        $logs += "Microsoft-Windows-CAPI2/Operational"
    }
    $logDays = 7
    $timeFilter = $logDays * 86400000
    foreach ($log in $logs) {
        $safeName = $log -replace '[\\/]', '_'
        $logFile = "$logPath\${safeName}_$timestamp.evtx"
        if (Test-Path $logFile) { Remove-Item $logFile -Force }
        wevtutil epl $log "$logFile" /q:"*[System[TimeCreated[timediff(@SystemTime) <= $timeFilter]]]"
    }
}

# Step 6: Final Check
Write-Host "`n[Step 6] Verifying saved logs..."
$expectedFiles = @()
if ($doSystemInfo) {
    $expectedFiles += Join-Path $logPath "SystemInfo_$timestamp.txt"
    $expectedFiles += Join-Path $logPath "Application_$timestamp.evtx"
    $expectedFiles += Join-Path $logPath "System_$timestamp.evtx"
    $expectedFiles += Join-Path $logPath "Security_$timestamp.evtx"
}
if ($doTraceAndLogs) {
    $expectedFiles += Join-Path $logPath "Microsoft-Windows-CAPI2_Operational_$timestamp.evtx"
    $expectedFiles += $traceFile
    $expectedFiles += $perfLog
}
if ($doTraceOnly) {
    $expectedFiles += $traceFile
    $expectedFiles += $perfLog
}

$missing = @()
foreach ($file in $expectedFiles) {
    $folder = Split-Path $file
    $pattern = [System.IO.Path]::GetFileNameWithoutExtension($file)
    $extension = [System.IO.Path]::GetExtension($file)
    $match = Get-ChildItem -Path $folder -Filter "*$pattern*$extension" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $match) {
        $missing += $file
    }
}

if ($missing.Count -eq 0) {
    Write-Host "`n✅ ALL LOGS AND TRACES SAVED TO: $logPath" -ForegroundColor Green
} else {
    Write-Host "`n❌ ERROR: The following files were not saved correctly:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
}
