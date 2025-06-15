<#
.SYNOPSIS
    Collect environmental information useful for troubleshooting.

.DESCRIPTION
    This script collects network ETL trace, Windows event logs, performance monitor metrics,
    and other Windows Server information. It is designed to assist in diagnosing issues by
    gathering relevant system and network data during a reproduction scenario.

.AUTHOR
    Alexis Touet

.VERSION
    v0.3
#>

# Step 0: Check for Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

# Step 1: Prompt for user selection
Write-Host "`nPlease select what option you would like to perform:"
Write-Host "1. Collect system info and Windows event logs"
Write-Host "2. Start network and performance traces, and collect only these traces"
Write-Host "3. Both options 1 and 2"
$selection = Read-Host "Enter your choice (1, 2, or 3)"

$doSystemInfo = $false
$doTraces = $false

switch ($selection.ToLower()) {
    "1" { $doSystemInfo = $true }
    "2" { $doTraces = $true }
    "3" { $doSystemInfo = $true; $doTraces = $true }
    default {
        Write-Host "Invalid selection. Exiting." -ForegroundColor Red
        exit
    }
}

# Ask how many days of event logs to collect (only if system info is selected)
$logDays = 1
if ($doSystemInfo) {
    do {
        $logDaysInput = Read-Host "How many days of Windows event logs would you like to collect?"
        if ($logDaysInput -match '^[0-9]+$') {
            $logDays = [int]$logDaysInput
        } else {
            Write-Host "Please enter a valid number of days (e.g., 1, 3, 7)." -ForegroundColor Yellow
        }
    } while ($logDaysInput -notmatch '^[0-9]+$')
}

# Step 2: Create MSTraces_<timestamp> folder on a non-C drive if available
Write-Host "`n[Step 2] Creating MSTraces folder..."
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }
$logDrive = $drives | Where-Object { $_.Name -ne "C" } | Select-Object -First 1
if (-not $logDrive) {
    $logDrive = $drives | Where-Object { $_.Name -eq "C" } | Select-Object -First 1
}
$logPath = "$($logDrive.Name):\MSTraces_$timestamp"
New-Item -Path $logPath -ItemType Directory -Force | Out-Null

# Step 3: Collect System Information
if ($doSystemInfo) {
    Write-Host "`n[Step 3] Collecting system information..."
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
    $cpuCores = (Get-WmiObject Win32_Processor).NumberOfCores
    $vCores = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
    $ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)

    $webproxy = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
    $proxyEnabled = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable
    $winhttpProxy = netsh winhttp show proxy | Out-String

    # Windows version and build
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
    $buildMap = @{
        # Windows 10
        10240 = 'Windows 10 Version 1507 (RTM)'
        10586 = 'Windows 10 Version 1511 (November Update)'
        14393 = 'Windows 10 Version 1607 (Anniversary Update)'
        15063 = 'Windows 10 Version 1703 (Creators Update)'
        16299 = 'Windows 10 Version 1709 (Fall Creators Update)'
        17134 = 'Windows 10 Version 1803 (April 2018 Update)'
        17763 = 'Windows 10 Version 1809 (October 2018 Update)'
        18362 = 'Windows 10 Version 1903 (May 2019 Update)'
        18363 = 'Windows 10 Version 1909 (November 2019 Update)'
        19041 = 'Windows 10 Version 2004 (May 2020 Update)'
        19042 = 'Windows 10 Version 20H2 (October 2020 Update)'
        19043 = 'Windows 10 Version 21H1 (May 2021 Update)'
        19044 = 'Windows 10 Version 21H2 (November 2021 Update)'
        19045 = 'Windows 10 Version 22H2 (October 2022 Update)'
        # Windows 11
        22000 = 'Windows 11 Version 21H2 (October 2021 RTM)'
        22621 = 'Windows 11 Version 22H2 (September 2022 Update)'
        22631 = 'Windows 11 Version 23H2 (October 2023 Update)'
        26100 = 'Windows 11 Version 24H2 (October 2024 Update)'
        # Windows Server
        7601  = 'Windows Server 2008 R2 SP1'
        9200  = 'Windows Server 2012'
        9600  = 'Windows Server 2012 R2'
        14393 = 'Windows Server 2016'
        17763 = 'Windows Server 2019'
        20348 = 'Windows Server 2022'
        25398 = 'Windows Server 2025 (Preview)'
    }

    if ($buildMap.ContainsKey($buildMajor)) {
        $winName = $buildMap[$buildMajor]
    } else {
        $winName = "Unknown build ($buildMajor)"
    }

    # .NET version
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
    $sysInfo | Out-File "$logPath\SystemInfo.txt"
}

# Step 4: Start Traces
if ($doTraces) {
    Write-Host "`n[Step 4] Enabling CAPI2 event log..."
    wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true

    Write-Host "`n[Step 5] Starting performance monitor..."
    $perfmonName = "Perfmon_$timestamp"
    $perfLog = "$logPath\$perfmonName.blg"
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

    Write-Host "`n[Step 6] Starting network trace..."
    $traceFile = "$logPath\Trace_$env:COMPUTERNAME_$timestamp.etl"
    netsh trace start scenario=netconnection,internetclient capture=yes report=yes overwrite=yes maxsize=4096 tracefile="$traceFile" provider="Microsoft-Windows-NDIS" keywords=0xffffffffffffffff level=0xff provider="Microsoft-Windows-TCPIP" keywords=0x80007fff000000ff level=0x5 provider="{EB004A05-9B1A-11D4-9123-0050047759BC}" keywords=0x3ffff level=0x5 provider="Microsoft-Windows-Winsock-AFD" keywords=0x800000000000003f level=0x5 provider="{B40AEF77-892A-46F9-9109-438E399BB894}" keywords=0xffffffffffffffff level=0xff

    Write-Host "`n[Step 7] Monitoring in progress. Type 'stop' to end monitoring..."
    do {
        $input = Read-Host "Type 'stop' to end monitoring"
    } while ($input -ne "stop")

    Write-Host "Stopping monitoring... Please wait while logs are being collected."

    Write-Host "`n[Step 8] Stopping traces..."
    logman stop $perfmonName
    netsh trace stop

    Write-Host "`n[Step 9] Disabling CAPI2 event log..."
    wevtutil sl Microsoft-Windows-CAPI2/Operational /e:false
}

# Step 5: Export Windows Event Logs
if ($doSystemInfo) {
    Write-Host "`n[Step 10] Exporting Windows event logs..."
    $logs = @("Application", "System", "Security")
    if ($doTraces) {
        $logs += "Microsoft-Windows-CAPI2/Operational"
    }
    $timeFilter = $logDays * 86400000
    foreach ($log in $logs) {
        $safeName = $log -replace '[\\/]', '_'
        $logFile = "$logPath\\${safeName}_$timestamp.evtx"
        if (Test-Path $logFile) { Remove-Item $logFile -Force }
        wevtutil epl $log "$logFile" /q:"*[System[TimeCreated[timediff(@SystemTime) <= $timeFilter]]]"
    }
}

# Step 6: Final Check
Write-Host "`n[Step 11] Verifying saved logs..."
$expectedFiles = @()

if ($doSystemInfo) {
    $expectedFiles += "$logPath\\SystemInfo_$timestamp.txt"
    $expectedFiles += "$logPath\\Application_$timestamp.evtx", "$logPath\\System_$timestamp.evtx", "$logPath\\Security_$timestamp.evtx"
    if ($doTraces) {
        $expectedFiles += "$logPath\\Microsoft-Windows-CAPI2_Operational_$timestamp.evtx"
    }
}

if ($doTraces) {
    $perfmonFiles = Get-ChildItem -Path $logPath -Filter "$perfmonName*.blg"
    foreach ($file in $perfmonFiles) {
        if ($file -ne $null) {
            $expectedFiles += $file.FullName
        }
    }
    $expectedFiles += "$traceFile"
}

$missing = @()
foreach ($file in $expectedFiles) {
    if ($file -and -not (Test-Path $file)) {
        $missing += $file
    }
}

if ($missing.Count -eq 0) {
    Write-Output "`n✅ All logs and traces saved to $logPath"
} else {
    Write-Output "`n❌ Error: The following files were not saved successfully:"
    $missing | ForEach-Object { Write-Output "- $_" }
}
