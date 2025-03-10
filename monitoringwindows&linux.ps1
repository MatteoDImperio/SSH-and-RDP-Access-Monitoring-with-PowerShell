# Operating System Detection
$OS = $PSVersionTable.Platform  # More reliable method for PowerShell Core

# Use custom variables to avoid conflicts with system variables
$IsLinuxCustom = $false
$IsWindowsCustom = $false

if ($OS -eq "Unix") {
    $IsLinuxCustom = $true
    $IsWindowsCustom = $false
} else {
    $IsLinuxCustom = $false
    $IsWindowsCustom = $true
}

# Log file setup
if ($IsLinuxCustom) {
    $logFile = "/tmp/access.log"
    if (!(Test-Path $logFile)) {
        New-Item -Path $logFile -ItemType File -Force | Out-Null
        chmod 600 $logFile  # Protects the file on Linux
    }
} elseif ($IsWindowsCustom) {
    $logFile = "C:\Windows\Temp\access.log"
    if (!(Test-Path $logFile)) {
        New-Item -Path $logFile -ItemType File -Force | Out-Null
        attrib +h $logFile  # Hides the file on Windows
    }
} else {
    Write-Host "Unsupported operating system!"
    exit
}

# Startup message compatible with all PowerShell versions
if ($IsLinuxCustom) {
    Write-Host "[INFO] Monitoring active on Linux. Waiting for events..." -ForegroundColor Cyan
} else {
    Write-Host "[INFO] Monitoring active on Windows. Waiting for events..." -ForegroundColor Cyan
}

$lastEvent = ""

while ($true) {
    if ($IsLinuxCustom) {
        # Linux Monitoring (SSH)
        if (Test-Path "/var/log/auth.log") {
            $logFilePath = "/var/log/auth.log"
        } elseif (Test-Path "/var/log/secure") {
            $logFilePath = "/var/log/secure"
        } else {
            Write-Host "[ERROR] Authentication log not found. Check log location on Kali." -ForegroundColor Red
            exit
        }
        
        $linuxLogs = Get-Content $logFilePath -Tail 50
        foreach ($line in $linuxLogs) {
            if ($line -match "sshd.*Accepted") {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $userName = ($line -split " ")[8]
                $ipAddress = ($line -split " ")[10]
                $message = "$timestamp - LOGIN: User $userName connected via SSH from $ipAddress"
                $message | Out-File -Append -FilePath $logFile
                Write-Host "[INFO] $message" -ForegroundColor Green
            } elseif ($line -match "sshd.*Failed password") {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $userName = ($line -split " ")[8]
                $ipAddress = ($line -split " ")[10]
                $message = "$timestamp - WARNING: Failed login attempt for $userName from $ipAddress"
                $message | Out-File -Append -FilePath $logFile
                Write-Host "[ALERT] $message" -ForegroundColor Red
            }
        }
    } elseif ($IsWindowsCustom) {
        # Windows Monitoring (RDP)
        $events = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647)]]" -ErrorAction SilentlyContinue
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $eventID = $xml.Event.System.EventID
            $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            $userName = $xml.Event.EventData.Data[5].'#text'
            $ipAddress = $xml.Event.EventData.Data[-3].'#text'
            
            if ($lastEvent -ne "$userName-$eventID-$timestamp") {
                $lastEvent = "$userName-$eventID-$timestamp"
                
                if ($eventID -eq 4624) {
                    $message = "$timestamp - LOGIN: User $userName connected from $ipAddress"
                } elseif ($eventID -eq 4625) {
                    $message = "$timestamp - WARNING: Failed login attempt for $userName from $ipAddress"
                } elseif ($eventID -eq 4634 -or $eventID -eq 4647) {
                    $message = "$timestamp - LOGOUT: User $userName disconnected"
                }
                
                $message | Out-File -Append -FilePath $logFile
                Write-Host "[INFO] $message" -ForegroundColor Green
            }
        }
    }
    
    Start-Sleep -Seconds 5
}
