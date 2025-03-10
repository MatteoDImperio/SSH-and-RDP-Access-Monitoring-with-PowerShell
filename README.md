# SSH-and-RDP-Access-Monitoring-with-PowerShell
This PowerShell script monitors remote access on Linux and Windows systems, logging both successful logins and failed attempts.
The goal is to provide a lightweight and easy-to-use monitoring system to track SSH connections (on Linux) and RDP connections (on Windows).
The results are saved in a log file and displayed on the screen with color-coded messages for better readability.



Functionality

1. Detecting the Operating System
The script determines whether it is running on Linux or Windows using:
$OS = $PSVersionTable.Platform

If $OS is "Unix", the system is Linux.
Otherwise, it is considered Windows.

To avoid conflicts with system variables, custom variables are used:

$IsLinuxCustom = $false
$IsWindowsCustom = $false
These are then set based on the detected system.

2. Log File Setup
The log file is created in different locations depending on the operating system:
Linux: /tmp/accessi.dat
Windows: C:\Windows\Temp\accessi.dat

If the file does not exist, it is created using:
New-Item -Path $logFile -ItemType File -Force | Out-Null

On Linux, restrictive permissions are set to protect the file:
chmod 600 $logFile

On Windows, the file is hidden for added security:
attrib +h $logFile

3. Monitoring Access
The script starts an infinite loop to check for access attempts every 5 seconds.

Linux (SSH Monitoring)
The script checks for the most common authentication log files:

if (Test-Path "/var/log/auth.log") {
    $logFilePath = "/var/log/auth.log"
} elseif (Test-Path "/var/log/secure") {
    $logFilePath = "/var/log/secure"
}

It then reads the last 50 lines of the file to detect successful logins and failed attempts:
$linuxLogs = Get-Content $logFilePath -Tail 50

If a line contains "sshd.*Accepted", a successful login is logged:
if ($line -match "sshd.*Accepted") {
    $userName = ($line -split " ")[8]
    $ipAddress = ($line -split " ")[10]
    $message = "$timestamp - LOGIN: User $userName connected via SSH from $ipAddress"
}
If it contains "sshd.*Failed password", a failed access attempt is recorded.



Windows (RDP Monitoring)
On Windows, security events are read using Get-WinEvent:
$events = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647)]]"

Where:
4624 → Successful login
4625 → Failed login attempt
4634 / 4647 → Logout

The data is extracted in XML format to retrieve details such as username and IP address:

$xml = [xml]$event.ToXml()
$userName = $xml.Event.EventData.Data[5].'#text'
$ipAddress = $xml.Event.EventData.Data[-3].'#text'

If the event is new, it is logged and displayed on the screen.


4. Pausing Between Checks

The script waits 5 seconds before repeating the check:
Start-Sleep -Seconds 5

This reduces resource usage while ensuring important events are not missed.


Issues Encountered
Permission Issues with System Logs
On Linux, the script must be run with administrator privileges to access logs (sudo pwsh script.ps1).
On Windows, some events may only be accessible with an administrative account.

Log File Locations on Linux
The log file location may vary depending on the distribution (/var/log/auth.log on Ubuntu, /var/log/secure on CentOS).
The script may need modification to suit specific systems.


Conclusion
This script provides a basic level of monitoring for remote access on Linux and Windows.For more advanced use, it could be enhanced with:
Sending notifications (e.g., email or Telegram) for suspicious access attempts.

The script can be easily customized to meet specific security needs. 
