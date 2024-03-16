# PowerShell 7.4 Reference
https://learn.microsoft.com/en-us/powershell/?view=powershell-7.4

# List of simple commands that can be combined into other various scripts

# Get system inventory
Get-CimInstance -ClassName Win32_ComputerSystem

# Get installed software
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# Get disk space
Get-PSDrive -PSProvider FileSystem

# Create a new user
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName jdoe -UserPrincipalName jdoe@example.com

# Add a user to a group
Add-ADGroupMember -Identity "GroupName" -Members jdoe

# List all users in a domain
# In some cases, you might need to import the module manually before using its cmdlets
Import-Module ActiveDirectory
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
Get-ADUser -Filter * -Properties Name, SamAccountName, Enabled, LastLogonDate | Select-Object Name, SamAccountName, Enabled, LastLogonDate
Get-ADUser -Filter * -Properties Name, SamAccountName, Enabled, LastLogonDate, Mail, UserPrincipalName, AccountExpirationDate, PasswordLastSet, LockedOut, whenCreated, Department, Title, Manager, physicalDeliveryOfficeName | Select-Object Name, SamAccountName, Enabled, LastLogonDate, Mail, UserPrincipalName, AccountExpirationDate, PasswordLastSet, LockedOut, whenCreated, Department, Title, Manager, physicalDeliveryOfficeName

# Get IP address information
Get-NetIPAddress
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like '*Ethernet*' -or $_.InterfaceAlias -like '*Wi-Fi*' -or $_.InterfaceAlias -like '*Wireless*' } | Select-Object InterfaceAlias, IPAddress, PrefixLength

# Get DNS server addresses for Ethernet and WiFi interfaces
Get-DnsClientServerAddress | Where-Object { $_.InterfaceAlias -like '*Ethernet*' -or $_.InterfaceAlias -like '*Wi-Fi*' } | Select-Object InterfaceAlias, ServerAddresses

# Test network connection
Test-Connection google.com

# List all open ports
# On the fence a little regarding this command. netstat is an invaluable tool and is cross platform, but requires piping to other applications, that makes it less efficient and harder to maintain automation code
# However, on Windows this basic cmdlet can lead to detection and automation of connections
Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" }

# List all running services
Get-Service | Where-Object { $_.Status -eq "Running" }

# Seeking a specific service name
Get-Service | Where-Object { $_.Name -eq "BadService" -and $_.Status -eq "Running" }

# Stop Start a service
Stop-Service -Name "ServiceName", Start-Service -Name "ServiceName"

# Kill a process
Get-Process -Name "ProcessName" | Stop-Process

# Create a new directory
New-Item -Path 'C:\NewFolder' -ItemType Directory

# Copy files
copy-Item -Path "C:\NewFolder\file.txt" -Destination "C:\destination"

# Delete files oder than 30 days
Get-ChildItem -Path "D:\old_reports" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-60) } | Remove-Item

# Last 50 recent for System events 
Get-EventLog -LogName System -Newest 50

# Lets search for connections to RDP
# Event ID 4624: Indicates a successful logon
Get-EventLog -LogName Security | Where-Object { $_.EventID -eq 4625 -and $_.Message -match "Logon Type:\s+10" }

# Lets search for connections to RDP
# Event ID 4625: Indicates a failed logon attempt
Get-EventLog -LogName Security | Where-Object { $_.EventID -eq 4624 -and $_.Message -match "Logon Type:\s+10" }

# Retrieves all events from the Security log with Event ID 4624 for the last 2 hours
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-2)}

# Export event logs
Get-EventLog -LogName Application | Export-Csv -Path C:\logs\application_logs.csv

# Monitor real-time events
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 50

# Create a system backup
# Operating System, System Settings, Installed Applications, System Files, User Data
# To D:\Backups
Backup-WindowsImage -Online -TargetPath "D:\Backups\MySystemBackup.wim"

# Restore a file from backup
# Boot Into Windows Recovery Environment (Windows RE), Access Command Prompt
# Use DISM to Apply the Image
dism /Apply-Image /ImageFile:D:\Backups\MySystemBackup.wim /Index:1 /ApplyDir:C:\

# Schedule tasks
# Define the action to run a PowerShell script
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-File "C:\Scripts\MyScript.ps1"'

# Define the trigger for daily execution at 8:00 AM
$trigger = New-ScheduledTaskTrigger -Daily -At 8am

# Register the scheduled task
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "RunMyScriptDaily" -Description "Runs MyScript.ps1 every day at 8:00 AM"

# Verify if an update is installed and write computer names to a file
$A = Get-Content -Path ./Servers.txt
$A | ForEach-Object { if (!(Get-HotFix -Id KB5022289 -ComputerName $_))
    { Add-Content $_ -Path ./Missing-KB5022289.txt }}


# Set file permissions
Get-Acl "C:\path\file.txt" | Set-Acl "C:\new\path\file.txt"

# "AUser" with Modify permissions
$aUser = "AUser"
$aUserRights = [System.Security.AccessControl.FileSystemRights]::Modify
$aUserAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($aUser, $aUserRights, 'Allow')

# "BUser" with Full Control permissions
$bUser = "BUser"
$bUserRights = [System.Security.AccessControl.FileSystemRights]::FullControl
$bUserAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($bUser, $bUserRights, 'Allow')
