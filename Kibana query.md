## Kibana Search Queries Cheatsheet (KQL)

* ### File Encryption query looks for events where a file is modified or written to with an unusual file extension, such as .locked or .encrypted.
```
index_name:Winlogbeat-* AND event_data.ObjectName:*.??????* AND event_data.AccessMask:0x10000 AND event_data.AccessList:(S,AD)
```
* ### System Process Modification: (query looks for events where the Command Prompt, PowerShell, or Rundll32.exe is used to modify system files)
```
index_name:Winlogbeat-* AND (event_data.Image:*\\cmd.exe OR event_data.Image:*\\powershell.exe OR event_data.Image:*\\rundll32.exe) AND (event_data.Details:*-s* OR event_data.Details:*-r*)
```
* ### Changes to System Settings:(query searches for events where the Registry Editor or Reg.exe is used to modify the shell or userinit registry key)
```
index_name:Winlogbeat-* AND (event_data.Image:*\\reg.exe OR event_data.Image:*\\regedit.exe) AND event_data.ObjectName:*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon AND (event_data.Details:*Shell* OR event_data.Details:*Userinit*)
```
* ### Access to Network Shares:(query looks for events where a file or folder is accessed with an unusual access mask or access list)
```
index_name:Winlogbeat-* AND event_data.ObjectName:*\*\*.* AND event_data.AccessMask:0x2019f AND event_data.AccessList:*(S,AD)
```
* ### Attempts to Disable Security Tools:(query looks for events where common command-line tools like Wmic.exe, Sc.exe, or Net.exe are used to stop or disable security)
```
index_name:Winlogbeat-* AND (event_data.Image:*\\wmic.exe OR event_data.Image:*\\sc.exe OR event_data.Image:*\\net.exe) AND (event_data.CommandLine:*stop* OR event_data.CommandLine:*disable*)
```
* ### Suspicious Network Connections:(query looks for events where PowerShell or Command Prompt is used to create a network connection using suspicious cmdlets, such as New-Object, Invoke-WebRequest)
```
index_name:Winlogbeat-* AND (event_data.Image:*\\powershell.exe OR event_data.Image:*\\cmd.exe) AND (event_data.Details:*New-Object* OR event_data.Details:*Invoke-WebRequest* OR event_data.Details:*Invoke-RestMethod*) AND event_data.DestinationIp:* AND event_data.DestinationPort:*
```
* ### Unusual Process Creation:(query looks for events where a new process is created, particularly by Command Prompt or PowerShell)
```
index_name:Winlogbeat-* AND event_id:4688 AND (event_data.Image:*\\cmd.exe OR event_data.Image:*\\powershell.exe) AND NOT event_data.Image:*\\System32\\* AND NOT event_data.Image:*\\Windows\\*
```
* ### Suspicious Registry Modification:(query looks for events where a registry key is modified to add a new run key, which can be used to execute malware or ransomware at system startup)
```
index_name:Winlogbeat-* AND event_id:4657 AND event_data.ObjectName:*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run AND event_data.SecurityDescriptor:*S-1-5-18* AND event_data.SecurityDescriptor:*RDP-Tcp*
```

* ### File Encryption:(query looks for events where a user has modified the access control list (ACL) of a Microsoft Word document)
```
index_name:Winlogbeat-* AND event_id:4663 AND event_data.AccessMask:0x20000 AND event_data.ObjectType:*\\File AND event_data.ObjectName:*\\*.docx AND event_data.SubjectUserName:*
```

* ### Unusual File Deletion:(query looks for events where a user has deleted a file with a “.encrypted” extension)
```
index_name:Winlogbeat-* AND event_id:4663 AND event_data.AccessMask:0x10000 AND event_data.ObjectType:*\\File AND event_data.ObjectName:*\\.encrypted AND event_data.SubjectUserName:*
```
* ### Suspicious PowerShell Activity:(query looks for events where PowerShell is used to execute suspicious cmdlets, such as Get-Random, Write-Output, Get-ChildItem, Invoke-WebRequest)
```
index_name:Winlogbeat-* AND event_id:4103 AND event_data.ScriptBlockText:*Get-Random* AND event_data.ScriptBlockText:*Write-Output* AND event_data.ScriptBlockText:*Get-ChildItem* AND event_data.ScriptBlockText:*Invoke-WebRequest* AND event_data.ScriptBlockText:*Invoke-RestMethod*
```
* ### Suspicious Scheduled Task Creation:(query looks for events where a scheduled task is created with a name that contains “ransom”, “encrypt”, or “decrypt”.)
```
index_name:Winlogbeat-* AND event_id:4698 AND event_data.TaskName:*\\ransom* OR event_data.TaskName:*\\encrypt* OR event_data.TaskName:*\\decrypt*
```
* ### Suspicious Registry Key Creation:(query looks for events where a registry key is created or modified under the “Run” key in the Windows registry.)
```
index_name:Winlogbeat-* AND (event_id:12 OR event_id:13) AND (event_data.KeyPath:*\\Microsoft\\Windows\\CurrentVersion\\Run* OR event_data.KeyPath:*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*)
```
* ### Suspicious Network Connections:(query looks for events where a suspicious network connection is made from the system.)
```
index_name:Winlogbeat-* AND (event_id:3 OR event_id:5156 OR event_id:5158 OR event_id:5159) AND (event_data.DestinationIp:192.168.0.0/16 OR event_data.DestinationIp:10.0.0.0/8 OR event_data.DestinationIp:172.16.0.0/12 OR event_data.DestinationIp:0.0.0.0/0) AND (NOT event_data.DestinationIp:192.168.0.0/16 AND NOT event_data.DestinationIp:10.0.0.0/8 AND NOT event_data.DestinationIp:172.16.0.0/12)
```
* ### Suspicious PowerShell Child Processes:(query looks for events where PowerShell is used to execute suspicious child processes. It searches for events with event IDs 4688 or 4103)
```
index_name:Winlogbeat-* AND (event_id:4688 OR event_id:4103) AND (event_data.ParentCommandLine:*powershell.exe* OR event_data.NewProcessName:powershell.exe) AND (event_data.NewProcessCommandLine:*-EncodedCommand* OR event_data.NewProcessCommandLine:*-ep* OR event_data.NewProcessCommandLine:*-Encoded* OR event_data.NewProcessCommandLine:*-NoProfile* OR event_data.NewProcessCommandLine:*-w* OR event_data.NewProcessCommandLine:*-WindowStyle*)
```
