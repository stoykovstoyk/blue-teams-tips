# Hunting Logic for Windows Event Logs

This document provides a list of important Windows Event Logs and Sysmon Event IDs that can be used for threat hunting. These events are crucial for detecting suspicious activities and malicious behavior on Windows systems.

## Event Log Table

| **Event Type**                    | **Event ID** |
|------------------------------------|--------------|
| Process Creation (Sysmon)          | 1            |
| Network Connections (Sysmon)       | 3            |
| Image Loads (Sysmon)               | 7            |
| File Creation (Sysmon)             | 11           |
| Registry Events (Sysmon)           | 13           |
| PowerShell Script Blocks           | 4104         |
| Process Creation                   | 4688         |
| Scheduled Task Creation            | 4698         |
| Service Creation                   | 7045         |

## Description of Event Types

1. **Process Creation (Sysmon - Event ID 1)**
   - Monitors when a process is created. Can help identify potentially malicious processes spawned by attackers.

2. **Network Connections (Sysmon - Event ID 3)**
   - Tracks network connections initiated by processes. Useful for detecting unauthorized communication or C2 traffic.

3. **Image Loads (Sysmon - Event ID 7)**
   - Logs the loading of image files. Useful for identifying suspicious or unexpected DLLs or executables being loaded.

4. **File Creation (Sysmon - Event ID 11)**
   - Detects when a file is created. Can be useful to track unexpected files being written to disk.

5. **Registry Events (Sysmon - Event ID 13)**
   - Logs changes made to the registry, which can help in identifying persistence mechanisms or modifications to system configuration.

6. **PowerShell Script Blocks (Event ID 4104)**
   - Tracks PowerShell script blocks executed on the system. Crucial for detecting malicious PowerShell scripts, a common method for attack execution.

7. **Process Creation (Event ID 4688)**
   - This Windows native event tracks when a new process is created, valuable for identifying any suspicious activity at the process level.

8. **Scheduled Task Creation (Event ID 4698)**
   - Monitors when a new scheduled task is created. Attackers often create scheduled tasks for persistence and later stages of their attack.

9. **Service Creation (Event ID 7045)**
   - Logs when a new service is created. Malicious actors might create services to run their payloads or persist on the system.

## Usage

These Event IDs can be monitored and analyzed using SIEM solutions, Sysmon, and other logging tools to help detect abnormal activities. Threat hunters can correlate data from these events to identify potential threats like process injection, lateral movement, persistence mechanisms, or unauthorized network activity.

By utilizing these Windows Event Logs, defenders can gain visibility into system activity and quickly respond to potential intrusions.
