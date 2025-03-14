## MITRE ATT&CK Mapping: Tactics, Techniques, and Tools

The following table maps the tactics, techniques, and tools used in this attack to the **MITRE ATT&CK framework**, providing insights into the attack methodology and how each technique was applied.

| **Tactic** | **Technique** | **MITRE ID** | **Description & How It Was Used** | **Tools Used** |
|------------|--------------|-------------|----------------------------------|--------------|
| **Initial Access** | User Execution | [T1204](https://attack.mitre.org/techniques/T1204/) | The victim was tricked into opening a malicious `.RAR` file (`SANS SEC401.rar`) received via Telegram. The file contained an executable disguised as a `.PDF`, leading to the execution of malicious commands. | WinRAR, Telegram |
| **Execution** | Command and Scripting Interpreter (PowerShell) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | The attacker used `run.ps1` to execute commands and perform reconnaissance. This script also encoded data in Base64 and sent it to an external server. | PowerShell |
| **Persistence** | Scheduled Task/Job | [T1053](https://attack.mitre.org/techniques/T1053/) | The attacker likely leveraged scheduled tasks to ensure the execution of malicious scripts upon system reboot. | Task Scheduler (Potentially used but not yet confirmed) |
| **Privilege Escalation** | Bypass User Account Control (UAC) | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | The attacker executed PowerShell with `-NOP -EP Bypass` flags, allowing scripts to run with fewer restrictions. | PowerShell |
| **Defense Evasion** | Indicator Removal on Host (Clearing Logs) | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | The script `Eventlogs.ps1` executed log-clearing commands, removing evidence from Windows Event Logs. | Eventlogs.ps1, PowerShell |
| **Discovery** | Network Service Scanning | [T1046](https://attack.mitre.org/techniques/T1046/) | The `run.ps1` script scanned for online machines in the network by pinging IP addresses and storing results. | PowerShell |
| **Collection** | Data Staging | [T1074](https://attack.mitre.org/techniques/T1074/) | The attacker stored scan results in `BL4356.txt` before encoding them for exfiltration. | PowerShell |
| **Exfiltration** | Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | The attacker encoded the contents of `BL4356.txt` in Base64 and exfiltrated it using an HTTP GET request to `http://192.168.1.5:8000/`. | PowerShell |

