## Indicators of Compromise (IOCs)

### **1. Malicious Files & Hashes**

| **File Name**            | **File Path**                                                 | **MD5**                                      | **SHA-256**                                  |
|--------------------------|--------------------------------------------------------------|----------------------------------------------|----------------------------------------------|
| `SANS SEC401.pdf .cmd`   | `C:\cases\SpottedInTheWild\SANS SEC401.pdf .cmd`          | `74900dd2a29cd5eebcc259f0265c8425`          | `5790225b1bcfa692c57a0914dd78678ceef6e212fbe7042b7ddf5a06fd4ab70d` |
| `BL4356.txt`             | `C:\Users\Administrator\AppData\Local\Temp\BL4356.txt` | `f778c5a62ee2598618f8c2992596da2d`          | `ace607318bba614ead615d2d8d9671c1fc2cf7a26c53eefe4e226f8a06246e04` |
| `run.bat`                | `C:\Windows\Temp\run.bat`                                | `c77601154a2dc23af91ecbdfbe3f124a`          | `f11e1927a12b0bf6bc41b4ea1363b45aa8b5d194737d4bb00f537956e2725324` |
| `run.ps1`                | `C:\Windows\Temp\run.ps1`                                | `d5391cd780949cf6cead24d7e6b0e3ba`          | `771c29efb71da4459e130cf8df363849c26c8a2ea69bcbdcce2f1809a02f075a` |

### **2. IP Addresses & Domains**

| **IP Address**           | **Purpose** |
|--------------------------|------------|
| `172.18.35.10:8000`      | Malicious server hosting second-stage malware. |
| `192.168.1.5:8000`       | Attacker-controlled exfiltration server. |

### **3. URLs Used for Exfiltration**

| **URL**                                      | **Purpose** |
|----------------------------------------------|------------|
| `http://172.18.35.10:8000/amanwhogetsnorest.jpg` | Downloading the second-stage malware. |
| `http://192.168.1.5:8000/{Base64-encoded data}` | Exfiltrating network scan results. |

