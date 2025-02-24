# 🛡️ Threat Hunt Report: Identifying Exposed VMs & Brute-Force Attempts

  ![image](https://github.com/user-attachments/assets/c12801c4-5097-4215-94ee-1826abb699af)


## 📝 Summary of Findings

**Overview:**  
The machine **windows-target-1** has been internet-facing for several months, making it a potential target for external threat actors. Recent investigations revealed multiple unauthorized login attempts from various IP addresses, suggesting an attempted brute-force attack. However, **no successful logins** were recorded from the suspicious IPs.

---

## 🔍 Timeline Summary and Findings

### 🟡 Step 1: Confirming Internet-Facing Status

To assess exposure, we checked whether `windows-target-1` had been internet-facing.

```kql
DeviceInfo
| where DeviceName == "windows-target-1" and IsInternetFacing == true
| order by Timestamp desc
```

**Findings:**  
- The machine has been publicly accessible for an extended period.  
- **Last online instance:** `2025-02-09T15:08:29.1188735Z`  

*Implication:*  
An internet-facing machine increases the risk of external attacks, making it a likely target for unauthorized access attempts.

---

### 🟠 Step 2: Identifying Failed Login Attempts

To analyze authentication attempts, we filtered unsuccessful logins from external IPs.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1" 
| where ActionType != "LogonSuccess" and RemoteIPType != "Private" and ActionType != "LogonAttempted"
| summarize Attempts = count() by DeviceName, RemoteIP, ActionType
| order by Attempts
```

**Findings:**  
- Multiple failed login attempts from **several different external IP addresses**.  
- These attempts were likely part of a **brute-force attack**, attempting different credentials.  

  ![image](https://github.com/user-attachments/assets/c12801c4-5097-4215-94ee-1826abb699af)

*Implication:*  
Repeated login failures from various IPs strongly indicate that attackers were attempting to gain access through credential guessing.

---

### 🔴 Step 3: Confirming No Successful Logins from Suspicious IPs

To ensure that none of the most active malicious IPs successfully logged in, we ran the following query:

```kql
let RemoteIPsInQuestion = dynamic(["89.248.172.39","88.214.25.111", "45.141.84.154", "77.90.185.223", "194.0.234.31"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**Findings:**  
- None of the top **5 IPs** responsible for most failed attempts were able to authenticate successfully.  
- The **only successful logins (57 in the last 30 days)** were from recognized sources.  

*Implication:*  
- The attack **did not succeed**, indicating that account security measures (password policies, monitoring) were effective.  
- The pattern of failed logins aligns with **brute-force attempts** rather than a one-time credential guess.  

---

## 📖 MITRE ATT&CK Techniques Mapped

The observed activities align with multiple MITRE ATT&CK techniques:

| **Tactic**         | **Technique (ID)**     | **Description** |
|------------------|---------------------|----------------|
| **Initial Access** | `T1078` - Valid Accounts | Checking for unauthorized successful logins. |
| **Credential Access** | `T1110` - Brute Force | Repeated failed login attempts indicate brute-force activity. |
| **Discovery** | `T1040` - Network Sniffing | Potential probing responses from attackers. |
| **Lateral Movement** | `T1021` - Remote Services | Logins attempted via remote access. |
| **Reconnaissance** | `T1595` - Active Scanning | Internet-exposed target likely probed for weaknesses. |

---

## 🛑 Response Actions Taken

To mitigate future risks, the following security measures have been implemented:

1. **Hardened Network Security Group (NSG):**  
   - Configured NSG to restrict traffic only to approved IP addresses.  
   - Eliminated unnecessary public exposure of the machine.  

2. **Implemented Account Lockout Policy:**  
   - Set a **maximum failed login threshold** to block repeated brute-force attempts.  
   - Enforced password complexity requirements to prevent easy credential guessing.  

3. **Multi-Factor Authentication (MFA) Enforcement:**  
   - Enabled **MFA for all remote access attempts** to prevent unauthorized logins even if credentials are compromised.  

---

## 🔐 Conclusion

The investigation confirms that **brute-force login attempts occurred but were unsuccessful**.  
- The machine remained internet-facing for an extended period, making it a **target for external attacks**.  
- Security enhancements, such as **restricting NSG rules and implementing MFA**, significantly reduced the attack surface.  
- No evidence of **compromised credentials or successful unauthorized access** was found.

📌 **Recommendations:**  
✅ **Continue monitoring** authentication logs for unusual patterns.  
✅ **Regularly review NSG and firewall rules** to minimize exposure.  
✅ **Educate users on password security** and ensure compliance with company policies.  

---

**📌 Author:** Rasheed Jimoh  
**📅 Date:** February 24, 2025  
**🔐 Focus Area:** Threat Hunting & Security Monitoring  

---

*© Rasheed Jimoh. All rights reserved.* 🚀🔐
