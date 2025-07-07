# Risk Assessment

This document presents a **comprehensive qualitative risk assessment** of all assets identified in the Asset Register for the simulated e-commerce environment. The assessment is performed under the assumption of **zero mitigation controls**, in alignment with ISO 27001 and best practices. Each asset is assessed based on its potential threats, vulnerabilities, and associated risks. Risk ratings are calculated using a **standardized matrix**, and actionable mitigation recommendations are provided.

---
# Compliance Mapping

This risk assessment is aligned with the ISO/IEC 27001:2022 standard. Relevant clauses and controls covered include:
1. Clause 6.1.2 – Information Security Risk Assessment  
2. Clause 6.1.3 – Risk Treatment and Control Selection  
3. Annex A Controls – Addressed through:  
    - A.5 – Information Security Policies  
    - A.6 – Organization of Information Security  
    - A.9 – Access Control  
    - A.12 – Operations Security  
    - A.13 – Communications Security  
    - A.14 – System Acquisition, Development and Maintenance  
    - A.18 – Compliance  

The assessment methodology also references ISO/IEC 27005 for industry-accepted risk calculation and evaluation best practices.

## Risk Rating Matrix

The following matrix defines risk levels by combining the **Likelihood** of an event with its **Impact**:

| Likelihood ↓ \ Impact → | Low    | Medium | High     |
| ----------------------- | ------ | ------ | -------- |
| Low                     | Low    | Low    | Medium   |
| Medium                  | Low    | Medium | High     |
| High                    | Medium | High   | Critical |

---

## Asset-Based Risk Assessment

| Asset Name                | Risk Description                                                                                                | Likelihood | Impact | **Risk Level** | Recommendation                                                             |
| ------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------- | ------ | -------------- | -------------------------------------------------------------------------- |
| **OpenCart Web App**      | World-writable storage directory (`/storage/`) confirmed via `ls -l`. May allow unauthorized code manipulation. | Medium     | High   | **High**       | Restrict permissions and relocate storage outside web root.                |
| **OpenCart Admin Panel**  | Manual login succeeded using default credentials (`admin:admin`). No CAPTCHA or brute-force control.            | High       | High   | **Critical**   | Enforce unique, strong credentials; disable default account.               |
| **Apache Web Server**     | `phpinfo.php` file exposed sensitive configurations. Security headers missing on manual `curl` test.            | Medium     | High   | **High**       | Configure HTTP headers.                              |
| **MySQL Database**        | Root login possible via `sudo mysql` without password. Validated manually.                                      | High       | High   | **Critical**   | Enforce password for root user, disable remote root login.                 |
| **Admin Credentials**     | Found bcrypt hashed in DB, but default credentials still active.                                                | High       | High   | **Critical**   | Replace defaults, enforce password policy, monitor auth logs.              |
| **Customer Data**         | Personally identifiable information stored in plaintext tables. Risk of leak via SQL injection or misconfig.    | Medium     | High   | **High**       | Apply encryption and access logging; implement data minimization.          |
| **Backup Archives**       | Backup files located in public web-accessible path (`/system/storage/backup`). No encryption observed.          | Medium     | High   | **High**       | Move to secured directory; encrypt archives; restrict access.              |
| **Default Admin Account** | Active and functional. No differentiation from real admin. Login tested manually.                               | High       | High   | **Critical**   | Disable or replace with role-based user accounts.                          |
| **VMware Host System**    | Host OS (Windows 11) connected to internet and managing VM. If compromised, VM is exposed.                      | Medium     | High   | **High**       | Keep host OS patched; isolate lab network; disable shared folders.         |
| **Ubuntu 22.04 OS**       | Firewall (`ufw`) confirmed inactive. OS exposed to network scans and potential lateral movement.                | Medium     | Medium | **Medium**     | Enable UFW or implement iptables rules.                                    |
| **Apache Config Files**   | Accessible by root, but no integrity monitoring applied. Misconfiguration risk.                                 | Medium     | Medium | **Medium**     | Audit file changes and restrict editing to root only.                      |
| **System Logs**           | Apache logs have secure permissions but no centralized log aggregation or tamper protection.                    | Medium     | Medium | **Medium**     | Forward logs securely or make log files immutable.                         |
| **Network Configuration** | NAT used; VM not directly exposed. However, if misconfigured, may allow unintended access.                      | Medium     | High   | **High**       | Confirm router/VM NAT isolation. Periodically audit exposure using `nmap`. |
| **Internet Router**       | Could not access router settings. Based on `arp -a`, VM appears NAT-isolated.                                   | Medium     | Medium | **Medium**     | Periodically check router for port forwarding or DMZ configs.              |
| **Robots.txt File**       | File reviewed. Parameters like `?page=`, `?sort=` exposed; may assist attackers in crawling hidden endpoints.   | Medium     | Low    | **Low**        | Remove sensitive endpoint references from `robots.txt`.                    |
| **Paper Notes**           | Printed notes may include credentials/configurations. Susceptible to physical theft.                            | Low        | Medium | **Medium**     | Store securely or digitize and encrypt.                                    |
| **CUPS Print Service**    | Port 631 open. Service running and web interface enabled. Not exposed externally. Verified via `nmap` on VM IP. | Low        | Medium | **Medium**     | Disable if unused; ensure service not exposed externally.                  |

---

## Risk Calculation Method

Each asset was analyzed individually using the following formula for **qualitative assessment**:

```
Risk Level = Likelihood × Impact
```

The values are estimated based on:

* **Likelihood**: How probable is it that the vulnerability will be exploited?
* **Impact**: What is the consequence if the threat is realized?

This method ensures each asset’s risk is calculated in a structured, objective, and auditable manner. The matrix above provides the level.

---

## XSS Test Summary (Manual)

Manual testing was conducted via OpenCart’s product review input. Payloads for reflected and stored XSS were submitted.

**Result:** No confirmed exploitation; input sanitization observed.

**Recommendation:** Use Burp/ZAP fuzzing to validate edge cases.

**Risk Level:** Low (not confirmed)

---

## Suggested Remediation (To Be Done in Phase 3)

1. Remove default credentials and implement multi-factor authentication
2. Apply firewall rules (UFW, router-level)
3. Patch and secure Apache and MySQL
4. Encrypt backups and sensitive database fields
5. Harden Ubuntu system (disable unused services, enable AppArmor)
6. Conduct full automated vulnerability scans

---
