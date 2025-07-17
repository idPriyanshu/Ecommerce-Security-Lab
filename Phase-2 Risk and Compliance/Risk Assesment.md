# Risk Assessment Report – E-commerce Security Lab

This report outlines potential threats and vulnerabilities associated with the assets in the e-commerce environment. Each risk is rated based on likelihood and impact to derive a risk level. Mitigation strategies and compliance standards are also included.

## Risk Rating Matrix

The following matrix defines risk levels by combining the **Likelihood** of an event with its **Impact**:

| Likelihood ↓ \ Impact → | Low    | Medium | High     |
| ----------------------- | ------ | ------ | -------- |
| Low                     | Low    | Low    | Medium   |
| Medium                  | Low    | Medium | High     |
| High                    | Medium | High   | Critical |

---

## Risk Calculation Method

Each asset was analyzed individually using the following formula for **qualitative assessment**:

```
Risk Level = Likelihood × Impact
```

The values are estimated based on:

* **Likelihood**: How probable is it that the vulnerability will be exploited?
* **Impact**: What is the consequence if the threat is realized?

This method ensures each asset’s risk is calculated in a structured, objective, and auditable manner.

---

# Asset-Based Risk Assessment

---

## Asset: Default Admin Account

| Threat               | Vulnerability                       | Likelihood | Impact | Risk Level | Mitigation Strategy                                      | Compliance Standards           |
| -------------------- | ----------------------------------- | ---------- | ------ | ---------- | -------------------------------------------------------- | ------------------------------ |
| Unauthorized Access  | Default credentials still active    | High       | High   | Critical   | Disable or change default accounts immediately           | ISO 27001 A.9.2.1, PCI DSS 8.2 |
| Brute Force Attack   | No CAPTCHA or login throttling      | High       | High   | Critical   | Implement CAPTCHA, rate limiting, and lockout mechanisms | ISO 27001 A.9.4.3              |
| Privilege Escalation | Default account has full privileges | Medium     | High   | High       | Apply least privilege, audit admin actions               | OWASP A5, ISO 27001 A.9.1.2    |
| Enumeration          | Username is predictable (`admin`)   | Medium     | Medium | Medium     | Rename default account, monitor login attempts           | OWASP A2, NIST AC-7            |

---

## Asset: Intern Users

| Threat                             | Vulnerability                            | Likelihood | Impact | Risk Level | Mitigation Strategy                                          | Compliance Standards           |
| ---------------------------------- | ---------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------ | ------------------------------ |
| Insider Threat                     | Lack of awareness or intent-based misuse | Medium     | High   | High       | Security training, monitor activities, restrict access       | ISO 27001 A.7.2.2, IT Act 2000 |
| Unauthorized Access                | Excessive privileges or shared accounts  | Medium     | High   | High       | Role-based access control, individual accounts               | ISO 27001 A.9.2.3, PCI DSS 7.1 |
| Phishing Susceptibility            | No training or simulated testing         | Medium     | Medium | Medium     | Conduct phishing awareness programs                          | ISO 27001 A.7.2.2, DPDPA       |
| Credential Mishandling             | Use of weak or reused passwords          | Medium     | High   | High       | Enforce password complexity rules, MFA, regular audits       | ISO 27001 A.9.4.3, PCI DSS 8.2 |
| Unauthorized Software Installation | Admin rights not restricted              | Medium     | Medium | Medium     | Limit software installation rights, application whitelisting | ISO 27001 A.12.5.1             |

---

## Asset: Customers

| Threat                      | Vulnerability                                       | Likelihood | Impact | Risk Level | Mitigation Strategy                                                         | Compliance Standards             |
| --------------------------- | --------------------------------------------------- | ---------- | ------ | ---------- | --------------------------------------------------------------------------- | -------------------------------- |
| Phishing & Credential Theft | Use of reused or weak passwords                     | High       | Medium | High       | Educate users, enforce MFA, alert on suspicious login behavior              | GDPR Art. 25, ISO 27001 A.18     |
| Account Takeover            | No login anomaly detection                          | Medium     | High   | High       | Implement behavioral monitoring and adaptive authentication                 | ISO 27001 A.12.4.1, PCI DSS 10.2 |
| Data Privacy Violation      | Personal data shared with third parties unknowingly | Medium     | High   | High       | Implement consent management and privacy notice mechanisms                  | GDPR Art. 6, DPDPA Sec. 7        |
| Session Hijacking           | No session timeout or secure cookie attributes      | Medium     | High   | High       | Set Secure and HttpOnly flags, enable session timeout and re-authentication | ISO 27001 A.9.4.2, OWASP A2      |
| Social Engineering          | Lack of user awareness                              | Medium     | Medium | Medium     | Awareness training, display safe browsing tips                              | ISO 27001 A.7.2.2                |

---

## Asset: Security Analyst

| Threat                   | Vulnerability                                | Likelihood | Impact | Risk Level | Mitigation Strategy                                        | Compliance Standards          |
| ------------------------ | -------------------------------------------- | ---------- | ------ | ---------- | ---------------------------------------------------------- | ----------------------------- |
| Delayed Threat Detection | Manual log monitoring without automation     | Medium     | High   | High       | Implement SIEM tools, enable real-time alerts              | ISO 27001 A.12.4.3, NIST IR   |
| Alert Fatigue            | High volume of false positives               | Medium     | Medium | Medium     | Prioritize alerts, use rule tuning, integrate threat intel | ISO 27001 A.16.1.4            |
| Insider Threat           | Overprivileged access or unmonitored actions | Low        | High   | Medium     | Enforce least privilege, monitor analyst activity          | ISO 27001 A.9.2.3, NIST AC-6  |
| Skill Gap                | Lack of threat hunting or analysis training  | Medium     | Medium | Medium     | Conduct regular training and red/blue team simulations     | ISO 27001 A.7.2.2, NIST PR.AT |

---

## Asset: Data Protection Officer

| Threat                   | Vulnerability                                    | Likelihood | Impact | Risk Level | Mitigation Strategy                                         | Compliance Standards               |
| ------------------------ | ------------------------------------------------ | ---------- | ------ | ---------- | ----------------------------------------------------------- | ---------------------------------- |
| Ineffective Governance   | Undefined responsibilities and authority         | Medium     | High   | High       | Clearly define DPO role, document responsibilities          | GDPR Art. 37–39, DPDPA Sec. 8      |
| Non-compliance Oversight | Lack of visibility into processing activities    | Medium     | High   | High       | Implement data inventory, privacy impact assessments (DPIA) | GDPR Art. 30, ISO 27001 A.18.1.4   |
| Communication Gaps       | Inadequate interaction with stakeholders         | Low        | Medium | Medium     | Regular privacy meetings, clear reporting lines             | GDPR Art. 39                       |
| Training Negligence      | Failure to promote awareness within organization | Medium     | Medium | Medium     | Launch privacy awareness programs and DPO-led workshops     | GDPR Art. 39(b), ISO 27001 A.7.2.2 |

---

## Asset: IT Support Staff

| Threat                  | Vulnerability                                    | Likelihood | Impact | Risk Level | Mitigation Strategy                                        | Compliance Standards              |
|-------------------------|--------------------------------------------------|------------|--------|------------|------------------------------------------------------------|-----------------------------------|
| Social Engineering      | Lack of security awareness and training          | Medium     | Medium | Medium     | Conduct regular training on phishing, vishing, tailgating | ISO 27001 A.7.2.2, NIST PR.AT     |
| Privilege Misuse        | Excessive or poorly managed access rights        | Medium     | High   | High       | Implement RBAC, regular access reviews                     | ISO 27001 A.9.2.3, NIST AC-6      |
| Human Error             | Incorrect system configurations or deletions     | Medium     | Medium | Medium     | Introduce change control, require peer verification        | ISO 27001 A.12.1.2, ITIL CM        |
| Unlogged Support Actions| Lack of activity logging and audit trails        | Medium     | Medium | Medium     | Log all support actions and privileged sessions            | ISO 27001 A.12.4.1, PCI DSS 10.2  |

---

## Asset: Compliance Officer

| Threat                    | Vulnerability                                     | Likelihood | Impact | Risk Level | Mitigation Strategy                                              | Compliance Standards              |
| ------------------------- | ------------------------------------------------- | ---------- | ------ | ---------- | ---------------------------------------------------------------- | --------------------------------- |
| Missed Regulatory Changes | No tracking mechanism for updates in regulations  | Medium     | High   | High       | Use automated compliance tracking tools, subscribe to updates    | ISO 27001 A.18.1.1, DPDPA Sec. 29 |
| Incomplete Compliance     | Lack of centralized checklist or status reporting | Medium     | High   | High       | Maintain audit-ready compliance dashboard                        | ISO 27001 A.18.2.3, PCI DSS 12.1  |
| Poor Documentation        | Inadequate record-keeping of control status       | Medium     | Medium | Medium     | Enforce documentation policy and periodic compliance reviews     | ISO 27001 A.7.5, NIST IR          |
| Role Overlap              | Undefined boundaries with other roles (e.g., DPO) | Low        | Medium | Medium     | Clarify responsibilities across compliance, privacy, audit roles | ISO 27001 A.6.1.1                 |

---

## Asset: Cybersecurity Team

| Threat                  | Vulnerability                                    | Likelihood | Impact | Risk Level | Mitigation Strategy                                              | Compliance Standards           |
| ----------------------- | ------------------------------------------------ | ---------- | ------ | ---------- | ---------------------------------------------------------------- | ------------------------------ |
| Alert Fatigue           | Too many low-priority or false-positive alerts   | Medium     | Medium | Medium     | Implement alert tuning, prioritize critical use cases via SIEM   | ISO 27001 A.16.1.4, NIST DE.AE |
| Resource Misallocation  | Lack of threat triage and playbooks              | Medium     | High   | High       | Develop incident response playbooks and threat classification    | ISO 27001 A.16.1.5             |
| Inadequate Skillset     | Insufficient hands-on experience or upskilling   | Medium     | Medium | Medium     | Provide regular technical training and threat-hunting exercises  | ISO 27001 A.7.2.2, NIST PR.AT  |
| Overdependence on Tools | Reliance on automated detection without analysis | Medium     | High   | High       | Blend automation with manual validation and adversary simulation | NIST CSF DE.DP, MITRE ATT\&CK  |

---

## Asset: Developer Team

| Threat                    | Vulnerability                                | Likelihood | Impact | Risk Level | Mitigation Strategy                                               | Compliance Standards           |
| ------------------------- | -------------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------------------- | ------------------------------ |
| Insecure Coding Practices | Lack of training in secure development       | Medium     | High   | High       | Conduct secure coding workshops, integrate OWASP Top 10 awareness | ISO 27001 A.7.2.2, OWASP ASVS  |
| Code Injection            | Failure to sanitize inputs or outputs        | Medium     | High   | High       | Enforce input validation, output encoding, code reviews           | OWASP A1, ISO 27001 A.14.2.1   |
| Hardcoded Secrets         | Credentials embedded in code                 | High       | High   | Critical   | Use secret management systems, enforce pre-commit secret scanning | ISO 27001 A.9.2.4, OWASP A3    |
| Lack of Peer Review       | Code deployed without review                 | Medium     | Medium | Medium     | Implement mandatory pull request reviews and approval workflows   | ISO 27001 A.14.2.2             |
| Source Code Leak          | Uncontrolled repo sharing or public exposure | Medium     | High   | High       | Set repos to private, restrict access, implement CI/CD scanning   | ISO 27001 A.8.2.2, PCI DSS 6.3 |

---

## Asset: OpenCart Web Application

| Threat                 | Vulnerability                            | Likelihood | Impact | Risk Level | Mitigation Strategy                        | Compliance Standards         |
| ---------------------- | ---------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------ | ---------------------------- |
| XSS (Reflected/Stored) | Unescaped user input in forms/comments   | Medium     | High   | High       | Escape output, apply CSP                   | OWASP A7, GDPR Art. 32       |
| SQL Injection          | Lack of input sanitization in DB queries | Medium     | High   | High       | Parameterized queries, input validation    | OWASP A1, ISO 27001 A.14.2.5 |
| File Upload Attack     | No validation for uploaded images/files  | Medium     | High   | High       | Scan file types, apply upload restrictions | OWASP A8                     |
| Business Logic Flaws   | Checkout manipulation, price tampering   | Medium     | Medium | Medium     | Enforce validation at server side          | ISO 27001 A.14               |

---

## Asset: OpenCart Admin Panel

| Threat                | Vulnerability                  | Likelihood | Impact | Risk Level | Mitigation Strategy                   | Compliance Standards           |
| --------------------- | ------------------------------ | ---------- | ------ | ---------- | ------------------------------------- | ------------------------------ |
| Brute Force Attack    | No CAPTCHA or login throttling | High       | High   | Critical   | Implement CAPTCHA, rate limiting, MFA | ISO 27001 A.9.4, PCI DSS 8.1.6 |
| Default Credentials   | Admin/admin still active       | High       | High   | Critical   | Remove/replace default accounts       | ISO 27001 A.9.2.1              |
| Broken Access Control | No RBAC, unrestricted access   | High       | Medium | High       | Enforce RBAC policies                 | OWASP A5, ISO 27001 A.9        |

---

## Asset: Customer Login Module

| Threat              | Vulnerability                                  | Likelihood | Impact | Risk Level | Mitigation Strategy                                          | Compliance Standards           |
| ------------------- | ---------------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------ | ------------------------------ |
| Credential Stuffing | No rate limiting or detection of reuse         | High       | Medium | High       | Implement rate limiting, CAPTCHA, and monitor login patterns | ISO 27001 A.9.4, PCI DSS 8.1.6 |
| Weak Passwords      | No enforcement of strong password policy       | High       | High   | Critical   | Enforce strong password requirements                         | ISO 27001 A.9.2.1, OWASP A2    |
| No MFA              | Single-factor authentication only              | Medium     | High   | High       | Implement Multi-Factor Authentication                        | ISO 27001 A.9.4.2, PCI DSS 8.3 |
| Session Hijacking   | Insecure session management (e.g., no timeout) | Medium     | High   | High       | Use Secure/HttpOnly flags, session expiration                | ISO 27001 A.9.2, OWASP A2      |
| Phishing            | No alert or detection for credential reuse     | Medium     | Medium | Medium     | Notify users on login from new IP/device                     | GDPR Art. 32, ISO 27001 A.16   |

---

## Asset: Password Reset Module

| Threat                | Vulnerability                          | Likelihood | Impact | Risk Level | Mitigation Strategy                                               | Compliance Standards             |
| --------------------- | -------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------------------- | -------------------------------- |
| Token Prediction      | Weak or guessable reset tokens         | Medium     | High   | High       | Use cryptographically secure, random tokens with short expiration | ISO 27001 A.10.1, OWASP A2       |
| Token Reuse           | Tokens not invalidated after use       | Medium     | High   | High       | Invalidate token after reset, limit validity duration             | ISO 27001 A.9.4.2, PCI DSS 8.5.6 |
| Insecure Transmission | Token sent over HTTP instead of HTTPS  | High       | High   | Critical   | Enforce HTTPS-only communications for reset flows                 | ISO 27001 A.13.1.1, OWASP A6     |
| Enumeration Attacks   | Reset form reveals user existence      | Medium     | Medium | Medium     | Return generic success message regardless of account validity     | OWASP A7, GDPR Art. 5            |
| Missing Logging       | Password reset not logged or monitored | Medium     | Medium | Medium     | Enable auditing and alerting for password reset attempts          | ISO 27001 A.12.4, NIST AC-7      |

---

## Asset: Apache Web Server

| Threat                   | Vulnerability                                              | Likelihood | Impact | Risk Level | Mitigation Strategy                           | Compliance Standards     |
| ------------------------ | ---------------------------------------------------------- | ---------- | ------ | ---------- | --------------------------------------------- | ------------------------ |
| Remote Code Execution    | World-writable web root (`/var/www/html`) and outdated PHP | High       | High   | Critical   | Patch PHP, restrict directory permissions     | OWASP A1, ISO 27001 A.14 |
| Directory Traversal      | Improper file path validation                              | Medium     | High   | High       | Sanitize file input, enforce access controls  | OWASP A5, PCI DSS 6.5.7  |
| Information Disclosure   | `phpinfo.php` file accessible                              | Medium     | Medium | Medium     | Remove test/debug files, restrict file access | ISO 27001 A.12.1         |
| Missing Security Headers | Lacking CSP, X-Frame-Options                               | Medium     | High   | High       | Apply secure headers                          | OWASP A6, ISO 27001 A.10 |

---

## Asset: MySQL Database

| Threat                   | Vulnerability                                   | Likelihood | Impact | Risk Level | Mitigation Strategy                                        | Compliance Standards              |
| ------------------------ | ----------------------------------------------- | ---------- | ------ | ---------- | ---------------------------------------------------------- | --------------------------------- |
| Unauthorized Root Access | No password for root via `sudo mysql`           | High       | High   | Critical   | Require password, restrict sudo access                     | ISO 27001 A.9.2, PCI DSS 8.2      |
| SQL Injection            | Dynamic queries without sanitization            | Medium     | High   | High       | Use prepared statements, input validation, implement WAF   | ISO 27001 A.14.2.5, PCI DSS 6.5.1 |
| Weak Authentication      | Default user credentials and no password policy | High       | High   | Critical   | Enforce password policy, disable defaults, monitor logs    | ISO 27001 A.9.4.3                 |
| Network Exposure         | MySQL listening on all interfaces               | Medium     | High   | High       | Restrict MySQL to localhost, firewall untrusted interfaces | ISO 27001 A.13.1                  |

---

## Asset: Ubuntu 22.04 OS

| Threat               | Vulnerability                        | Likelihood | Impact | Risk Level | Mitigation Strategy                                        | Compliance Standards |
| -------------------- | ------------------------------------ | ---------- | ------ | ---------- | ---------------------------------------------------------- | -------------------- |
| OS Exploits          | Outdated packages, firewall disabled | Medium     | High   | High       | Regular patching, enable UFW, disable unnecessary services | ISO 27001 A.12.6.1   |
| Privilege Escalation | Kernel vulnerabilities               | Medium     | High   | High       | Apply LTS kernel updates, use AppArmor/SELinux             | ISO 27001 A.12       |

---

## Asset: CUPS Print Service

| Threat            | Vulnerability               | Likelihood | Impact | Risk Level | Mitigation Strategy       | Compliance Standards |
| ----------------- | --------------------------- | ---------- | ------ | ---------- | ------------------------- | -------------------- |
| Port Exploitation | Port 631 open unnecessarily | Medium     | Medium | Medium     | Disable service if unused | ISO 27001 A.12.1.2   |

---

## Asset: Cron Jobs

| Threat                    | Vulnerability              | Likelihood | Impact | Risk Level | Mitigation Strategy                      | Compliance Standards |
| ------------------------- | -------------------------- | ---------- | ------ | ---------- | ---------------------------------------- | -------------------- |
| Unauthorized Job Addition | No permission control      | Low        | Medium | Medium     | Restrict access to crontab files         | ISO 27001 A.12.1.1   |
| Task Tampering            | Logs or timing manipulated | Medium     | Medium | Medium     | Monitor cron logs, apply checksum alerts | ISO 27001 A.12.4.1   |

---

## Asset: Apache Config Files

| Threat                    | Vulnerability                                   | Likelihood | Impact | Risk Level | Mitigation Strategy                                                  | Compliance Standards           |
| ------------------------- | ----------------------------------------------- | ---------- | ------ | ---------- | -------------------------------------------------------------------- | ------------------------------ |
| Unauthorized Modification | World-writable config files (`/etc/apache2/*`)  | Medium     | High   | High       | Restrict file permissions, allow only root/admin edits               | ISO 27001 A.9.2.3, PCI DSS 6.5 |
| Information Disclosure    | Backup/config files exposed via web server      | Medium     | High   | High       | Move config files outside web root, deny access via `.htaccess`      | ISO 27001 A.8.3, OWASP A6      |
| Misconfiguration          | Directory listing enabled, indexes not disabled | Medium     | Medium | Medium     | Disable `Indexes` directive, review `httpd.conf` and `.htaccess`     | OWASP A6, ISO 27001 A.12.1     |
| Lack of TLS Enforcement   | HTTP allowed or redirect misconfigured          | Medium     | High   | High       | Force HTTPS with `RewriteRule` or `Strict-Transport-Security` header | ISO 27001 A.13, PCI DSS 4.1    |
| Logging Misconfiguration  | No error/access logging or excessive logging    | Low        | Medium | Medium     | Enable appropriate logging, avoid verbose sensitive data in logs     | ISO 27001 A.12.4.1             |

---

## Asset: Network Configuration

| Threat                 | Vulnerability               | Likelihood | Impact | Risk Level | Mitigation Strategy                          | Compliance Standards |
| ---------------------- | --------------------------- | ---------- | ------ | ---------- | -------------------------------------------- | -------------------- |
| Misrouting or Exposure | Weak NAT or port forwarding | Medium     | High   | High       | Enforce proper NAT, isolate network segments | ISO 27001 A.13       |
| Lateral Movement       | Open services not filtered  | Medium     | High   | High       | Use VLANs, firewall policies                 | PCI DSS 1.3.6        |

---

## Asset: Robots.txt File

| Threat                 | Vulnerability                            | Likelihood | Impact | Risk Level | Mitigation Strategy                              | Compliance Standards |
| ---------------------- | ---------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------ | -------------------- |
| Information Disclosure | Reveals admin or sensitive paths         | Low        | Medium | Medium     | Remove sensitive entries or block access via 403 | OWASP A6             |
| Crawling Hidden Pages  | Allows enumeration of parameterized URLs | Medium     | Medium | Medium     | Use honeypots, monitor bot activity              | ISO 27001 A.13       |

---

## Asset: Uploaded Product Images

| Threat             | Vulnerability                     | Likelihood | Impact | Risk Level | Mitigation Strategy                          | Compliance Standards |
| ------------------ | --------------------------------- | ---------- | ------ | ---------- | -------------------------------------------- | -------------------- |
| Malware Upload     | No file sanitization or AV scan   | Medium     | High   | High       | File extension checks, integrate AV scanning | OWASP A8             |
| Overwrite or Abuse | Same filename uploaded repeatedly | Medium     | Medium | Medium     | Use random file names and access validation  | ISO 27001 A.14       |

---

## Asset: System Logs

| Threat                   | Vulnerability                                | Likelihood | Impact | Risk Level | Mitigation Strategy                                            | Compliance Standards             |
|--------------------------|----------------------------------------------|------------|--------|------------|----------------------------------------------------------------|----------------------------------|
| Log Tampering            | Writable by unauthorized users               | High       | High   | Critical   | Apply strict file permissions, use log integrity mechanisms    | ISO 27001 A.12.4.3, PCI DSS 10.5 |
| Log Overwrite            | Log rotation misconfigured                   | Medium     | Medium | Medium     | Configure proper log rotation with size/time triggers          | ISO 27001 A.12.4.1               |
| Insufficient Retention   | Logs purged before required retention period | Medium     | High   | High       | Define and enforce log retention policy                        | ISO 27001 A.12.4.2               |
| Missing Monitoring       | Logs not reviewed regularly                  | Medium     | Medium | Medium     | Centralize logs with SIEM, set alerts for suspicious behavior   | NIST CSF DE.CM-7, ISO 27001 A.16 |
| Information Disclosure   | Sensitive data logged (e.g., passwords)      | Medium     | High   | High       | Sanitize logs to exclude credentials and personal data         | GDPR Art. 5, ISO 27001 A.10      |

---

## Asset: Authentication Logs

| Threat                  | Vulnerability                               | Likelihood | Impact | Risk Level | Mitigation Strategy                                              | Compliance Standards             |
| ----------------------- | ------------------------------------------- | ---------- | ------ | ---------- | ---------------------------------------------------------------- | -------------------------------- |
| Log Tampering           | Logs can be altered or deleted by attackers | High       | High   | Critical   | Centralize logs, enable log immutability and access restrictions | ISO 27001 A.12.4.3, PCI DSS 10.5 |
| Lack of Log Review      | Login anomalies not detected                | Medium     | High   | High       | Implement automated alerting and daily log review procedures     | ISO 27001 A.16, NIST CSF DE.CM   |
| Incomplete Logging      | Failed/successful login events not captured | Medium     | Medium | Medium     | Ensure all auth events are logged with timestamps                | ISO 27001 A.12.4.1               |
| Sensitive Data Exposure | Logging of passwords or tokens in plaintext | Medium     | High   | High       | Redact sensitive data from logs, review log formats              | GDPR Art. 5, ISO 27001 A.10      |
| Unauthorized Access     | Logs accessible by non-privileged users     | Medium     | High   | High       | Restrict access using role-based permissions                     | ISO 27001 A.9.4.1                |

---

## Asset: Audit Logs

| Threat                   | Vulnerability                                        | Likelihood | Impact | Risk Level | Mitigation Strategy                                                    | Compliance Standards             |
|--------------------------|------------------------------------------------------|------------|--------|------------|------------------------------------------------------------------------|----------------------------------|
| Log Tampering            | Logs not protected against modification              | High       | High   | Critical   | Implement write-once logging, enable log integrity checks              | ISO 27001 A.12.4.3, PCI DSS 10.5 |
| Incomplete Coverage      | Critical system events not audited                   | Medium     | High   | High       | Enable auditing for access control, configuration, and data changes    | ISO 27001 A.12.4.1               |
| Insufficient Retention   | Logs deleted before meeting regulatory requirements  | Medium     | High   | High       | Define log retention periods and protect storage                       | ISO 27001 A.18.1.3, PCI DSS 10.7 |
| No Alerting or Review    | Logs not analyzed for suspicious activity            | Medium     | Medium | Medium     | Integrate with SIEM tools for real-time monitoring and alerts          | ISO 27001 A.16.1.7, NIST CSF DE.CM |
| Exposure of Sensitive Data | PII or credentials logged without masking           | Medium     | High   | High       | Sanitize log output, avoid logging personal or credential data         | GDPR Art. 5, ISO 27001 A.10      |

---

## Asset: Customer Data

| Threat              | Vulnerability                               | Likelihood | Impact | Risk Level | Mitigation Strategy                                         | Compliance Standards               |
| ------------------- | ------------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------------- | ---------------------------------- |
| Data Breach         | Stored in plaintext or weak encryption      | High       | High   | Critical   | Store data in encrypted format, use strong access controls  | ISO 27001 A.8, GDPR Art. 32, DPDPA |
| Unauthorized Access | Excessive privileges or missing ACLs        | High       | High   | Critical   | Apply least privilege principle, audit access control lists | ISO 27001 A.9.1                    |
| Insider Threat      | Access to sensitive data without monitoring | Medium     | High   | High       | Enable access logging and anomaly detection                 | ISO 27001 A.12.4, DPDPA            |
| Injection Attacks   | SQL injection or insecure queries           | Medium     | High   | High       | Use parameterized queries and validate input                | OWASP A1                           |

---

## Asset: Admin Credentials

| Threat            | Vulnerability                               | Likelihood | Impact | Risk Level | Mitigation Strategy                                   | Compliance Standards         |
| ----------------- | ------------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------- | ---------------------------- |
| Credential Theft  | Weak or default credentials stored in DB    | High       | High   | Critical   | Enforce strong passwords, rotate credentials, use MFA | ISO 27001 A.9.2, PCI DSS 8.2 |
| Insecure Storage  | Credentials stored as plaintext/broken hash | High       | High   | Critical   | Use bcrypt or Argon2, salting and hashing             | ISO 27001 A.10.1, OWASP A3   |
| Database Exposure | Admin table accessible via SQL injection    | Medium     | High   | High       | Harden DB queries, limit admin role exposure          | OWASP A1                     |

---

## Asset: Customer Credentials

| Threat                 | Vulnerability                      | Likelihood | Impact | Risk Level | Mitigation Strategy                                     | Compliance Standards             |
| ---------------------- | ---------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------- | -------------------------------- |
| Brute Force Login      | No account lockout, weak passwords | High       | High   | Critical   | Account lockout, CAPTCHA, strong password policy        | ISO 27001 A.9.1.1, PCI DSS 8.1.6 |
| Credential Reuse       | Same password across accounts      | Medium     | Medium | Medium     | Encourage unique passwords, MFA, password health checks | OWASP A2                         |
| Insecure Reset Process | Weak password reset token          | Medium     | High   | High       | Secure token generation, time limit, HTTPS enforcement  | ISO 27001 A.9.4                  |

---

## Asset: Backup Archives

| Threat               | Vulnerability                               | Likelihood | Impact | Risk Level | Mitigation Strategy                           | Compliance Standards          |
| -------------------- | ------------------------------------------- | ---------- | ------ | ---------- | --------------------------------------------- | ----------------------------- |
| Data Tampering       | Backups unencrypted and publicly accessible | High       | High   | Critical   | Encrypt backups, restrict storage access      | ISO 27001 A.12.3, PCI DSS 9.5 |
| Ransomware Targeting | Backup folders writable and visible         | Medium     | High   | High       | Store offline copies, backup integrity checks | NIST SP 800-34                |
| Data Loss            | No versioning or integrity verification     | Medium     | High   | High       | Version control, test restoration procedures  | ISO 27001 A.12.3.1            |

---

## Asset: Developer Notes

| Threat                 | Vulnerability                    | Likelihood | Impact | Risk Level | Mitigation Strategy                 | Compliance Standards |
| ---------------------- | -------------------------------- | ---------- | ------ | ---------- | ----------------------------------- | -------------------- |
| Information Disclosure | Hardcoded credentials or secrets | Medium     | Medium | Medium     | Use `.gitignore`, sanitize comments | OWASP A3             |

---

## Asset: Google Cloud Free Tier

| Threat                | Vulnerability        | Likelihood | Impact | Risk Level | Mitigation Strategy                            | Compliance Standards         |
| --------------------- | -------------------- | ---------- | ------ | ---------- | ---------------------------------------------- | ---------------------------- |
| Misconfigured Buckets | Public data exposure | Medium     | High   | High       | Apply IAM policies, private access enforcement | ISO 27001 A.13, GDPR Art. 32 |

---

## Asset: GitHub Repository

| Threat              | Vulnerability                             | Likelihood | Impact | Risk Level | Mitigation Strategy                                         | Compliance Standards            |
| ------------------- | ----------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------------- | ------------------------------- |
| Source Code Leak    | Public repository or shared access        | Medium     | High   | High       | Make repositories private, restrict collaborator access     | ISO 27001 A.14.1, PCI DSS 6.3.1 |
| Secrets Exposure    | Hardcoded secrets, credentials in code    | High       | High   | Critical   | Use secret scanning tools, environment variables            | ISO 27001 A.9.4.3, OWASP A3     |
| Insecure Commits    | Committing sensitive config or keys       | Medium     | High   | High       | Enforce commit hooks, review pull requests                  | ISO 27001 A.12.5.1              |
| Supply Chain Attack | Unverified dependencies in `package.json` | Medium     | High   | High       | Use dependency scanners (Dependabot, Snyk), verify packages | ISO 27001 A.14.2.8              |
| Repository Takeover | Weak GitHub account security              | Medium     | High   | High       | Enforce MFA for all contributors                            | ISO 27001 A.9.2, PCI DSS 8.3    |

---

## Asset: Payment Gateway Plugin

| Threat                   | Vulnerability                                         | Likelihood | Impact | Risk Level | Mitigation Strategy                                                 | Compliance Standards           |
| ------------------------ | ----------------------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------------- | ------------------------------ |
| Transaction Hijacking    | Insecure communication or improper request validation | Medium     | High   | High       | Use HTTPS, validate all inputs/requests, verify digital signatures  | PCI DSS 4.1, ISO 27001 A.10.1  |
| Man-in-the-Middle (MITM) | Self-signed or expired SSL certificate                | Medium     | High   | High       | Use CA-signed certificates and implement TLS best practices         | PCI DSS 4.1, OWASP A6          |
| API Abuse                | No rate limiting or authentication for API endpoints  | Medium     | High   | High       | Implement API authentication (OAuth), apply rate limiting           | OWASP API Security Top 10 A4   |
| Improper Error Handling  | Debug errors expose sensitive transaction details     | Low        | Medium | Medium     | Suppress detailed errors in production, use generic error messages  | ISO 27001 A.14.1.2, OWASP A6   |
| Lack of Logging          | No transaction audit trail maintained                 | Medium     | Medium | Medium     | Enable transaction logging and monitoring with alerts for anomalies | PCI DSS 10.2, ISO 27001 A.12.4 |

---

## Asset: Internet Service Provider

| Threat                  | Vulnerability                                            | Likelihood | Impact | Risk Level | Mitigation Strategy                                                      | Compliance Standards           |
| ----------------------- | -------------------------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------------------ | ------------------------------ |
| Service Interruption    | No redundancy or failover in ISP connection              | Medium     | High   | High       | Implement secondary ISP or cellular backup line                          | ISO 27001 A.17.2.1             |
| DNS Hijacking           | ISP-provided DNS servers are compromised                 | Medium     | High   | High       | Use secure, custom DNS resolvers with DNSSEC                             | ISO 27001 A.13.1.1, NIST PR.AC |
| Unencrypted Traffic     | ISP-level monitoring of unencrypted HTTP traffic         | Medium     | High   | High       | Enforce HTTPS across all services, use VPN tunnels                       | ISO 27001 A.10.1.1             |
| IP Address Reassignment | Static IP not reserved, leading to session hijack issues | Low        | Medium | Medium     | Use static IP for production services or auto-detect IP change and alert | ISO 27001 A.13.1.3             |
| Bandwidth Throttling    | ISP restricts traffic during high load periods           | Medium     | Medium | Medium     | Monitor bandwidth usage, consider SLA negotiation with provider          | ISO 27001 A.15.1.1             |

---

## Asset: Domain Registrar Account

| Threat           | Vulnerability         | Likelihood | Impact | Risk Level | Mitigation Strategy                 | Compliance Standards |
| ---------------- | --------------------- | ---------- | ------ | ---------- | ----------------------------------- | -------------------- |
| Account Takeover | Weak password, no MFA | Medium     | High   | High       | Use unique passwords and enable MFA | ISO 27001 A.9.4.2    |

---

## Asset: Open-source Security Tools

| Threat              | Vulnerability                                | Likelihood | Impact | Risk Level | Mitigation Strategy                                          | Compliance Standards            |
| ------------------- | -------------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------ | ------------------------------- |
| False Positives     | Alerts not validated, causing alert fatigue  | Medium     | Medium | Medium     | Cross-verify results, tune rules, prioritize by severity     | ISO 27001 A.16.1.4, NIST DE.CM  |
| Outdated Signatures | Lack of timely updates for detection engines | Medium     | High   | High       | Automate signature updates and schedule tool upgrades        | ISO 27001 A.12.6.1              |
| Misconfiguration    | Improper setup leading to missed detections  | Medium     | High   | High       | Follow configuration guides, conduct regular tool validation | ISO 27001 A.14.2.1              |
| Insecure Deployment | Tools exposed to internet without hardening  | Medium     | High   | High       | Host tools internally or behind VPN; apply access controls   | ISO 27001 A.13.1.1, A.9.2.3     |
| Data Leakage        | Logs or results stored insecurely            | Medium     | Medium | Medium     | Secure storage paths, encrypt logs, restrict access          | ISO 27001 A.8.2.3, PCI DSS 10.5 |

---

## Asset: Anti-Malware Software

| Threat              | Vulnerability       | Likelihood | Impact | Risk Level | Mitigation Strategy                           | Compliance Standards |
| ------------------- | ------------------- | ---------- | ------ | ---------- | --------------------------------------------- | -------------------- |
| Inactive Protection | No update mechanism | Medium     | Medium | Medium     | Automate definition updates, alert on failure | ISO 27001 A.12.2.1   |

---

## Asset: SSL Certificate (Self-signed)

| Threat             | Vulnerability                              | Likelihood | Impact | Risk Level | Mitigation Strategy                                      | Compliance Standards         |
|--------------------|--------------------------------------------|------------|--------|------------|----------------------------------------------------------|------------------------------|
| MITM Attack         | Self-signed cert not trusted by browsers  | Medium     | High   | High       | Use certificates signed by trusted Certificate Authority | PCI DSS 4.1, ISO 27001 A.10  |
| Certificate Spoofing| No certificate pinning                    | Medium     | Medium | Medium     | Implement SSL pinning on client-side apps                | OWASP M5                     |
| Expired Certificate | Lack of renewal monitoring                | Medium     | Medium | Medium     | Set up renewal alerts, automate cert management          | ISO 27001 A.12.1.2           |
| Weak Cipher Suites  | Using outdated encryption algorithms      | Medium     | High   | High       | Disable weak ciphers, enforce TLS 1.2 or above           | NIST SP 800-52               |

---

## Asset: Session Management Mechanism

| Threat                | Vulnerability                                  | Likelihood | Impact | Risk Level | Mitigation Strategy                                                  | Compliance Standards      |
| --------------------- | ---------------------------------------------- | ---------- | ------ | ---------- | -------------------------------------------------------------------- | ------------------------- |
| Session Hijacking     | Missing `HttpOnly` / `Secure` flags on cookies | Medium     | High   | High       | Set `Secure` and `HttpOnly` flags, use SameSite cookies              | OWASP A2, ISO 27001 A.9.2 |
| Session Fixation      | Session ID not regenerated after login         | Medium     | High   | High       | Regenerate session ID after authentication                           | OWASP A2, ISO 27001 A.13  |
| Session Timeout Abuse | Long-lived or infinite session expiry          | Medium     | Medium | Medium     | Set appropriate session timeouts and idle session termination        | ISO 27001 A.9.4.2         |
| Predictable IDs       | Weak or guessable session identifiers          | Low        | High   | Medium     | Use strong, random session ID generators                             | OWASP A2, ISO 27001 A.10  |
| Insecure Storage      | Session data stored in client-side cookies     | Medium     | High   | High       | Store sessions server-side with encrypted session management systems | ISO 27001 A.9.4, OWASP A5 |

---

## Asset: Email Notification Module

| Threat     | Vulnerability               | Likelihood | Impact | Risk Level | Mitigation Strategy              | Compliance Standards |
| ---------- | --------------------------- | ---------- | ------ | ---------- | -------------------------------- | -------------------- |
| Spam Relay | Misconfigured SMTP settings | Medium     | Medium | Medium     | Apply SPF, DKIM, and rate limits | ISO 27001 A.13       |

---

## Asset: Paper Notes

| Threat         | Vulnerability                              | Likelihood | Impact | Risk Level | Mitigation Strategy                           | Compliance Standards |
| -------------- | ------------------------------------------ | ---------- | ------ | ---------- | --------------------------------------------- | -------------------- |
| Physical Theft | Contains passwords or architecture details | Medium     | Medium | Medium     | Store in locked drawers, digitize and encrypt | ISO 27001 A.11.2.9   |

---

## Asset: Training Material

| Threat               | Vulnerability                                  | Likelihood | Impact | Risk Level | Mitigation Strategy                                         | Compliance Standards             |
| -------------------- | ---------------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------------- | -------------------------------- |
| Knowledge Leakage    | Shared externally without authorization        | Medium     | Medium | Medium     | Apply internal access controls, use watermarks on documents | ISO 27001 A.7.2.2                |
| Outdated Content     | Stale or incorrect security procedures         | Medium     | Medium | Medium     | Periodic review and updates of training modules             | ISO 27001 A.7.2.1                |
| Unauthorized Access  | Publicly accessible LMS or shared drives       | Medium     | Medium | Medium     | Enforce login-based access, monitor downloads               | ISO 27001 A.9.1.2                |
| Compliance Deviation | Incomplete coverage of compliance requirements | Medium     | High   | High       | Align training with applicable standards and regulations    | ISO 27001 A.18.1.3, GDPR Art. 39 |

---

## Asset: Risk Assessment Report

| Threat                    | Vulnerability                              | Likelihood | Impact | Risk Level | Mitigation Strategy                                              | Compliance Standards          |
|---------------------------|--------------------------------------------|------------|--------|------------|------------------------------------------------------------------|-------------------------------|
| Unauthorized Modification | No version control or access restriction   | Medium     | Medium | Medium     | Apply version control (e.g., Git), restrict editing rights       | ISO 27001 A.12.1.2, A.8.2.1   |
| Data Leakage              | Shared via unsecured channels              | Medium     | High   | High       | Use secure file transfer methods and encryption                  | ISO 27001 A.13.2.3, DPDPA     |
| Loss of Availability      | File corruption or accidental deletion     | Medium     | Medium | Medium     | Maintain regular backups, use redundancy                         | ISO 27001 A.12.3.1            |
| Integrity Tampering       | Manual edits without audit trail           | Medium     | Medium | Medium     | Use document signing and centralized document repositories        | ISO 27001 A.12.4.3, A.9.2.6   |

---

## Asset: Compliance Checklist

| Threat                  | Vulnerability                                      | Likelihood | Impact | Risk Level | Mitigation Strategy                                                | Compliance Standards             |
|-------------------------|----------------------------------------------------|------------|--------|------------|--------------------------------------------------------------------|----------------------------------|
| Non-compliance          | Checklist is outdated or incomplete                | Medium     | High   | High       | Schedule periodic reviews and updates                             | ISO 27001 A.18.1.1, PCI DSS 12.1 |
| Audit Failure           | Checklist not aligned with actual control status   | Medium     | High   | High       | Cross-verify checklist with control implementation reports         | ISO 27001 A.18.2.2               |
| Unauthorized Access     | Checklist editable by unauthorized users           | Medium     | Medium | Medium     | Set access controls and use version tracking                       | ISO 27001 A.9.1.2                |
| Lack of Evidence Mapping| Controls not linked to documented proof            | Medium     | High   | High       | Maintain mapping of each control to supporting evidence            | ISO 27001 A.7.5.1                |

---

## Asset: Access Control Policy Document

| Threat                   | Vulnerability                                  | Likelihood | Impact | Risk Level | Mitigation Strategy                                                    | Compliance Standards            |
|--------------------------|------------------------------------------------|------------|--------|------------|------------------------------------------------------------------------|---------------------------------|
| Policy Bypass            | Policy exists but not enforced technically     | Medium     | High   | High       | Enforce access control via IAM, group roles, and permissions           | ISO 27001 A.9.1, DPDPA          |
| Unauthorized Modification| Document is editable by unauthorized personnel | Medium     | Medium | Medium     | Apply role-based access control and version control                   | ISO 27001 A.9.2.1, A.8.2.2      |
| Outdated Definitions     | Policy not updated with system architecture    | Medium     | Medium | Medium     | Align policy with periodic system and organization reviews            | ISO 27001 A.5.1.1               |
| Lack of Awareness        | Employees unaware of access policy guidelines  | Medium     | Medium | Medium     | Conduct regular training and mandatory policy acknowledgment sessions | ISO 27001 A.7.2.2               |

---

## Asset: Incident Response Template

| Threat              | Vulnerability                       | Likelihood | Impact | Risk Level | Mitigation Strategy                                          | Compliance Standards               |
| ------------------- | ----------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------ | ---------------------------------- |
| Delay in Response   | Incomplete or outdated IR plan      | Medium     | High   | High       | Regularly test, update, and simulate IR plans                | ISO 27001 A.16.1.5, NIST SP 800-61 |
| Missed Escalations  | No defined escalation procedures    | Medium     | High   | High       | Clearly define escalation matrix and assign responsibilities | ISO 27001 A.16.1.4                 |
| Lack of Awareness   | Employees unaware of IR process     | Medium     | Medium | Medium     | Conduct IR training and tabletop exercises                   | ISO 27001 A.7.2.2, A.16.1.2        |
| Unauthorized Access | Template file not access restricted | Low        | Medium | Medium     | Restrict file access and maintain audit trail                | ISO 27001 A.9.1.2                  |

---

## Asset: Business Continuity Plan

| Threat                      | Vulnerability                                          | Likelihood | Impact | Risk Level | Mitigation Strategy                                                       | Compliance Standards             |
|-----------------------------|--------------------------------------------------------|------------|--------|------------|---------------------------------------------------------------------------|----------------------------------|
| Operational Disruption      | Outdated or untested continuity procedures            | Medium     | High   | High       | Regularly update and test the BCP through simulations                     | ISO 27001 A.17.1.3, NIST SP 800-34 |
| Lack of Role Clarity        | Undefined roles and responsibilities in crisis        | Medium     | High   | High       | Clearly define and document roles in BCP                                  | ISO 27001 A.17.1.2               |
| Inaccessible Documentation  | BCP stored only on internal systems                   | Medium     | Medium | Medium     | Store BCP in both online/offline formats with access control              | ISO 27001 A.17.1.1               |
| Data Recovery Failure       | Recovery steps not aligned with IT and data systems   | Medium     | High   | High       | Sync BCP with disaster recovery plans and validate data recovery process  | ISO 27001 A.17.2.1               |

---

## Asset: Privacy Policy

| Threat                     | Vulnerability                                                | Likelihood | Impact | Risk Level | Mitigation Strategy                                                    | Compliance Standards            |
| -------------------------- | ------------------------------------------------------------ | ---------- | ------ | ---------- | ---------------------------------------------------------------------- | ------------------------------- |
| Legal Non-compliance       | Outdated or missing privacy clauses                          | High       | High   | Critical   | Regularly review and update policy to align with GDPR, DPDPA, etc.     | GDPR Art. 12–14, DPDPA Sec. 7   |
| Lack of Transparency       | Unclear data collection and usage disclosures                | Medium     | High   | High       | Clearly define what data is collected, how it is used, and user rights | GDPR Art. 5, ISO 27001 A.18.1.4 |
| Unauthorized Modifications | Policy page editable without approval                        | Medium     | Medium | Medium     | Apply access controls and maintain version control                     | ISO 27001 A.9.1.2, A.12.1.2     |
| Inaccessible to Users      | Not linked prominently or not available in regional language | Low        | Medium | Medium     | Ensure accessibility via footer link, offer in multiple languages      | DPDPA Sec. 6, GDPR Art. 7       |

---

## Asset: Company-Owned Laptops

| Threat                 | Vulnerability                                       | Likelihood | Impact | Risk Level | Mitigation Strategy                                          | Compliance Standards             |
| ---------------------- | --------------------------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------ | -------------------------------- |
| Malware Infection      | No antivirus or endpoint protection                 | Medium     | High   | High       | Deploy EDR/AV tools, enforce USB restrictions, regular scans | ISO 27001 A.12.2.1, A.12.6.1     |
| Data Theft/Loss        | No full disk encryption                             | Medium     | High   | High       | Enable full disk encryption (e.g., BitLocker, LUKS)          | ISO 27001 A.10.1, GDPR Art. 32   |
| Unauthorized Access    | Shared devices, weak login credentials              | Medium     | High   | High       | Enforce strong password policies, auto-lock screen, MFA      | ISO 27001 A.9.2.1, PCI DSS 8.2   |
| Lack of Updates        | Unpatched OS and software                           | Medium     | High   | High       | Centralized patch management system                          | ISO 27001 A.12.6.1               |
| Physical Theft         | Devices left unattended or unsecured                | Medium     | Medium | Medium     | Use cable locks, asset tags, enforce secure storage policies | ISO 27001 A.11.2.6, A.11.2.9     |
| Insecure Configuration | Admin rights for users, services enabled by default | Medium     | High   | High       | Apply CIS Benchmarks, disable unnecessary services           | NIST CSF PR.IP-1, ISO 27001 A.12 |

---

## Asset: Network Switch

| Threat                   | Vulnerability                             | Likelihood | Impact | Risk Level | Mitigation Strategy                                               | Compliance Standards                   |
| ------------------------ | ----------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------------------- | -------------------------------------- |
| Unauthorized Access      | Default credentials or no access control  | High       | High   | Critical   | Change default credentials, implement access control lists (ACLs) | ISO 27001 A.9.2.3, NIST SP 800-53 AC-6 |
| VLAN Hopping             | Improper VLAN configuration               | Medium     | High   | High       | Enforce proper VLAN tagging and segmentation                      | PCI DSS 1.2.3, ISO 27001 A.13          |
| SNMP Exploitation        | SNMP community strings are default/public | Medium     | High   | High       | Change SNMP strings, use SNMPv3 with encryption                   | NIST SP 800-115                        |
| Firmware Vulnerabilities | Outdated firmware with known exploits     | Medium     | High   | High       | Regularly update switch firmware after validation                 | ISO 27001 A.12.6.1                     |
| Physical Tampering       | Unsecured access to switch ports          | Low        | Medium | Medium     | Lock switch cabinets, disable unused ports                        | ISO 27001 A.11.1.1                     |

---

## Asset: Internet Router

| Threat              | Vulnerability                      | Likelihood | Impact | Risk Level | Mitigation Strategy                              | Compliance Standards |
| ------------------- | ---------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------ | -------------------- |
| Unauthorized Access | Default admin credentials active   | High       | Medium | High       | Change default credentials, disable remote admin | ISO 27001 A.13.1     |
| DoS Attack          | No firewall or rate limit settings | Medium     | Medium | Medium     | Enable DoS protection, filter traffic            | NIST SP 800-41       |

---

## Asset: Firewall Appliance

| Threat                 | Vulnerability                            | Likelihood | Impact | Risk Level | Mitigation Strategy                                         | Compliance Standards           |
| ---------------------- | ---------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------------------------- | ------------------------------ |
| Misconfiguration       | Unnecessary ports/services left open     | Medium     | High   | High       | Regular audits, apply principle of least privilege          | ISO 27001 A.13, PCI DSS 1.1.6  |
| Insecure Remote Access | Remote admin enabled without MFA         | Medium     | High   | High       | Disable remote admin or enforce MFA and IP whitelisting     | ISO 27001 A.9.4.2              |
| Outdated Firmware      | Unpatched vulnerabilities in firewall OS | Medium     | High   | High       | Regular firmware updates and security patching              | ISO 27001 A.12.6               |
| Rule Shadowing         | Conflicting or redundant rules           | Medium     | Medium | Medium     | Perform rule optimization and cleanup                       | NIST SP 800-41, ISO 27001 A.13 |
| Logging Disabled       | Lack of traffic monitoring or alerting   | Medium     | Medium | Medium     | Enable firewall logging and integrate with centralized SIEM | ISO 27001 A.12.4.1             |

---

## Asset: Storage Server

| Threat                | Vulnerability                                    | Likelihood | Impact | Risk Level | Mitigation Strategy                                                | Compliance Standards             |
| --------------------- | ------------------------------------------------ | ---------- | ------ | ---------- | ------------------------------------------------------------------ | -------------------------------- |
| Data Corruption       | No redundancy, no integrity verification         | Medium     | High   | High       | Use RAID setup, schedule regular checksums and integrity scans     | ISO 27001 A.12.3.1               |
| Unauthorized Access   | Inadequate access controls or shared credentials | High       | High   | Critical   | Implement RBAC, isolate sensitive shares, enforce strong passwords | ISO 27001 A.9.1.2, A.9.2.3       |
| Ransomware Infection  | Files accessible from compromised endpoint       | Medium     | High   | High       | Enable backups, apply least privilege, segment network             | ISO 27001 A.12.3, NIST SP 800-83 |
| Lack of Backup        | No periodic or offsite backups                   | Medium     | High   | High       | Implement scheduled encrypted backups stored offsite               | ISO 27001 A.12.3, PCI DSS 9.5    |
| Insecure File Sharing | Shares exposed over SMB/NFS without encryption   | Medium     | Medium | Medium     | Enforce encrypted protocols, audit share configuration             | ISO 27001 A.13.2.3               |

---

## Asset: Audit Trail System

| Threat                 | Vulnerability                         | Likelihood | Impact | Risk Level | Mitigation Strategy                       | Compliance Standards             |
| ---------------------- | ------------------------------------- | ---------- | ------ | ---------- | ----------------------------------------- | -------------------------------- |
| Log Tampering          | No integrity or immutability controls | High       | High   | Critical   | Implement log signing, central log server | ISO 27001 A.12.4.3, PCI DSS 10.5 |
| Insufficient Retention | Logs rotated or deleted early         | Medium     | High   | High       | Define log retention policy, backups      | ISO 27001 A.12.4.1               |
| Missing Monitoring     | Logs not reviewed or alerted          | Medium     | Medium | Medium     | Enable log analysis via SIEM              | NIST CSF DE.CM-7                 |


---


## Suggested Remediation

1. **Identity and Access Control**

   * Remove default credentials for admin panels and routers.
   * Enforce Multi-Factor Authentication (MFA) for all administrative and sensitive accounts.
   * Apply principle of least privilege through IAM and role-based controls.

2. **Network and Perimeter Security**

   * Enable and configure UFW or iptables on the Ubuntu VM.
   * Apply firewall rules to block unused ports at host, VM, and router level.
   * Disable remote administration features where unnecessary.

3. **System Hardening and Patching**

   * Ensure latest security patches are installed for OS and applications (Apache, MySQL).
   * Disable or remove unused services like CUPS Print Service.
   * Enable AppArmor or SELinux for OS-level security.

4. **Data Protection and Encryption**

   * Encrypt all backups and sensitive data in transit and at rest.
   * Move backup files and credentials outside web-accessible directories.
   * Use SSL/TLS certificates signed by trusted Certificate Authorities.

5. **Monitoring and Logging**

   * Centralize and secure log files with access control.
   * Monitor logs using SIEM tools and implement alert tuning.
   * Ensure audit trails are preserved and reviewed periodically.

6. **Secure Development Practices**

   * Conduct regular code reviews and vulnerability assessments.
   * Avoid hardcoding credentials; scan repositories for secrets.
   * Sanitize and validate user input to mitigate injection attacks.

7. **Security Awareness and Policy Enforcement**

   * Train employees, interns, and IT staff on social engineering and phishing.
   * Maintain updated and tested incident response and continuity plans.
   * Ensure compliance with ISO 27001, PCI DSS, GDPR, and DPDPA standards.

---
