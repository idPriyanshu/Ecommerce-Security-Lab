# E-commerce Security Assessment – Phase 2 (Risk & Compliance)

## Asset Register

- This asset register provides a comprehensive inventory of assets within the simulated e-commerce environment. It includes physical, digital, people, paper, service, and software assets — each critical to business operations and security.
- Every asset is categorized and assessed for sensitivity, which reflects the potential impact if the asset is compromised. The register includes both implemented components in the lab setup and conceptual elements to support broader security and compliance learning objectives.

| Asset ID   | Asset Name                      | Description                                                      | Category           | Location                                         | Sensitivity |
| ---------- | ------------------------------ | ---------------------------------------------------------------- | ------------------ | ------------------------------------------------ | ----------- |
| Asset-01   | Default Admin Account           | Built-in OpenCart admin identity                                 | People              | Web App Interface                                | High        |
| Asset-02   | Intern Users                    | Participants using personal laptops to run the simulation        | People              | Local Laptops                                    | Medium      |
| Asset-03   | Customers                       | External users purchasing from the platform                      | People              | Public Web Access                                | High        |
| Asset-04   | Security Analyst                | Simulated role responsible for monitoring and response           | People              | Security Function                                | High        |
| Asset-05   | Data Protection Officer         | Responsible for data governance and DPDPA compliance             | People              | Compliance Team                                  | High        |
| Asset-06   | IT Support Staff                | Provides support for systems and hardware                        | People              | Internal Team                                    | Medium      |
| Asset-07   | Compliance Officer              | Oversees regulatory compliance activities                        | People              | Compliance Team                                  | High        |
| Asset-08   | Cybersecurity Team              | Responsible for threat hunting, incident response, and hardening | People              | Security Department                              | High        |
| Asset-09   | Developer Team                  | Maintains and enhances OpenCart codebase                         | People              | Engineering                                      | High        |
| Asset-10   | OpenCart Web App                | Customer-facing e-commerce platform                              | Software           | /var/www/html                                    | High        |
| Asset-11   | OpenCart Admin Panel            | Backend management interface                                     | Software           | [http://localhost/admin](http://localhost/admin) | High        |
| Asset-12   | Customer Login Module           | Allows customers to access their account                         | Software           | /index.php?route=account/login                   | High        |
| Asset-13   | Password Reset Module           | Password recovery functionality                                  | Software           | /index.php?route=account/forgotten               | High        |
| Asset-14   | Apache Web Server               | Serves the OpenCart application                                  | Software           | Ubuntu VM                                        | High        |
| Asset-15   | MySQL Database                  | Stores application data                                          | Software           | Localhost:3306                                   | High        |
| Asset-16   | Ubuntu 22.04 OS                 | Operating system for the virtual environment                     | Software           | VMware VM                                        | Medium      |
| Asset-17   | CUPS Print Service              | Inactive printing service                                        | Software           | Ubuntu VM                                        | Medium      |
| Asset-18   | Cron Jobs                       | Automates backups and log rotation                               | Software           | /etc/cron.d/                                     | Low         |
| Asset-19   | Apache Config Files             | Controls behavior of Apache server                               | Digital            | /etc/apache2/                                    | Medium      |
| Asset-20   | Network Configuration           | Network settings and IP mappings                                 | Digital            | /etc/network/                                    | Medium      |
| Asset-21   | robots.txt File                 | Web crawler restriction file                                     | Digital            | /var/www/html                                    | Low         |
| Asset-22   | Uploaded Product Images         | Product media visible to users                                   | Digital            | /image/                                          | Medium      |
| Asset-23   | System Logs                     | Web server access and error logs                                 | Digital            | /var/log/apache2/                                | Medium      |
| Asset-24   | Authentication Logs             | Logs of user authentication attempts                             | Digital            | /var/log/auth.log                                | Medium      |
| Asset-25   | Audit Logs                      | Tracks system-level activities                                   | Digital            | /var/log/                                        | High        |
| Asset-26   | Customer Data                   | Personal and transaction information                             | Digital            | MySQL Database                                   | High        |
| Asset-27   | Admin Credentials               | OpenCart admin login details                                     | Digital            | Stored in Database                               | High        |
| Asset-28   | Customer Credentials            | Login data of customers                                          | Digital            | MySQL Database                                   | High        |
| Asset-29   | Backup Archives                 | Full application and database backups                            | Digital            | /var/www/html/storage                            | High        |
| Asset-30   | Developer Notes                 | Implementation and internal documentation                        | Paper              | GitHub/Git Readme                                | Low         |
| Asset-31   | Google Cloud Free Tier          | Cloud service for remote hosting                                 | Service            | cloud.google.com                                 | Medium      |
| Asset-32   | GitHub Repository               | Source code and version control                                  | Service            | github.com/project-repo                          | High        |
| Asset-33   | Payment Gateway Plugin          | Plugin for processing transactions (e.g., PayPal, Razorpay)      | Service            | Checkout Module                                  | High        |
| Asset-34   | Internet Service Provider       | Provides connectivity to host and VM                             | Service            | Home ISP                                         | Medium      |
| Asset-35   | Domain Registrar Account        | Manages domain ownership                                         | Service            | Domain Provider                                  | Medium      |
| Asset-36   | Open-source Security Tools      | Tools used for security testing (Nikto, Nmap)                    | Software           | Local Environment                                | Medium      |
| Asset-37   | Anti-Malware Software           | Endpoint protection                                              | Software           | Ubuntu VM & Host                                 | Medium      |
| Asset-38   | SSL Certificate (Self-signed)   | Enables encrypted HTTPS traffic                                  | Software           | Apache SSL Config                                | High        |
| Asset-39   | Session Management Mechanism    | Manages user sessions securely                                   | Software           | OpenCart Core                                    | High        |
| Asset-40   | Email Notification Module       | Sends order confirmations and alerts                             | Software           | OpenCart Module                                  | Medium      |
| Asset-41   | Paper Notes                     | Intern's handwritten documentation                               | Paper           | Physical Desk/Notebook                           | Low         |
| Asset-42   | Training Material               | Printed learning content                                         | Paper           | On Desk/Shared Folder                            | Low         |
| Asset-43   | Risk Assessment Report          | Threat and risk identification summary                           | Paper           | Security Folder                                  | High        |
| Asset-44   | Compliance Checklist            | Mapping of regulations to controls                               | Paper           | Security Folder                                  | High        |
| Asset-45   | Access Control Policy Document  | Defines who has access to what                                   | Paper           | Security Folder                                  | High        |
| Asset-46   | Incident Response Template      | Steps for managing a breach                                      | Paper           | Documentation Folder                             | Medium      |
| Asset-47   | Business Continuity Plan        | Ensures minimal disruption during disaster                       | Paper           | Documentation Folder                             | Medium      |
| Asset-48   | Privacy Policy                  | Outlines customer data usage and rights                          | Paper              | Public Web Folder                                | High        |
| Asset-49   | Company-Owned Laptops           | Inventory of 100 organizational laptops                          | Physical           | Inventory Sheet / Office                         | High        |
| Asset-50   | Network Switch                  | Hardware to connect multiple devices                             | Physical           | Server Room                                      | High        |
| Asset-51   | Internet Router                 | Gateway device connecting LAN to internet                        | Physical           | Physical router (e.g., 192.168.1.1)              | High        |
| Asset-52   | Firewall Appliance              | Provides network perimeter defense                               | Physical           | Perimeter/VM Host                                | High        |
| Asset-53   | Storage Server                  | Centralized backup and file storage                              | Physical           | Storage Device                                   | High        |
| Asset-54   | Audit Trail System              | Centralized logging system for auditing                          | Software           | /var/log/ or Syslog server                       | High        |

---

## Threats and Vulnerabilities
- This section identifies potential threats targeting each asset and the vulnerabilities that may be exploited by those threats. By linking threats to specific vulnerabilities and assets, this mapping enables accurate risk assessment and prioritization.
- Each entry includes a unique Threat ID, the associated Asset ID, a brief threat description, the specific vulnerability, its corresponding Vulnerability ID, and the impact if exploited.

| Threat ID   | Asset ID   | Threat Description                | Vulnerability                                   | Vulnerability ID | Impact  |
|-------------|------------|-----------------------------------|-------------------------------------------------|------------------|---------|
| Threat-001  | Asset-01   | Unauthorized Access               | Default credentials still active                | VULN-001         | High    |
| Threat-002  | Asset-01   | Brute Force Attack                | No CAPTCHA or login throttling                  | VULN-002         | High    |
| Threat-003  | Asset-01   | Privilege Escalation              | Default account has full privileges             | VULN-003         | High    |
| Threat-004  | Asset-01   | Enumeration                       | Username is predictable (`admin`)               | VULN-004         | Medium  |
| Threat-005  | Asset-02   | Insider Threat                    | Lack of awareness or intent-based misuse        | VULN-005         | High    |
| Threat-006  | Asset-02   | Unauthorized Access               | Excessive privileges or shared accounts         | VULN-006         | High    |
| Threat-007  | Asset-02   | Phishing Susceptibility           | No training or simulated testing                | VULN-007         | Medium  |
| Threat-008  | Asset-02   | Credential Mishandling            | Use of weak or reused passwords                 | VULN-008         | High    |
| Threat-009  | Asset-02   | Unauthorized Software Installation| Admin rights not restricted                     | VULN-009         | Medium  |
| Threat-010  | Asset-03   | Phishing & Credential Theft       | Use of reused or weak passwords                 | VULN-008         | Medium  |
| Threat-011  | Asset-03   | Account Takeover                  | No login anomaly detection                      | VULN-010         | High    |
| Threat-012  | Asset-03   | Data Privacy Violation            | Personal data shared with third parties         | VULN-011         | High    |
| Threat-013  | Asset-03   | Session Hijacking                 | No session timeout or secure cookie attributes  | VULN-012         | High    |
| Threat-014  | Asset-03   | Social Engineering                | Lack of user awareness                          | VULN-005         | Medium  |
| Threat-015  | Asset-04   | Delayed Threat Detection          | Manual log monitoring without automation        | VULN-013         | High    |
| Threat-016  | Asset-04   | Alert Fatigue                     | High volume of false positives                  | VULN-014         | Medium  |
| Threat-017  | Asset-04   | Insider Threat                    | Overprivileged access or unmonitored actions    | VULN-015         | High    |
| Threat-018  | Asset-04   | Skill Gap                         | Lack of threat hunting or analysis training     | VULN-016         | Medium  |
| Threat-019  | Asset-05   | Ineffective Governance            | Undefined responsibilities and authority        | VULN-017         | High    |
| Threat-020  | Asset-05   | Non-compliance Oversight          | Lack of visibility into processing activities   | VULN-018         | High    |
| Threat-021  | Asset-05   | Communication Gaps                | Inadequate interaction with stakeholders        | VULN-019         | Medium  |
| Threat-022  | Asset-05   | Training Negligence               | Failure to promote awareness within organization| VULN-020         | Medium  |
| Threat-023  | Asset-06   | Social Engineering                | Lack of security awareness and training         | VULN-021         | Medium  |
| Threat-024  | Asset-06   | Privilege Misuse                  | Excessive or poorly managed access rights       | VULN-022         | High    |
| Threat-025  | Asset-06   | Human Error                       | Incorrect system configurations or deletions    | VULN-023         | Medium  |
| Threat-026  | Asset-06   | Unlogged Support Actions          | Lack of activity logging and audit trails       | VULN-024         | Medium  |
| Threat-027  | Asset-07   | Missed Regulatory Changes         | No tracking mechanism for updates in regulations| VULN-025         | High    |
| Threat-028  | Asset-07   | Incomplete Compliance             | Lack of centralized checklist or status reporting| VULN-026         | High   |
| Threat-029  | Asset-07   | Poor Documentation                | Inadequate record-keeping of control status     | VULN-027         | Medium  |
| Threat-030  | Asset-07   | Role Overlap                      | Undefined boundaries with other roles           | VULN-028         | Medium  |
| Threat-031  | Asset-08   | Alert Fatigue                     | Too many low-priority or false-positive alerts  | VULN-014         | Medium  |
| Threat-032  | Asset-08   | Resource Misallocation            | Lack of threat triage and playbooks             | VULN-029         | High    |
| Threat-033  | Asset-08   | Inadequate Skillset               | Insufficient hands-on experience or upskilling  | VULN-016         | Medium  |
| Threat-034  | Asset-08   | Overdependence on Tools           | Reliance on automated detection without analysis| VULN-030         | High    |
| Threat-035  | Asset-09   | Insecure Coding Practices         | Lack of training in secure development          | VULN-031         | High    |
| Threat-036  | Asset-09   | Code Injection                    | Failure to sanitize inputs or outputs           | VULN-032         | High    |
| Threat-037  | Asset-09   | Hardcoded Secrets                 | Credentials embedded in code                    | VULN-033         | High    |
| Threat-038  | Asset-09   | Lack of Peer Review               | Code deployed without review                    | VULN-034         | Medium  |
| Threat-039  | Asset-09   | Source Code Leak                  | Uncontrolled repo sharing or public exposure    | VULN-035         | High    |
| Threat-040  | Asset-10   | XSS (Reflected/Stored)            | Unescaped user input in forms/comments          | VULN-036         | High    |
| Threat-041  | Asset-10   | SQL Injection                     | Lack of input sanitization in DB queries        | VULN-037         | High    |
| Threat-042  | Asset-10   | File Upload Attack                | No validation for uploaded images/files         | VULN-038         | High    |
| Threat-043  | Asset-10   | Business Logic Flaws              | Checkout manipulation, price tampering          | VULN-039         | Medium  |
| Threat-044  | Asset-11   | Brute Force Attack                | No CAPTCHA or login throttling                  | VULN-002         | High    |
| Threat-045  | Asset-11   | Default Credentials               | Admin/admin still active                        | VULN-001         | High    |
| Threat-046  | Asset-11   | Broken Access Control             | No RBAC, unrestricted access                    | VULN-040         | Medium  |
| Threat-047  | Asset-12   | Credential Stuffing               | No rate limiting or detection of reuse          | VULN-041         | Medium  |
| Threat-048  | Asset-12   | Weak Passwords                    | No enforcement of strong password policy        | VULN-042         | High    |
| Threat-049  | Asset-12   | No MFA                            | Single-factor authentication only               | VULN-043         | High    |
| Threat-050  | Asset-12   | Session Hijacking                 | Insecure session management (e.g., no timeout)  | VULN-012         | High    |
| Threat-051  | Asset-12   | Phishing                          | No alert or detection for credential reuse      | VULN-044         | Medium  |
| Threat-052  | Asset-13   | Token Prediction                  | Weak or guessable reset tokens                  | VULN-045         | High    |
| Threat-053  | Asset-13   | Token Reuse                       | Tokens not invalidated after use                | VULN-046         | High    |
| Threat-054  | Asset-13   | Insecure Transmission             | Token sent over HTTP instead of HTTPS           | VULN-047         | High    |
| Threat-055  | Asset-13   | Enumeration Attacks               | Reset form reveals user existence               | VULN-048         | Medium  |
| Threat-056  | Asset-13   | Missing Logging                   | Password reset not logged or monitored          | VULN-049         | Medium  |
| Threat-057  | Asset-14   | Remote Code Execution             | World-writable web root and outdated PHP        | VULN-050         | High    |
| Threat-058  | Asset-14   | Directory Traversal               | Improper file path validation                   | VULN-051         | High    |
| Threat-059  | Asset-14   | Information Disclosure            | `phpinfo.php` file accessible                   | VULN-052         | Medium  |
| Threat-060  | Asset-14   | Missing Security Headers          | Lacking CSP, X-Frame-Options                    | VULN-053         | High    |
| Threat-061  | Asset-15   | Unauthorized Root Access          | No password for root via `sudo mysql`           | VULN-054         | High    |
| Threat-062  | Asset-15   | SQL Injection                     | Dynamic queries without sanitization            | VULN-037         | High    |
| Threat-063  | Asset-15   | Weak Authentication               | Default user credentials and no password policy | VULN-055         | High    |
| Threat-064  | Asset-15   | Network Exposure                  | MySQL listening on all interfaces               | VULN-056         | High    |
| Threat-065  | Asset-16   | OS Exploits                       | Outdated packages, firewall disabled            | VULN-057         | High    |
| Threat-066  | Asset-16   | Privilege Escalation              | Kernel vulnerabilities                          | VULN-058         | High    |
| Threat-067  | Asset-17   | Port Exploitation                 | Port 631 open unnecessarily                     | VULN-059         | Medium  |
| Threat-068  | Asset-18   | Unauthorized Job Addition         | No permission control                           | VULN-060         | Medium  |
| Threat-069  | Asset-18   | Task Tampering                    | Logs or timing manipulated                      | VULN-061         | Medium  |
| Threat-070  | Asset-19   | Unauthorized Modification         | World-writable config files                     | VULN-062         | High    |
| Threat-071  | Asset-19   | Information Disclosure            | Backup/config files exposed via web server      | VULN-063         | High    |
| Threat-072  | Asset-19   | Misconfiguration                  | Directory listing enabled, indexes not disabled | VULN-064         | Medium  |
| Threat-073  | Asset-19   | Lack of TLS Enforcement           | HTTP allowed or redirect misconfigured          | VULN-065         | High    |
| Threat-074  | Asset-19   | Logging Misconfiguration          | No error/access logging or excessive logging    | VULN-066         | Medium  |
| Threat-075  | Asset-20   | Misrouting or Exposure            | Weak NAT or port forwarding                     | VULN-067         | High    |
| Threat-076  | Asset-20   | Lateral Movement                  | Open services not filtered                      | VULN-068         | High    |
| Threat-077  | Asset-21   | Information Disclosure            | Reveals admin or sensitive paths                | VULN-069         | Medium  |
| Threat-078  | Asset-21   | Crawling Hidden Pages             | Allows enumeration of parameterized URLs        | VULN-070         | Medium  |
| Threat-079  | Asset-22   | Malware Upload                    | No file sanitization or AV scan                 | VULN-071         | High    |
| Threat-080  | Asset-22   | Overwrite or Abuse                | Same filename uploaded repeatedly               | VULN-072         | Medium  |
| Threat-081  | Asset-23   | Log Tampering                     | Writable by unauthorized users                  | VULN-073         | High    |
| Threat-082  | Asset-23   | Log Overwrite                     | Log rotation misconfigured                      | VULN-074         | Medium  |
| Threat-083  | Asset-23   | Insufficient Retention            | Logs purged before required retention period    | VULN-075         | High    |
| Threat-084  | Asset-23   | Missing Monitoring                | Logs not reviewed regularly                     | VULN-076         | Medium  |
| Threat-085  | Asset-23   | Information Disclosure            | Sensitive data logged (e.g., passwords)         | VULN-077         | High    |
| Threat-086  | Asset-24   | Log Tampering                     | Logs can be altered or deleted by attackers     | VULN-078         | High    |
| Threat-087  | Asset-24   | Lack of Log Review                | Login anomalies not detected                    | VULN-079         | High    |
| Threat-088  | Asset-24   | Incomplete Logging                | Failed/successful login events not captured     | VULN-080         | Medium  |
| Threat-089  | Asset-24   | Sensitive Data Exposure           | Logging of passwords or tokens in plaintext     | VULN-081         | High    |
| Threat-090  | Asset-24   | Unauthorized Access               | Logs accessible by non-privileged users         | VULN-082         | High    |
| Threat-091  | Asset-25   | Log Tampering                     | Logs not protected against modification         | VULN-083         | High    |
| Threat-092  | Asset-25   | Incomplete Coverage               | Critical system events not audited              | VULN-084         | High    |
| Threat-093  | Asset-25   | Insufficient Retention            | Logs deleted before meeting regulatory requirements | VULN-075      | High |
| Threat-094  | Asset-25   | No Alerting or Review             | Logs not analyzed for suspicious activity       | VULN-085         | Medium  |
| Threat-095  | Asset-25   | Exposure of Sensitive Data        | PII or credentials logged without masking       | VULN-086         | High    |
| Threat-096  | Asset-26   | Data Breach                       | Stored in plaintext or weak encryption          | VULN-087         | High    |
| Threat-097  | Asset-26   | Unauthorized Access               | Excessive privileges or missing ACLs            | VULN-088         | High    |
| Threat-098  | Asset-26   | Insider Threat                    | Access to sensitive data without monitoring     | VULN-089         | High    |
| Threat-099  | Asset-26   | Injection Attacks                 | SQL injection or insecure queries               | VULN-037         | High    |
| Threat-100  | Asset-27   | Credential Theft                  | Weak or default credentials stored in DB        | VULN-090         | High    |
| Threat-101  | Asset-27   | Insecure Storage                  | Credentials stored as plaintext/broken hash     | VULN-091         | High    |
| Threat-102  | Asset-27   | Database Exposure                 | Admin table accessible via SQL injection        | VULN-092         | High    |
| Threat-103  | Asset-28   | Brute Force Login                 | No account lockout, weak passwords              | VULN-093         | High    |
| Threat-104  | Asset-28   | Credential Reuse                  | Same password across accounts                   | VULN-094         | Medium  |
| Threat-105  | Asset-28   | Insecure Reset Process            | Weak password reset token                       | VULN-045         | High    |
| Threat-106  | Asset-29   | Data Tampering                    | Backups unencrypted and publicly accessible     | VULN-095         | High    |
| Threat-107  | Asset-29   | Ransomware Targeting              | Backup folders writable and visible             | VULN-096         | High    |
| Threat-108  | Asset-29   | Data Loss                         | No versioning or integrity verification         | VULN-097         | High    |
| Threat-109  | Asset-30   | Information Disclosure            | Hardcoded credentials or secrets                | VULN-033         | Medium  |
| Threat-110  | Asset-31   | Misconfigured Buckets             | Public data exposure                            | VULN-098         | High    |
| Threat-111  | Asset-32   | Source Code Leak                  | Public repository or shared access              | VULN-035         | High    |
| Threat-112  | Asset-32   | Secrets Exposure                  | Hardcoded secrets, credentials in code          | VULN-033         | High    |
| Threat-113  | Asset-32   | Insecure Commits                  | Committing sensitive config or keys             | VULN-099         | High    |
| Threat-114  | Asset-32   | Supply Chain Attack               | Unverified dependencies in `package.json`       | VULN-100         | High    |
| Threat-115  | Asset-32   | Repository Takeover               | Weak GitHub account security                    | VULN-101         | High    |
| Threat-116  | Asset-33   | Transaction Hijacking             | Insecure communication or improper request validation | VULN-102    | High |
| Threat-117  | Asset-33   | Man-in-the-Middle (MITM)          | Self-signed or expired SSL certificate          | VULN-103         | High    |
| Threat-118  | Asset-33   | API Abuse                         | No rate limiting or authentication for API endpoints | VULN-104    | High |
| Threat-119  | Asset-33   | Improper Error Handling           | Debug errors expose sensitive transaction details | VULN-105     | Medium |
| Threat-120  | Asset-33   | Lack of Logging                   | No transaction audit trail maintained           | VULN-106         | Medium  |
| Threat-121  | Asset-34   | Service Interruption              | No redundancy or failover in ISP connection     | VULN-107         | High    |
| Threat-122  | Asset-34   | DNS Hijacking                     | ISP-provided DNS servers are compromised        | VULN-108         | High    |
| Threat-123  | Asset-34   | Unencrypted Traffic               | ISP-level monitoring of unencrypted HTTP traffic| VULN-109         | High    |
| Threat-124  | Asset-34   | IP Address Reassignment           | Static IP not reserved, leading to session hijack issues | VULN-110 | Medium |
| Threat-125  | Asset-34   | Bandwidth Throttling              | ISP restricts traffic during high load periods  | VULN-111         | Medium  |
| Threat-126  | Asset-35   | Account Takeover                  | Weak password, no MFA                           | VULN-112         | High    |
| Threat-127  | Asset-36   | False Positives                   | Alerts not validated, causing alert fatigue     | VULN-113         | Medium  |
| Threat-128  | Asset-36   | Outdated Signatures               | Lack of timely updates for detection engines    | VULN-114         | High    |
| Threat-129  | Asset-36   | Misconfiguration                  | Improper setup leading to missed detections     | VULN-115         | High    |
| Threat-130  | Asset-36   | Insecure Deployment               | Tools exposed to internet without hardening     | VULN-116         | High    |
| Threat-131  | Asset-36   | Data Leakage                      | Logs or results stored insecurely               | VULN-117         | Medium  |
| Threat-132  | Asset-37   | Inactive Protection               | No update mechanism                             | VULN-118         | Medium  |
| Threat-133  | Asset-38   | MITM Attack                       | Self-signed cert not trusted by browsers        | VULN-103         | High    |
| Threat-134  | Asset-38   | Certificate Spoofing              | No certificate pinning                          | VULN-119         | Medium  |
| Threat-135  | Asset-38   | Expired Certificate               | Lack of renewal monitoring                      | VULN-120         | Medium  |
| Threat-136  | Asset-38   | Weak Cipher Suites                | Using outdated encryption algorithms            | VULN-121         | High    |
| Threat-137  | Asset-39   | Session Hijacking                 | Missing `HttpOnly` / `Secure` flags on cookies  | VULN-122         | High    |
| Threat-138  | Asset-39   | Session Fixation                  | Session ID not regenerated after login          | VULN-123         | High    |
| Threat-139  | Asset-39   | Session Timeout Abuse             | Long-lived or infinite session expiry           | VULN-124         | Medium  |
| Threat-140  | Asset-39   | Predictable IDs                   | Weak or guessable session identifiers           | VULN-125         | Medium  |
| Threat-141  | Asset-39   | Insecure Storage                  | Session data stored in client-side cookies      | VULN-126         | High    |
| Threat-142  | Asset-40   | Spam Relay                        | Misconfigured SMTP settings                     | VULN-127         | Medium  |
| Threat-143  | Asset-41   | Physical Theft                    | Contains passwords or architecture details      | VULN-128         | Medium  |
| Threat-144  | Asset-42   | Knowledge Leakage                 | Shared externally without authorization         | VULN-129         | Medium  |
| Threat-145  | Asset-42   | Outdated Content                  | Stale or incorrect security procedures          | VULN-130         | Medium  |
| Threat-146  | Asset-42   | Unauthorized Access               | Publicly accessible LMS or shared drives        | VULN-131         | Medium  |
| Threat-147  | Asset-42   | Compliance Deviation              | Incomplete coverage of compliance requirements  | VULN-132         | High    |
| Threat-148  | Asset-43   | Unauthorized Modification         | No version control or access restriction        | VULN-133         | Medium  |
| Threat-149  | Asset-43   | Data Leakage                      | Shared via unsecured channels                   | VULN-134         | High    |
| Threat-150  | Asset-43   | Loss of Availability              | File corruption or accidental deletion          | VULN-135         | Medium  |
| Threat-151  | Asset-43   | Integrity Tampering               | Manual edits without audit trail                | VULN-136         | Medium  |
| Threat-152  | Asset-44   | Non-compliance                    | Checklist is outdated or incomplete             | VULN-137         | High    |
| Threat-153  | Asset-44   | Audit Failure                     | Checklist not aligned with actual control status| VULN-138         | High    |
| Threat-154  | Asset-44   | Unauthorized Access               | Checklist editable by unauthorized users        | VULN-139         | Medium  |
| Threat-155  | Asset-44   | Lack of Evidence Mapping          | Controls not linked to documented proof         | VULN-140         | High    |
| Threat-156  | Asset-45   | Policy Bypass                     | Policy exists but not enforced technically      | VULN-141         | High    |
| Threat-157  | Asset-45   | Unauthorized Modification         | Document is editable by unauthorized personnel  | VULN-142         | Medium  |
| Threat-158  | Asset-45   | Outdated Definitions              | Policy not updated with system architecture     | VULN-143         | Medium  |
| Threat-159  | Asset-45   | Lack of Awareness                 | Employees unaware of access policy guidelines   | VULN-144         | Medium  |
| Threat-160  | Asset-46   | Delay in Response                 | Incomplete or outdated IR plan                  | VULN-145         | High    |
| Threat-161  | Asset-46   | Missed Escalations                | No defined escalation procedures                | VULN-146         | High    |
| Threat-162  | Asset-46   | Lack of Awareness                 | Employees unaware of IR process                 | VULN-147         | Medium  |
| Threat-163  | Asset-46   | Unauthorized Access               | Template file not access restricted             | VULN-148         | Medium  |
| Threat-164  | Asset-47   | Operational Disruption            | Outdated or untested continuity procedures      | VULN-149         | High    |
| Threat-165  | Asset-47   | Lack of Role Clarity              | Undefined roles and responsibilities in crisis  | VULN-150         | High    |
| Threat-166  | Asset-47   | Inaccessible Documentation        | BCP stored only on internal systems             | VULN-151         | Medium  |
| Threat-167  | Asset-47   | Data Recovery Failure             | Recovery steps not aligned with IT and data systems | VULN-152      | High |
| Threat-168  | Asset-48   | Legal Non-compliance              | Outdated or missing privacy clauses             | VULN-153         | High    |
| Threat-169  | Asset-48   | Lack of Transparency              | Unclear data collection and usage disclosures   | VULN-154         | High    |
| Threat-170  | Asset-48   | Unauthorized Modifications        | Policy page editable without approval           | VULN-155         | Medium  |
| Threat-171  | Asset-48   | Inaccessible to Users             | Not linked prominently or not available in regional language | VULN-156 | Medium |
| Threat-172  | Asset-49   | Malware Infection                 | No antivirus or endpoint protection             | VULN-157         | High    |
| Threat-173  | Asset-49   | Data Theft/Loss                   | No full disk encryption                         | VULN-158         | High    |
| Threat-174  | Asset-49   | Unauthorized Access               | Shared devices, weak login credentials          | VULN-159         | High    |
| Threat-175  | Asset-49   | Lack of Updates                   | Unpatched OS and software                       | VULN-160         | High    |
| Threat-176  | Asset-49   | Physical Theft                    | Devices left unattended or unsecured            | VULN-128         | Medium  |
| Threat-177  | Asset-49   | Insecure Configuration            | Admin rights for users, services enabled by default | VULN-161      | High |
| Threat-178  | Asset-50   | Unauthorized Access               | Default credentials or no access control        | VULN-001         | High    |
| Threat-179  | Asset-50   | VLAN Hopping                      | Improper VLAN configuration                     | VULN-162         | High    |
| Threat-180  | Asset-50   | SNMP Exploitation                 | SNMP community strings are default/public       | VULN-163         | High    |
| Threat-181  | Asset-50   | Firmware Vulnerabilities          | Outdated firmware with known exploits           | VULN-164         | High    |
| Threat-182  | Asset-50   | Physical Tampering                | Unsecured access to switch ports                | VULN-165         | Medium  |
| Threat-183  | Asset-51   | Unauthorized Access               | Default admin credentials active                | VULN-001         | High    |
| Threat-184  | Asset-51   | DoS Attack                        | No firewall or rate limit settings              | VULN-166         | Medium  |
| Threat-185  | Asset-52   | Misconfiguration                  | Unnecessary ports/services left open            | VULN-167         | High    |
| Threat-186  | Asset-52   | Insecure Remote Access            | Remote admin enabled without MFA                | VULN-043         | High    |
| Threat-187  | Asset-52   | Outdated Firmware                 | Unpatched vulnerabilities in firewall OS        | VULN-168         | High    |
| Threat-188  | Asset-52   | Rule Shadowing                    | Conflicting or redundant rules                  | VULN-169         | Medium  |
| Threat-189  | Asset-52   | Logging Disabled                  | Lack of traffic monitoring or alerting          | VULN-170         | Medium  |
| Threat-190  | Asset-53   | Data Corruption                   | No redundancy, no integrity verification        | VULN-171         | High    |
| Threat-191  | Asset-53   | Unauthorized Access               | Inadequate access controls or shared credentials| VULN-172         | High    |
| Threat-192  | Asset-53   | Ransomware Infection              | Files accessible from compromised endpoint      | VULN-173         | High    |
| Threat-193  | Asset-53   | Lack of Backup                    | No periodic or offsite backups                  | VULN-174         | High    |
| Threat-194  | Asset-53   | Insecure File Sharing             | Shares exposed over SMB/NFS without encryption  | VULN-175         | Medium  |
| Threat-195  | Asset-54   | Log Tampering                     | No integrity or immutability controls           | VULN-176         | High    |
| Threat-196  | Asset-54   | Insufficient Retention            | Logs rotated or deleted early                   | VULN-075         | High    |
| Threat-197  | Asset-54   | Missing Monitoring                | Logs not reviewed or alerted                    | VULN-076         | Medium  |

---

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

## Risk Assessment

- This section evaluates the security risks associated with each asset by analyzing the threats and their corresponding vulnerabilities. Each risk entry is derived from a specific combination of an asset, a threat targeting that asset, and the vulnerability being exploited.
- The Risk Level is calculated based on the Likelihood and Impact of the threat materializing, along with the Sensitivity of the asset. The goal is to prioritize which risks require immediate mitigation and compliance mapping.

| Risk ID   | Asset ID   | Threat ID   | Vulnerability ID | Likelihood | Impact  | Sensitivity | Risk Level |
|-----------|------------|-------------|------------------|------------|---------|-------------|-----------|
| Risk-001  | Asset-01   | Threat-001  | VULN-001         | High       | High    | High        | Critical  |
| Risk-002  | Asset-01   | Threat-002  | VULN-002         | High       | High    | High        | Critical  |
| Risk-003  | Asset-01   | Threat-003  | VULN-003         | Medium     | High    | High        | High      |
| Risk-004  | Asset-01   | Threat-004  | VULN-004         | Medium     | Medium  | High        | Medium    |
| Risk-005  | Asset-02   | Threat-005  | VULN-005         | Medium     | High    | Medium      | High      |
| Risk-006  | Asset-02   | Threat-006  | VULN-006         | Medium     | High    | Medium      | High      |
| Risk-007  | Asset-02   | Threat-007  | VULN-007         | Medium     | Medium  | Medium      | Medium    |
| Risk-008  | Asset-02   | Threat-008  | VULN-008         | Medium     | High    | Medium      | High      |
| Risk-009  | Asset-02   | Threat-009  | VULN-009         | Medium     | Medium  | Medium      | Medium    |
| Risk-010  | Asset-03   | Threat-010  | VULN-008         | High       | Medium  | High        | High      |
| Risk-011  | Asset-03   | Threat-011  | VULN-010         | Medium     | High    | High        | High      |
| Risk-012  | Asset-03   | Threat-012  | VULN-011         | Medium     | High    | High        | High      |
| Risk-013  | Asset-03   | Threat-013  | VULN-012         | Medium     | High    | High        | High      |
| Risk-014  | Asset-03   | Threat-014  | VULN-005         | Medium     | Medium  | High        | Medium    |
| Risk-015  | Asset-04   | Threat-015  | VULN-013         | Medium     | High    | High        | High      |
| Risk-016  | Asset-04   | Threat-016  | VULN-014         | Medium     | Medium  | High        | Medium    |
| Risk-017  | Asset-04   | Threat-017  | VULN-015         | Low        | High    | High        | Medium    |
| Risk-018  | Asset-04   | Threat-018  | VULN-016         | Medium     | Medium  | High        | Medium    |
| Risk-019  | Asset-05   | Threat-019  | VULN-017         | Medium     | High    | High        | High      |
| Risk-020  | Asset-05   | Threat-020  | VULN-018         | Medium     | High    | High        | High      |
| Risk-021  | Asset-05   | Threat-021  | VULN-019         | Low        | Medium  | High        | Medium    |
| Risk-022  | Asset-05   | Threat-022  | VULN-020         | Medium     | Medium  | High        | Medium    |
| Risk-023  | Asset-06   | Threat-023  | VULN-021         | Medium     | Medium  | Medium      | Medium    |
| Risk-024  | Asset-06   | Threat-024  | VULN-022         | Medium     | High    | Medium      | High      |
| Risk-025  | Asset-06   | Threat-025  | VULN-023         | Medium     | Medium  | Medium      | Medium    |
| Risk-026  | Asset-06   | Threat-026  | VULN-024         | Medium     | Medium  | Medium      | Medium    |
| Risk-027  | Asset-07   | Threat-027  | VULN-025         | Medium     | High    | High        | High      |
| Risk-028  | Asset-07   | Threat-028  | VULN-026         | Medium     | High    | High        | High      |
| Risk-029  | Asset-07   | Threat-029  | VULN-027         | Medium     | Medium  | High        | Medium    |
| Risk-030  | Asset-07   | Threat-030  | VULN-028         | Low        | Medium  | High        | Medium    |
| Risk-031  | Asset-08   | Threat-031  | VULN-014         | Medium     | Medium  | High        | Medium    |
| Risk-032  | Asset-08   | Threat-032  | VULN-029         | Medium     | High    | High        | High      |
| Risk-033  | Asset-08   | Threat-033  | VULN-016         | Medium     | Medium  | High        | Medium    |
| Risk-034  | Asset-08   | Threat-034  | VULN-030         | Medium     | High    | High        | High      |
| Risk-035  | Asset-09   | Threat-035  | VULN-031         | Medium     | High    | High        | High      |
| Risk-036  | Asset-09   | Threat-036  | VULN-032         | Medium     | High    | High        | High      |
| Risk-037  | Asset-09   | Threat-037  | VULN-033         | High       | High    | High        | Critical  |
| Risk-038  | Asset-09   | Threat-038  | VULN-034         | Medium     | Medium  | High        | Medium    |
| Risk-039  | Asset-09   | Threat-039  | VULN-035         | Medium     | High    | High        | High      |
| Risk-040  | Asset-10   | Threat-040  | VULN-036         | Medium     | High    | High        | High      |
| Risk-041  | Asset-10   | Threat-041  | VULN-037         | Medium     | High    | High        | High      |
| Risk-042  | Asset-10   | Threat-042  | VULN-038         | Medium     | High    | High        | High      |
| Risk-043  | Asset-10   | Threat-043  | VULN-039         | Medium     | Medium  | High        | Medium    |
| Risk-044  | Asset-11   | Threat-044  | VULN-002         | High       | High    | High        | Critical  |
| Risk-045  | Asset-11   | Threat-045  | VULN-001         | High       | High    | High        | Critical  |
| Risk-046  | Asset-11   | Threat-046  | VULN-040         | High       | Medium  | High        | High      |
| Risk-047  | Asset-12   | Threat-047  | VULN-041         | High       | Medium  | High        | High      |
| Risk-048  | Asset-12   | Threat-048  | VULN-042         | High       | High    | High        | Critical  |
| Risk-049  | Asset-12   | Threat-049  | VULN-043         | Medium     | High    | High        | High      |
| Risk-050  | Asset-12   | Threat-050  | VULN-012         | Medium     | High    | High        | High      |
| Risk-051  | Asset-12   | Threat-051  | VULN-044         | Medium     | Medium  | High        | Medium    |
| Risk-052  | Asset-13   | Threat-052  | VULN-045         | Medium     | High    | High        | High      |
| Risk-053  | Asset-13   | Threat-053  | VULN-046         | Medium     | High    | High        | High      |
| Risk-054  | Asset-13   | Threat-054  | VULN-047         | High       | High    | High        | Critical  |
| Risk-055  | Asset-13   | Threat-055  | VULN-048         | Medium     | Medium  | High        | Medium    |
| Risk-056  | Asset-13   | Threat-056  | VULN-049         | Medium     | Medium  | High        | Medium    |
| Risk-057 | Asset-14   | Threat-057  | VULN-050         | High       | High    | High        | Critical   |
| Risk-058 | Asset-14   | Threat-058  | VULN-051         | Medium     | High    | High        | High       |
| Risk-059 | Asset-14   | Threat-059  | VULN-052         | Medium     | Medium  | High        | Medium     |
| Risk-060 | Asset-14   | Threat-060  | VULN-053         | Medium     | High    | High        | High       |
| Risk-061 | Asset-15   | Threat-061  | VULN-054         | High       | High    | High        | Critical   |
| Risk-062 | Asset-15   | Threat-062  | VULN-037         | Medium     | High    | High        | High       |
| Risk-063 | Asset-15   | Threat-063  | VULN-055         | High       | High    | High        | Critical   |
| Risk-064 | Asset-15   | Threat-064  | VULN-056         | Medium     | High    | High        | High       |
| Risk-065 | Asset-16   | Threat-065  | VULN-057         | Medium     | High    | Medium      | High       |
| Risk-066 | Asset-16   | Threat-066  | VULN-058         | Medium     | High    | Medium      | High       |
| Risk-067 | Asset-17   | Threat-067  | VULN-059         | Medium     | Medium  | Medium      | Medium     |
| Risk-068 | Asset-18   | Threat-068  | VULN-060         | Low        | Medium  | Low         | Medium     |
| Risk-069 | Asset-18   | Threat-069  | VULN-061         | Medium     | Medium  | Low         | Medium     |
| Risk-070 | Asset-19   | Threat-070  | VULN-062         | Medium     | High    | Medium      | High       |
| Risk-071 | Asset-19   | Threat-071  | VULN-063         | Medium     | High    | Medium      | High       |
| Risk-072 | Asset-19   | Threat-072  | VULN-064         | Medium     | Medium  | Medium      | Medium     |
| Risk-073 | Asset-19   | Threat-073  | VULN-065         | Medium     | High    | Medium      | High       |
| Risk-074 | Asset-19   | Threat-074  | VULN-066         | Low        | Medium  | Medium      | Medium     |
| Risk-075 | Asset-20   | Threat-075  | VULN-067         | Medium     | High    | Medium      | High       |
| Risk-076 | Asset-20   | Threat-076  | VULN-068         | Medium     | High    | Medium      | High       |
| Risk-077 | Asset-21   | Threat-077  | VULN-069         | Low        | Medium  | Low         | Medium     |
| Risk-078 | Asset-21   | Threat-078  | VULN-070         | Medium     | Medium  | Low         | Medium     |
| Risk-079 | Asset-22   | Threat-079  | VULN-071         | Medium     | High    | Medium      | High       |
| Risk-080 | Asset-22   | Threat-080  | VULN-072         | Medium     | Medium  | Medium      | Medium     |
| Risk-081 | Asset-23   | Threat-081  | VULN-073         | High       | High    | Medium      | Critical   |
| Risk-082 | Asset-23   | Threat-082  | VULN-074         | Medium     | Medium  | Medium      | Medium     |
| Risk-083 | Asset-23   | Threat-083  | VULN-075         | Medium     | High    | Medium      | High       |
| Risk-084 | Asset-23   | Threat-084  | VULN-076         | Medium     | Medium  | Medium      | Medium     |
| Risk-085 | Asset-23   | Threat-085  | VULN-077         | Medium     | High    | Medium      | High       |
| Risk-086 | Asset-24   | Threat-086  | VULN-078         | High       | High    | Medium      | Critical   |
| Risk-087 | Asset-24   | Threat-087  | VULN-079         | Medium     | High    | Medium      | High       |
| Risk-088 | Asset-24   | Threat-088  | VULN-080         | Medium     | Medium  | Medium      | Medium     |
| Risk-089 | Asset-24   | Threat-089  | VULN-081         | Medium     | High    | Medium      | High       |
| Risk-090 | Asset-24   | Threat-090  | VULN-082         | Medium     | High    | Medium      | High       |
| Risk-091 | Asset-25   | Threat-091  | VULN-083         | High       | High    | High        | Critical   |
| Risk-092 | Asset-25   | Threat-092  | VULN-084         | Medium     | High    | High        | High       |
| Risk-093 | Asset-25   | Threat-093  | VULN-075         | Medium     | High    | High        | High       |
| Risk-094 | Asset-25   | Threat-094  | VULN-085         | Medium     | Medium  | High        | Medium     |
| Risk-095 | Asset-25   | Threat-095  | VULN-086         | Medium     | High    | High        | High       |
| Risk-096 | Asset-26   | Threat-096  | VULN-087         | High       | High    | High        | Critical   |
| Risk-097 | Asset-26   | Threat-097  | VULN-088         | High       | High    | High        | Critical   |
| Risk-098 | Asset-26   | Threat-098  | VULN-089         | Medium     | High    | High        | High       |
| Risk-099 | Asset-26   | Threat-099  | VULN-037         | Medium     | High    | High        | High       |
| Risk-100 | Asset-27   | Threat-100  | VULN-090         | High       | High    | High        | Critical   |
| Risk-101 | Asset-27   | Threat-101  | VULN-091         | High       | High    | High        | Critical   |
| Risk-102 | Asset-27   | Threat-102  | VULN-092         | Medium     | High    | High        | High       |
| Risk-103 | Asset-28   | Threat-103  | VULN-093         | High       | High    | High        | Critical   |
| Risk-104 | Asset-28   | Threat-104  | VULN-094         | Medium     | Medium  | High        | Medium     |
| Risk-105 | Asset-28   | Threat-105  | VULN-045         | Medium     | High    | High        | High       |
| Risk-106 | Asset-29   | Threat-106  | VULN-095         | High       | High    | High        | Critical   |
| Risk-107 | Asset-29   | Threat-107  | VULN-096         | Medium     | High    | High        | High       |
| Risk-108 | Asset-29   | Threat-108  | VULN-097         | Medium     | High    | High        | High       |
| Risk-109 | Asset-30   | Threat-109  | VULN-033         | Medium     | Medium  | Low         | Medium     |
| Risk-110 | Asset-31   | Threat-110  | VULN-098         | Medium     | High    | Medium      | High       |
| Risk-111 | Asset-32   | Threat-111  | VULN-035         | Medium     | High    | High        | High       |
| Risk-112 | Asset-32   | Threat-112  | VULN-033         | High       | High    | High        | Critical   |
| Risk-113 | Asset-32   | Threat-113  | VULN-099         | Medium     | High    | High        | High       |
| Risk-114 | Asset-32   | Threat-114  | VULN-100         | Medium     | High    | High        | High       |
| Risk-115 | Asset-32   | Threat-115  | VULN-101         | Medium     | High    | High        | High       |
| Risk-116 | Asset-33   | Threat-116  | VULN-102         | Medium     | High    | High        | High       |
| Risk-117 | Asset-33   | Threat-117  | VULN-103         | Medium     | High    | High        | High       |
| Risk-118 | Asset-33   | Threat-118  | VULN-104         | Medium     | High    | High        | High       |
| Risk-119 | Asset-33   | Threat-119  | VULN-105         | Low        | Medium  | High        | Medium     |
| Risk-120 | Asset-33   | Threat-120  | VULN-106         | Medium     | Medium  | High        | Medium     |
| Risk-121 | Asset-34   | Threat-121  | VULN-107         | Medium     | High    | Medium      | High       |
| Risk-122 | Asset-34   | Threat-122  | VULN-108         | Medium     | High    | Medium      | High       |
| Risk-123 | Asset-34   | Threat-123  | VULN-109         | Medium     | High    | Medium      | High       |
| Risk-124 | Asset-34   | Threat-124  | VULN-110         | Low        | Medium  | Medium      | Medium     |
| Risk-125 | Asset-34   | Threat-125  | VULN-111         | Medium     | Medium  | Medium      | Medium     |
| Risk-126 | Asset-35   | Threat-126  | VULN-112         | Medium     | High    | Medium      | High       |
| Risk-127 | Asset-36   | Threat-127  | VULN-113         | Medium     | Medium  | Medium      | Medium     |
| Risk-128 | Asset-36   | Threat-128  | VULN-114         | Medium     | High    | Medium      | High       |
| Risk-129 | Asset-36   | Threat-129  | VULN-115         | Medium     | High    | Medium      | High       |
| Risk-130 | Asset-36   | Threat-130  | VULN-116         | Medium     | High    | Medium      | High       |
| Risk-131 | Asset-36   | Threat-131  | VULN-117         | Medium     | Medium  | Medium      | Medium     |
| Risk-132 | Asset-37   | Threat-132  | VULN-118         | Medium     | Medium  | Medium      | Medium     |
| Risk-133 | Asset-38   | Threat-133  | VULN-103         | Medium     | High    | High        | High       |
| Risk-134 | Asset-38   | Threat-134  | VULN-119         | Medium     | Medium  | High        | Medium     |
| Risk-135 | Asset-38   | Threat-135  | VULN-120         | Medium     | Medium  | High        | Medium     |
| Risk-136 | Asset-38   | Threat-136  | VULN-121         | Medium     | High    | High        | High       |
| Risk-137 | Asset-39   | Threat-137  | VULN-122         | Medium     | High    | High        | High       |
| Risk-138 | Asset-39   | Threat-138  | VULN-123         | Medium     | High    | High        | High       |
| Risk-139 | Asset-39   | Threat-139  | VULN-124         | Medium     | Medium  | High        | Medium     |
| Risk-140 | Asset-39   | Threat-140  | VULN-125         | Low        | High    | High        | Medium     |
| Risk-141 | Asset-39   | Threat-141  | VULN-126         | Medium     | High    | High        | High       |
| Risk-142 | Asset-40   | Threat-142  | VULN-127         | Medium     | Medium  | Medium      | Medium     |
| Risk-143 | Asset-41   | Threat-143  | VULN-128         | Medium     | Medium  | Low         | Medium     |
| Risk-144 | Asset-42   | Threat-144  | VULN-129         | Medium     | Medium  | Low         | Medium     |
| Risk-145 | Asset-42   | Threat-145  | VULN-130         | Medium     | Medium  | Low         | Medium     |
| Risk-146 | Asset-42   | Threat-146  | VULN-131         | Medium     | Medium  | Low         | Medium     |
| Risk-147 | Asset-42   | Threat-147  | VULN-132         | Medium     | High    | Low         | High       |
| Risk-148 | Asset-43   | Threat-148  | VULN-133         | Medium     | Medium  | High        | Medium     |
| Risk-149 | Asset-43   | Threat-149  | VULN-134         | Medium     | High    | High        | High       |
| Risk-150 | Asset-43   | Threat-150  | VULN-135         | Medium     | Medium  | High        | Medium     |
| Risk-151 | Asset-43   | Threat-151  | VULN-136         | Medium     | Medium  | High        | Medium     |
| Risk-152 | Asset-44   | Threat-152  | VULN-137         | Medium     | High    | High        | High       |
| Risk-153 | Asset-44   | Threat-153  | VULN-138         | Medium     | High    | High        | High       |
| Risk-154 | Asset-44   | Threat-154  | VULN-139         | Medium     | Medium  | High        | Medium     |
| Risk-155 | Asset-44   | Threat-155  | VULN-140         | Medium     | High    | High        | High       |
| Risk-156 | Asset-45   | Threat-156  | VULN-141         | Medium     | High    | High        | High       |
| Risk-157 | Asset-45   | Threat-157  | VULN-142         | Medium     | Medium  | High        | Medium     |
| Risk-158 | Asset-45   | Threat-158  | VULN-143         | Medium     | Medium  | High        | Medium     |
| Risk-159 | Asset-45   | Threat-159  | VULN-144         | Medium     | Medium  | High        | Medium     |
| Risk-160 | Asset-46   | Threat-160  | VULN-145         | Medium     | High    | Medium      | High       |
| Risk-161 | Asset-46   | Threat-161  | VULN-146         | Medium     | High    | Medium      | High       |
| Risk-162 | Asset-46   | Threat-162  | VULN-147         | Medium     | Medium  | Medium      | Medium     |
| Risk-163 | Asset-46   | Threat-163  | VULN-148         | Low        | Medium  | Medium      | Medium     |
| Risk-164 | Asset-47   | Threat-164  | VULN-149         | Medium     | High    | Medium      | High       |
| Risk-165 | Asset-47   | Threat-165  | VULN-150         | Medium     | High    | Medium      | High       |
| Risk-166 | Asset-47   | Threat-166  | VULN-151         | Medium     | Medium  | Medium      | Medium     |
| Risk-167 | Asset-47   | Threat-167  | VULN-152         | Medium     | High    | Medium      | High       |
| Risk-168 | Asset-48   | Threat-168  | VULN-153         | High       | High    | High        | Critical   |
| Risk-169 | Asset-48   | Threat-169  | VULN-154         | Medium     | High    | High        | High       |
| Risk-170 | Asset-48   | Threat-170  | VULN-155         | Medium     | Medium  | High        | Medium     |
| Risk-171 | Asset-48   | Threat-171  | VULN-156         | Low        | Medium  | High        | Medium     |
| Risk-172 | Asset-49   | Threat-172  | VULN-157         | Medium     | High    | High        | High       |
| Risk-173 | Asset-49   | Threat-173  | VULN-158         | Medium     | High    | High        | High       |
| Risk-174 | Asset-49   | Threat-174  | VULN-159         | Medium     | High    | High        | High       |
| Risk-175 | Asset-49   | Threat-175  | VULN-160         | Medium     | High    | High        | High       |
| Risk-176 | Asset-49   | Threat-176  | VULN-128         | Medium     | Medium  | High        | Medium     |
| Risk-177 | Asset-49   | Threat-177  | VULN-161         | Medium     | High    | High        | High       |
| Risk-178 | Asset-50   | Threat-178  | VULN-001         | High       | High    | High        | Critical   |
| Risk-179 | Asset-50   | Threat-179  | VULN-162         | Medium     | High    | High        | High       |
| Risk-180 | Asset-50   | Threat-180  | VULN-163         | Medium     | High    | High        | High       |
| Risk-181 | Asset-50   | Threat-181  | VULN-164         | Medium     | High    | High        | High       |
| Risk-182 | Asset-50   | Threat-182  | VULN-165         | Low        | Medium  | High        | Medium     |
| Risk-183 | Asset-51   | Threat-183  | VULN-001         | High       | Medium  | High        | High       |
| Risk-184 | Asset-51   | Threat-184  | VULN-166         | Medium     | Medium  | High        | Medium     |
| Risk-185 | Asset-52   | Threat-185  | VULN-167         | Medium     | High    | High        | High       |
| Risk-186 | Asset-52   | Threat-186  | VULN-043         | Medium     | High    | High        | High       |
| Risk-187 | Asset-52   | Threat-187  | VULN-168         | Medium     | High    | High        | High       |
| Risk-188 | Asset-52   | Threat-188  | VULN-169         | Medium     | Medium  | High        | Medium     |
| Risk-189 | Asset-52   | Threat-189  | VULN-170         | Medium     | Medium  | High        | Medium     |
| Risk-190 | Asset-53   | Threat-190  | VULN-171         | Medium     | High    | High        | High       |
| Risk-191 | Asset-53   | Threat-191  | VULN-172         | High       | High    | High        | Critical   |
| Risk-192 | Asset-53   | Threat-192  | VULN-173         | Medium     | High    | High        | High       |
| Risk-193 | Asset-53   | Threat-193  | VULN-174         | Medium     | High    | High        | High       |
| Risk-194 | Asset-53   | Threat-194  | VULN-175         | Medium     | Medium  | High        | Medium     |
| Risk-195 | Asset-54   | Threat-195  | VULN-176         | High       | High    | High        | Critical   |
| Risk-196 | Asset-54   | Threat-196  | VULN-075         | Medium     | High    | High        | High       |
| Risk-197 | Asset-54   | Threat-197  | VULN-076         | Medium     | Medium  | High        | Medium     |

## Risk Mitigation Strategies

- This section presents the mitigation approach for each identified risk. The objective is to reduce the associated likelihood, impact, or both by implementing appropriate security measures.
- Each mitigation is also categorized by its control type — such as Preventive, Detective, Corrective, Deterrent, Compensating, or Recovery — following standard cybersecurity control classifications.

| Risk ID   | Mitigation Strategy                                                                                   | Control Type      |
|-----------|------------------------------------------------------------------------------------------------------|-------------------|
| Risk-001  | Disable or change default accounts immediately                                                       | Preventive        |
| Risk-002  | Implement CAPTCHA, rate limiting, and lockout mechanisms                                             | Preventive        |
| Risk-003  | Apply least privilege, audit admin actions                                                           | Preventive        |
| Risk-004  | Rename default account, monitor login attempts                                                       | Preventive        |
| Risk-005  | Security training, monitor activities, restrict access                                               | Preventive        |
| Risk-006  | Role-based access control, individual accounts                                                       | Preventive        |
| Risk-007  | Conduct phishing awareness programs                                                                  | Preventive        |
| Risk-008  | Enforce password complexity rules, MFA, regular audits                                               | Preventive        |
| Risk-009  | Limit software installation rights, application whitelisting                                         | Preventive        |
| Risk-010  | Educate users, enforce MFA, alert on suspicious login behavior                                       | Preventive        |
| Risk-011  | Implement behavioral monitoring and adaptive authentication                                          | Detective         |
| Risk-012  | Implement consent management and privacy notice mechanisms                                           | Preventive        |
| Risk-013  | Set Secure and HttpOnly flags, enable session timeout and re-authentication                         | Preventive        |
| Risk-014  | Awareness training, display safe browsing tips                                                       | Preventive        |
| Risk-015  | Implement SIEM tools, enable real-time alerts                                                        | Detective         |
| Risk-016  | Prioritize alerts, use rule tuning, integrate threat intel                                           | Detective         |
| Risk-017  | Enforce least privilege, monitor analyst activity                                                    | Preventive        |
| Risk-018  | Conduct regular training and red/blue team simulations                                               | Preventive        |
| Risk-019  | Clearly define DPO role, document responsibilities                                                   | Preventive        |
| Risk-020  | Implement data inventory, privacy impact assessments (DPIA)                                          | Preventive        |
| Risk-021  | Regular privacy meetings, clear reporting lines                                                      | Preventive        |
| Risk-022  | Launch privacy awareness programs and DPO-led workshops                                              | Preventive        |
| Risk-023  | Conduct regular training on phishing, vishing, tailgating                                            | Preventive        |
| Risk-024  | Implement RBAC, regular access reviews                                                               | Preventive        |
| Risk-025  | Introduce change control, require peer verification                                                  | Preventive        |
| Risk-026  | Log all support actions and privileged sessions                                                      | Detective         |
| Risk-027  | Use automated compliance tracking tools, subscribe to updates                                        | Preventive        |
| Risk-028  | Maintain audit-ready compliance dashboard                                                            | Preventive        |
| Risk-029  | Enforce documentation policy and periodic compliance reviews                                         | Preventive        |
| Risk-030  | Clarify responsibilities across compliance, privacy, audit roles                                     | Preventive        |
| Risk-031  | Implement alert tuning, prioritize critical use cases via SIEM                                       | Detective         |
| Risk-032  | Develop incident response playbooks and threat classification                                        | Preventive        |
| Risk-033  | Provide regular technical training and threat-hunting exercises                                      | Preventive        |
| Risk-034  | Blend automation with manual validation and adversary simulation                                     | Compensating      |
| Risk-035  | Conduct secure coding workshops, integrate OWASP Top 10 awareness                                    | Preventive        |
| Risk-036  | Enforce input validation, output encoding, code reviews                                              | Preventive        |
| Risk-037  | Use secret management systems, enforce pre-commit secret scanning                                    | Preventive        |
| Risk-038  | Implement mandatory pull request reviews and approval workflows                                      | Preventive        |
| Risk-039  | Set repos to private, restrict access, implement CI/CD scanning                                      | Preventive        |
| Risk-040  | Escape output, apply CSP                                                                             | Preventive        |
| Risk-041  | Parameterized queries, input validation                                                              | Preventive        |
| Risk-042  | Scan file types, apply upload restrictions                                                           | Preventive        |
| Risk-043  | Enforce validation at server side                                                                    | Preventive        |
| Risk-044  | Implement CAPTCHA, rate limiting, MFA                                                                | Preventive        |
| Risk-045  | Remove/replace default accounts                                                                      | Preventive        |
| Risk-046  | Enforce RBAC policies                                                                                | Preventive        |
| Risk-047  | Implement rate limiting, CAPTCHA, and monitor login patterns                                         | Preventive        |
| Risk-048  | Enforce strong password requirements                                                                 | Preventive        |
| Risk-049  | Implement Multi-Factor Authentication                                                                | Preventive        |
| Risk-050  | Use Secure/HttpOnly flags, session expiration                                                        | Preventive        |
| Risk-051  | Notify users on login from new IP/device                                                             | Detective         |
| Risk-052  | Use cryptographically secure, random tokens with short expiration                                    | Preventive        |
| Risk-053  | Invalidate token after reset, limit validity duration                                                | Preventive        |
| Risk-054  | Enforce HTTPS-only communications for reset flows                                                    | Preventive        |
| Risk-055  | Return generic success message regardless of account validity                                        | Preventive        |
| Risk-056  | Enable auditing and alerting for password reset attempts                                             | Detective         |
| Risk-057  | Patch PHP, restrict directory permissions                                                            | Preventive        |
| Risk-058  | Sanitize file input, enforce access controls                                                         | Preventive        |
| Risk-059  | Remove test/debug files, restrict file access                                                        | Preventive        |
| Risk-060  | Apply secure headers                                                                                 | Preventive        |
| Risk-061  | Require password, restrict sudo access                                                               | Preventive        |
| Risk-062  | Use prepared statements, input validation, implement WAF                                             | Preventive        |
| Risk-063  | Enforce password policy, disable defaults, monitor logs                                              | Preventive        |
| Risk-064  | Restrict MySQL to localhost, firewall untrusted interfaces                                           | Preventive        |
| Risk-065  | Regular patching, enable UFW, disable unnecessary services                                           | Preventive        |
| Risk-066  | Apply LTS kernel updates, use AppArmor/SELinux                                                       | Preventive        |
| Risk-067  | Disable service if unused                                                                            | Preventive        |
| Risk-068  | Restrict access to crontab files                                                                    | Preventive        |
| Risk-069  | Monitor cron logs, apply checksum alerts                                                             | Detective         |
| Risk-070  | Restrict file permissions, allow only root/admin edits                                               | Preventive        |
| Risk-071  | Move config files outside web root, deny access via `.htaccess`                                     | Preventive        |
| Risk-072  | Disable `Indexes` directive, review `httpd.conf` and `.htaccess`                                    | Preventive        |
| Risk-073  | Force HTTPS with `RewriteRule` or `Strict-Transport-Security` header                                | Preventive        |
| Risk-074  | Enable appropriate logging, avoid verbose sensitive data in logs                                     | Detective         |
| Risk-075  | Enforce proper NAT, isolate network segments                                                         | Preventive        |
| Risk-076  | Use VLANs, firewall policies                                                                         | Preventive        |
| Risk-077  | Remove sensitive entries or block access via 403                                                     | Preventive        |
| Risk-078  | Use honeypots, monitor bot activity                                                                  | Detective         |
| Risk-079  | File extension checks, integrate AV scanning                                                         | Preventive        |
| Risk-080  | Use random file names and access validation                                                          | Preventive        |
| Risk-081  | Apply strict file permissions, use log integrity mechanisms                                          | Preventive        |
| Risk-082  | Configure proper log rotation with size/time triggers                                                | Preventive        |
| Risk-083  | Define and enforce log retention policy                                                              | Preventive        |
| Risk-084  | Centralize logs with SIEM, set alerts for suspicious behavior                                        | Detective         |
| Risk-085  | Sanitize logs to exclude credentials and personal data                                               | Preventive        |
| Risk-086  | Centralize logs, enable log immutability and access restrictions                                     | Preventive        |
| Risk-087  | Implement automated alerting and daily log review procedures                                         | Detective         |
| Risk-088  | Ensure all auth events are logged with timestamps                                                    | Detective         |
| Risk-089  | Redact sensitive data from logs, review log formats                                                  | Preventive        |
| Risk-090  | Restrict access using role-based permissions                                                         | Preventive        |
| Risk-091  | Implement write-once logging, enable log integrity checks                                            | Preventive        |
| Risk-092  | Enable auditing for access control, configuration, and data changes                                  | Detective         |
| Risk-093  | Define log retention periods and protect storage                                                     | Preventive        |
| Risk-094  | Integrate with SIEM tools for real-time monitoring and alerts                                        | Detective         |
| Risk-095  | Sanitize log output, avoid logging personal or credential data                                       | Preventive        |
| Risk-096  | Store data in encrypted format, use strong access controls                                           | Preventive        |
| Risk-097  | Apply least privilege principle, audit access control lists                                          | Preventive        |
| Risk-098  | Enable access logging and anomaly detection                                                          | Detective         |
| Risk-099  | Use parameterized queries and validate input                                                         | Preventive        |
| Risk-100  | Enforce strong passwords, rotate credentials, use MFA                                                | Preventive        |
| Risk-101  | Use bcrypt or Argon2, salting and hashing                                                           | Preventive        |
| Risk-102  | Harden DB queries, limit admin role exposure                                                         | Preventive        |
| Risk-103  | Account lockout, CAPTCHA, strong password policy                                                     | Preventive        |
| Risk-104  | Encourage unique passwords, MFA, password health checks                                              | Preventive        |
| Risk-105  | Secure token generation, time limit, HTTPS enforcement                                               | Preventive        |
| Risk-106  | Encrypt backups, restrict storage access                                                             | Preventive        |
| Risk-107  | Store offline copies, backup integrity checks                                                        | Recovery          |
| Risk-108  | Version control, test restoration procedures                                                         | Recovery          |
| Risk-109  | Use `.gitignore`, sanitize comments                                                                  | Preventive        |
| Risk-110  | Apply IAM policies, private access enforcement                                                       | Preventive        |
| Risk-111  | Make repositories private, restrict collaborator access                                              | Preventive        |
| Risk-112  | Use secret scanning tools, environment variables                                                     | Preventive        |
| Risk-113  | Enforce commit hooks, review pull requests                                                           | Preventive        |
| Risk-114  | Use dependency scanners (Dependabot, Snyk), verify packages                                         | Preventive        |
| Risk-115  | Enforce MFA for all contributors                                                                    | Preventive        |
| Risk-116  | Use HTTPS, validate all inputs/requests, verify digital signatures                                   | Preventive        |
| Risk-117  | Use CA-signed certificates and implement TLS best practices                                          | Preventive        |
| Risk-118  | Implement API authentication (OAuth), apply rate limiting                                            | Preventive        |
| Risk-119  | Suppress detailed errors in production, use generic error messages                                   | Preventive        |
| Risk-120  | Enable transaction logging and monitoring with alerts for anomalies                                  | Detective         |
| Risk-121  | Implement secondary ISP or cellular backup line                                                      | Recovery          |
| Risk-122  | Use secure, custom DNS resolvers with DNSSEC                                                        | Preventive        |
| Risk-123  | Enforce HTTPS across all services, use VPN tunnels                                                   | Preventive        |
| Risk-124  | Use static IP for production services or auto-detect IP change and alert                             | Preventive        |
| Risk-125  | Monitor bandwidth usage, consider SLA negotiation with provider                                      | Compensating      |
| Risk-126  | Use unique passwords and enable MFA                                                                  | Preventive        |
| Risk-127  | Cross-verify results, tune rules, prioritize by severity                                             | Detective         |
| Risk-128  | Automate signature updates and schedule tool upgrades                                                | Preventive        |
| Risk-129  | Follow configuration guides, conduct regular tool validation                                         | Preventive        |
| Risk-130  | Host tools internally or behind VPN; apply access controls                                           | Preventive        |
| Risk-131  | Secure storage paths, encrypt logs, restrict access                                                  | Preventive        |
| Risk-132  | Automate definition updates, alert on failure                                                        | Preventive        |
| Risk-133  | Use certificates signed by trusted Certificate Authority                                             | Preventive        |
| Risk-134  | Implement SSL pinning on client-side apps                                                            | Preventive        |
| Risk-135  | Set up renewal alerts, automate cert management                                                      | Preventive        |
| Risk-136  | Disable weak ciphers, enforce TLS 1.2 or above                                                      | Preventive        |
| Risk-137  | Set `Secure` and `HttpOnly` flags, use SameSite cookies                                              | Preventive        |
| Risk-138  | Regenerate session ID after authentication                                                           | Preventive        |
| Risk-139  | Set appropriate session timeouts and idle session termination                                        | Preventive        |
| Risk-140  | Use strong, random session ID generators                                                             | Preventive        |
| Risk-141  | Store sessions server-side with encrypted session management systems                                 | Preventive        |
| Risk-142  | Apply SPF, DKIM, and rate limits                                                                     | Preventive        |
| Risk-143  | Store in locked drawers, digitize and encrypt                                                        | Preventive        |
| Risk-144  | Apply internal access controls, use watermarks on documents                                          | Preventive        |
| Risk-145  | Periodic review and updates of training modules                                                      | Corrective        |
| Risk-146  | Enforce login-based access, monitor downloads                                                        | Preventive        |
| Risk-147  | Align training with applicable standards and regulations                                             | Preventive        |
| Risk-148  | Apply version control (e.g., Git), restrict editing rights                                           | Preventive        |
| Risk-149  | Use secure file transfer methods and encryption                                                      | Preventive        |
| Risk-150  | Maintain regular backups, use redundancy                                                             | Recovery          |
| Risk-151  | Use document signing and centralized document repositories                                           | Detective         |
| Risk-152  | Schedule periodic reviews and updates                                                                | Corrective        |
| Risk-153  | Cross-verify checklist with control implementation reports                                           | Detective         |
| Risk-154  | Set access controls and use version tracking                                                         | Preventive        |
| Risk-155  | Maintain mapping of each control to supporting evidence                                              | Detective         |
| Risk-156  | Enforce access control via IAM, group roles, and permissions                                         | Preventive        |
| Risk-157  | Apply role-based access control and version control                                                  | Preventive        |
| Risk-158  | Align policy with periodic system and organization reviews                                           | Corrective        |
| Risk-159  | Conduct regular training and mandatory policy acknowledgment sessions                                | Preventive        |
| Risk-160  | Regularly test, update, and simulate IR plans                                                        | Corrective        |
| Risk-161  | Clearly define escalation matrix and assign responsibilities                                         | Preventive        |
| Risk-162  | Conduct IR training and tabletop exercises                                                           | Preventive        |
| Risk-163  | Restrict file access and maintain audit trail                                                        | Preventive        |
| Risk-164  | Regularly update and test the BCP through simulations                                                | Recovery          |
| Risk-165  | Clearly define and document roles in BCP                                                             | Preventive        |
| Risk-166  | Store BCP in both online/offline formats with access control                                         | Preventive        |
| Risk-167  | Sync BCP with disaster recovery plans and validate data recovery process                             | Recovery          |
| Risk-168  | Regularly review and update policy to align with GDPR, DPDPA, etc.                                  | Corrective        |
| Risk-169  | Clearly define what data is collected, how it is used, and user rights                              | Preventive        |
| Risk-170  | Apply access controls and maintain version control                                                   | Preventive        |
| Risk-171  | Ensure accessibility via footer link, offer in multiple languages                                    | Preventive        |
| Risk-172  | Deploy EDR/AV tools, enforce USB restrictions, regular scans                                        | Preventive        |
| Risk-173  | Enable full disk encryption (e.g., BitLocker, LUKS)                                                  | Preventive        |
| Risk-174  | Enforce strong password policies, auto-lock screen, MFA                                             | Preventive        |
| Risk-175  | Centralized patch management system                                                                  | Preventive        |
| Risk-176  | Use cable locks, asset tags, enforce secure storage policies                                         | Preventive        |
| Risk-177  | Apply CIS Benchmarks, disable unnecessary services                                                   | Preventive        |
| Risk-178  | Change default credentials, implement access control lists (ACLs)                                    | Preventive        |
| Risk-179  | Enforce proper VLAN tagging and segmentation                                                         | Preventive        |
| Risk-180  | Change SNMP strings, use SNMPv3 with encryption                                                      | Preventive        |
| Risk-181  | Regularly update switch firmware after validation                                                    | Preventive        |
| Risk-182  | Lock switch cabinets, disable unused ports                                                           | Preventive        |
| Risk-183  | Change default credentials, disable remote admin                                                     | Preventive        |
| Risk-184  | Enable DoS protection, filter traffic                                                                | Preventive        |
| Risk-185  | Regular audits, apply principle of least privilege                                                   | Preventive        |
| Risk-186  | Disable remote admin or enforce MFA and IP whitelisting                                              | Preventive        |
| Risk-187  | Regular firmware updates and security patching                                                       | Preventive        |
| Risk-188  | Perform rule optimization and cleanup                                                                | Corrective        |
| Risk-189  | Enable firewall logging and integrate with centralized SIEM                                          | Detective         |
| Risk-190  | Use RAID setup, schedule regular checksums and integrity scans                                       | Preventive        |
| Risk-191  | Implement RBAC, isolate sensitive shares, enforce strong passwords                                   | Preventive        |
| Risk-192  | Enable backups, apply least privilege, segment network                                               | Recovery          |
| Risk-193  | Implement scheduled encrypted backups stored offsite                                                 | Recovery          |
| Risk-194  | Enforce encrypted protocols, audit share configuration                                               | Preventive        |
| Risk-195  | Implement log signing, central log server                                                            | Preventive        |
| Risk-196  | Define log retention policy, backups                                                                 | Recovery          |
| Risk-197  | Enable log analysis via SIEM                                                                         | Detective         |

---

## Compliance Standards Mapping Table
- This section maps the identified risks to relevant security and privacy control requirements from established compliance frameworks such as ISO 27001, PCI DSS, GDPR, DPDPA, and others.
- Each entry in the table includes:
- Each entry in the table includes:
    - The control reference (e.g., ISO 27001 A.9.2.1)
    - The framework name
    - Associated Risk IDs that the control helps mitigate
    - A brief description of the control's objective
- This mapping ensures that risk mitigation strategies are aligned with industry best practices and regulatory expectations.

| Compliance Standard         | Framework/Initials | Risk IDs                                                                                                   | Description                        |
|----------------------------|--------------------|--------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| ISO 27001 A.9.2.1          | ISO 27001          | Risk-001, Risk-045, Risk-048, Risk-063, Risk-126, Risk-174                                                        | User access management              |
| ISO 27001 A.9.4.3          | ISO 27001          | Risk-002, Risk-008, Risk-063, Risk-112                                                                            | Secure authentication               |
| PCI DSS 8.2                | PCI DSS            | Risk-001, Risk-008, Risk-045, Risk-048, Risk-100, Risk-174                                                        | Password requirements               |
| OWASP A5                   | OWASP              | Risk-003, Risk-046, Risk-058, Risk-072, Risk-141                                                                  | Access control flaws                |
| OWASP A2                   | OWASP              | Risk-004, Risk-013, Risk-050, Risk-104, Risk-137, Risk-138, Risk-139, Risk-140                                    | Broken authentication               |
| NIST AC-7                  | NIST               | Risk-004, Risk-056                                                                                                | Account management                  |
| ISO 27001 A.7.2.2          | ISO 27001          | Risk-005, Risk-014, Risk-018, Risk-022, Risk-023, Risk-035, Risk-145, Risk-162                                    | Security awareness training         |
| IT Act 2000                | IT Act             | Risk-005                                                                                                          | Indian IT law                       |
| ISO 27001 A.9.2.3          | ISO 27001          | Risk-006, Risk-017, Risk-024, Risk-070, Risk-191                                                                  | Role-based access                   |
| PCI DSS 7.1                | PCI DSS            | Risk-006                                                                                                          | Access control policy               |
| DPDPA                      | DPDPA              | Risk-007, Risk-019, Risk-169, Risk-147, Risk-168, Risk-169                                                        | Indian privacy law                  |
| ISO 27001 A.12.5.1         | ISO 27001          | Risk-009, Risk-113                                                                                                | Change management                   |
| GDPR Art. 25               | GDPR               | Risk-010                                                                                                          | Data protection by design           |
| ISO 27001 A.18             | ISO 27001          | Risk-010, Risk-169                                                                                                | Compliance requirements             |
| ISO 27001 A.12.4.1         | ISO 27001          | Risk-011, Risk-025, Risk-026, Risk-031, Risk-056, Risk-088, Risk-131, Risk-151, Risk-189, Risk-196                | Event logging                       |
| PCI DSS 10.2               | PCI DSS            | Risk-011, Risk-120, Risk-189                                                                                      | Log monitoring                      |
| GDPR Art. 6                | GDPR               | Risk-012, Risk-085                                                                                                | Lawful processing                   |
| ISO 27001 A.9.4.2          | ISO 27001          | Risk-013, Risk-049, Risk-050, Risk-140                                                                            | Session management                  |
| ISO 27001 A.16.1.4         | ISO 27001          | Risk-016, Risk-031, Risk-161                                                                                      | Incident response                   |
| NIST IR                    | NIST               | Risk-015, Risk-029                                                                                                | Incident reporting                  |
| ISO 27001 A.9.1.2          | ISO 27001          | Risk-003, Risk-154, Risk-163, Risk-146, Risk-191                                                                  | Access rights                       |
| ISO 27001 A.7.5            | ISO 27001          | Risk-029, Risk-155                                                                                                | Documentation management            |
| GDPR Art. 37–39            | GDPR               | Risk-019, Risk-022                                                                                                | DPO responsibilities                |
| DPDPA Sec. 8               | DPDPA              | Risk-019                                                                                                          | Data protection officer             |
| GDPR Art. 30               | GDPR               | Risk-020                                                                                                          | Records of processing               |
| ISO 27001 A.18.1.4         | ISO 27001          | Risk-020, Risk-169                                                                                                | Privacy impact assessment           |
| GDPR Art. 39               | GDPR               | Risk-021, Risk-022                                                                                                | DPO tasks                           |
| NIST PR.AT                 | NIST               | Risk-018, Risk-033, Risk-023, Risk-162                                                                            | Awareness and training              |
| ISO 27001 A.12.1.2         | ISO 27001          | Risk-025, Risk-059, Risk-109, Risk-166                                                                            | Change management                   |
| ITIL CM                    | ITIL               | Risk-025                                                                                                          | Change control                      |
| ISO 27001 A.18.1.1         | ISO 27001          | Risk-027, Risk-152                                                                                                | Compliance monitoring               |
| DPDPA Sec. 29              | DPDPA              | Risk-027                                                                                                          | Regulatory updates                  |
| PCI DSS 12.1               | PCI DSS            | Risk-028, Risk-152                                                                                                | Security policies                   |
| ISO 27001 A.18.2.3         | ISO 27001          | Risk-028                                                                                                          | Compliance review                   |
| NIST CSF DE.AE             | NIST CSF           | Risk-031                                                                                                          | Alert management                    |
| ISO 27001 A.16.1.5         | ISO 27001          | Risk-032, Risk-160                                                                                                | Incident response                   |
| OWASP ASVS                 | OWASP              | Risk-035                                                                                                          | Secure coding practices             |
| OWASP A1                   | OWASP              | Risk-036, Risk-041, Risk-099, Risk-102                                                                            | Injection flaws                     |
| ISO 27001 A.14.2.1         | ISO 27001          | Risk-036, Risk-129, Risk-128                                                                                      | Secure development                  |
| OWASP A3                   | OWASP              | Risk-037, Risk-109, Risk-112, Risk-101                                                                            | Sensitive data exposure             |
| ISO 27001 A.9.2.4          | ISO 27001          | Risk-037                                                                                                          | Secret management                   |
| ISO 27001 A.14.2.2         | ISO 27001          | Risk-038                                                                                                          | Peer code review                    |
| PCI DSS 6.3                | PCI DSS            | Risk-039, Risk-111                                                                                                | Secure code management              |
| OWASP A7                   | OWASP              | Risk-040, Risk-055, Risk-068                                                                                      | XSS protection                      |
| GDPR Art. 32               | GDPR               | Risk-040, Risk-096, Risk-172                                                                                      | Data security                       |
| PCI DSS 6.5.1              | PCI DSS            | Risk-041, Risk-062                                                                                                | SQL injection prevention            |
| OWASP A8                   | OWASP              | Risk-042, Risk-079                                                                                                | File upload security                |
| ISO 27001 A.14             | ISO 27001          | Risk-043, Risk-080                                                                                                | Secure application design           |
| PCI DSS 8.1.6              | PCI DSS            | Risk-044, Risk-047, Risk-103                                                                                      | Authentication controls             |
| ISO 27001 A.9.4            | ISO 27001          | Risk-044, Risk-047, Risk-049, Risk-126                                                                            | Secure authentication               |
| PCI DSS 8.3                | PCI DSS            | Risk-049, Risk-115                                                                                                | Multi-factor authentication         |
| OWASP API Security Top 10  | OWASP              | Risk-118                                                                                                          | API security                        |
| NIST SP 800-34             | NIST SP            | Risk-107, Risk-164                                                                                                | Backup and recovery                 |
| NIST SP 800-41             | NIST SP            | Risk-184, Risk-188                                                                                                | Firewall management                 |
| NIST SP 800-115            | NIST SP            | Risk-180                                                                                                          | Penetration testing                 |
| ISO 27001 A.12.4.3         | ISO 27001          | Risk-015, Risk-081, Risk-086, Risk-091, Risk-195                                                                  | Log integrity                       |
| ISO 27001 A.12.4.2         | ISO 27001          | Risk-083, Risk-196                                                                                                | Log retention                       |
| ISO 27001 A.12.4           | ISO 27001          | Risk-012, Risk-084, Risk-098, Risk-120, Risk-131, Risk-151, Risk-189, Risk-196                                    | Logging and monitoring              |
| ISO 27001 A.13.1           | ISO 27001          | Risk-064, Risk-075, Risk-123, Risk-133, Risk-130, Risk-122, Risk-124                                              | Network security                    |
| ISO 27001 A.13.2.3         | ISO 27001          | Risk-149, Risk-194                                                                                                | Secure file transfer                |
| ISO 27001 A.17.2.1         | ISO 27001          | Risk-121, Risk-167                                                                                                | Business continuity                 |
| ISO 27001 A.17.1.3         | ISO 27001          | Risk-164                                                                                                          | BCP testing                         |
| ISO 27001 A.17.1.2         | ISO 27001          | Risk-165                                                                                                          | BCP role clarity                    |
| ISO 27001 A.17.1.1         | ISO 27001          | Risk-166                                                                                                          | BCP documentation                   |
| ISO 27001 A.18.1.3         | ISO 27001          | Risk-093, Risk-147                                                                                                | Compliance deviation                |
| ISO 27001 A.18.2.2         | ISO 27001          | Risk-153                                                                                                          | Audit failure                       |
| ISO 27001 A.7.5.1          | ISO 27001          | Risk-155                                                                                                          | Evidence mapping                    |
| ISO 27001 A.9.1            | ISO 27001          | Risk-020, Risk-097, Risk-103, Risk-156                                                                            | Access control policy               |
| ISO 27001 A.9.2            | ISO 27001          | Risk-061, Risk-100, Risk-126, Risk-174                                                                            | User authentication                 |
| ISO 27001 A.9.4.1          | ISO 27001          | Risk-090                                                                                                          | Log access control                  |
| ISO 27001 A.10.1           | ISO 27001          | Risk-052, Risk-173                                                                                                | Cryptography                        |
| ISO 27001 A.10.1.1         | ISO 27001          | Risk-054, Risk-123                                                                                                | Secure transmission                 |
| ISO 27001 A.12.6.1         | ISO 27001          | Risk-065, Risk-128, Risk-175                                                                                      | Patch management                    |
| ISO 27001 A.12.3           | ISO 27001          | Risk-106, Risk-192, Risk-193                                                                                      | Backup management                   |
| ISO 27001 A.12.3.1         | ISO 27001          | Risk-108, Risk-190, Risk-121                                                                                      | Data loss prevention                |
| ISO 27001 A.14.2.5         | ISO 27001          | Risk-041, Risk-062                                                                                                | Secure coding                       |
| ISO 27001 A.14.2.8         | ISO 27001          | Risk-114                                                                                                          | Supply chain security               |
| ISO 27001 A.14.1           | ISO 27001          | Risk-111                                                                                                          | Source code protection              |
| ISO 27001 A.8.2.2          | ISO 27001          | Risk-039, Risk-148                                                                                                | Source code leak                    |
| ISO 27001 A.8.3            | ISO 27001          | Risk-071                                                                                                          | Information disclosure              |
| ISO 27001 A.11.2.6         | ISO 27001          | Risk-176                                                                                                          | Physical security                   |
| ISO 27001 A.11.2.9         | ISO 27001          | Risk-143, Risk-176                                                                                                | Physical theft prevention           |
| ISO 27001 A.11.1.1         | ISO 27001          | Risk-182                                                                                                          | Physical tampering                  |
| ISO 27001 A.5.1.1          | ISO 27001          | Risk-158                                                                                                          | Policy review                       |
| ISO 27001 A.7.2.1          | ISO 27001          | Risk-145                                                                                                          | Training content review             |
| ISO 27001 A.13.2.3         | ISO 27001          | Risk-149, Risk-194                                                                                                | Secure file sharing                 |
| ISO 27001 A.12.2.1         | ISO 27001          | Risk-132, Risk-172                                                                                                | Anti-malware protection             |
| ISO 27001 A.12.6           | ISO 27001          | Risk-187, Risk-175                                                                                                | Firmware updates                    |
| ISO 27001 A.13.1.3         | ISO 27001          | Risk-124                                                                                                          | IP address management               |
| ISO 27001 A.15.1.1         | ISO 27001          | Risk-125                                                                                                          | SLA management                      |
| ISO 27001 A.9.2.3          | ISO 27001          | Risk-024, Risk-070, Risk-191                                                                                      | Access review                       |
| ISO 27001 A.9.1.2          | ISO 27001          | Risk-154, Risk-163, Risk-146, Risk-191                                                                            | Access rights                       |
| ISO 27001 A.9.4.2          | ISO 27001          | Risk-050, Risk-140, Risk-126                                                                                      | Session management                  |
| ISO 27001 A.9.4.3          | ISO 27001          | Risk-002, Risk-008, Risk-063, Risk-112                                                                            | Secure authentication               |
| ISO 27001 A.9.4            | ISO 27001          | Risk-044, Risk-047, Risk-049, Risk-126                                                                            | Secure authentication               |
| ISO 27001 A.9.2.1          | ISO 27001          | Risk-001, Risk-045, Risk-048, Risk-063, Risk-126, Risk-174                                                        | User access management              |
| PCI DSS 8.2                | PCI DSS            | Risk-001, Risk-008, Risk-045, Risk-048, Risk-100, Risk-174                                                        | Password requirements               |
| PCI DSS 8.1.6              | PCI DSS            | Risk-044, Risk-047, Risk-103                                                                                      | Authentication controls             |
| PCI DSS 8.3                | PCI DSS            | Risk-049, Risk-115                                                                                                | Multi-factor authentication         |
| PCI DSS 10.2               | PCI DSS            | Risk-011, Risk-120, Risk-189                                                                                      | Log monitoring                      |
| PCI DSS 10.5               | PCI DSS            | Risk-081, Risk-086, Risk-091, Risk-195                                                                            | Log integrity                       |
| PCI DSS 10.7               | PCI DSS            | Risk-093                                                                                                          | Log retention                       |
| PCI DSS 6.3                | PCI DSS            | Risk-039, Risk-111                                                                                                | Secure code management              |
| PCI DSS 6.5.1              | PCI DSS            | Risk-041, Risk-062                                                                                                | SQL injection prevention            |
| PCI DSS 12.1               | PCI DSS            | Risk-028, Risk-152                                                                                                | Security policies                   |
| PCI DSS 1.3.6              | PCI DSS            | Risk-076                                                                                                          | Network segmentation                |
| PCI DSS 1.2.3              | PCI DSS            | Risk-179                                                                                                          | VLAN security                       |
| PCI DSS 4.1                | PCI DSS            | Risk-073, Risk-116, Risk-117                                                                                      | Secure transmission                 |
| PCI DSS 9.5                | PCI DSS            | Risk-106, Risk-193                                                                                                | Backup management                   |
| PCI DSS 1.1.6              | PCI DSS            | Risk-185                                                                                                          | Firewall configuration              |
| NIST SP 800-34             | NIST SP            | Risk-107, Risk-164                                                                                                | Backup and recovery                 |
| NIST SP 800-41             | NIST SP            | Risk-184, Risk-188                                                                                                | Firewall management                 |
| NIST SP 800-115            | NIST SP            | Risk-180                                                                                                          | Penetration testing                 |
| NIST SP 800-52             | NIST SP            | Risk-136                                                                                                          | Cipher suite management             |
| NIST SP 800-61             | NIST SP            | Risk-160                                                                                                          | Incident response                   |
| NIST SP 800-83             | NIST SP            | Risk-192                                                                                                          | Ransomware protection               |
| NIST SP 800-53 AC-6        | NIST SP            | Risk-191                                                                                                          | Access control                      |
| NIST CSF DE.AE             | NIST CSF           | Risk-031                                                                                                          | Alert management                    |
| NIST CSF DE.CM-7           | NIST CSF           | Risk-084, Risk-197                                                                                                | Log monitoring                      |
| NIST CSF PR.IP-1           | NIST CSF           | Risk-177                                                                                                          | Secure configuration                |
| NIST PR.AT                 | NIST               | Risk-018, Risk-033, Risk-023, Risk-162                                                                            | Awareness and training              |
| NIST IR                    | NIST               | Risk-015, Risk-029                                                                                                | Incident reporting                  |
| OWASP ASVS                 | OWASP              | Risk-035                                                                                                          | Secure coding practices             |
| OWASP API Security Top 10  | OWASP              | Risk-118                                                                                                          | API security                        |
| OWASP A1                   | OWASP              | Risk-036, Risk-041, Risk-099, Risk-102                                                                            | Injection flaws                     |
| OWASP A2                   | OWASP              | Risk-004, Risk-013, Risk-050, Risk-104, Risk-137, Risk-138, Risk-139, Risk-140                                    | Broken authentication               |
| OWASP A3                   | OWASP              | Risk-037, Risk-109, Risk-112, Risk-101                                                                            | Sensitive data exposure             |
| OWASP A5                   | OWASP              | Risk-003, Risk-046, Risk-058, Risk-072, Risk-141                                                                  | Access control flaws                |
| OWASP A6                   | OWASP              | Risk-054, Risk-060, Risk-071, Risk-119                                                                            | Secure headers                      |
| OWASP A7                   | OWASP              | Risk-040, Risk-055, Risk-068                                                                                      | XSS protection                      |
| OWASP A8                   | OWASP              | Risk-042, Risk-079                                                                                                | File upload security                |
| OWASP M5                   | OWASP              | Risk-134                                                                                                          | Certificate pinning                 |

---

## GRC Summary

This document provides a detailed Governance, Risk, and Compliance (GRC) overview of the simulated e-commerce environment using OpenCart, Apache, MySQL, and PHP hosted on Ubuntu. The findings are based on 53 identified assets and their corresponding threats.

---

# Governance

* No segregation of duties across system components (e.g., `admin` account manages all OpenCart functions).
* Lack of RBAC (Role-Based Access Control) on OpenCart Admin Panel and Developer Notes.
* No formal documentation for information security, change management, or audit control policies.
* Developer team pushes unverified code directly to GitHub without code review.
* GitHub repositories contain hardcoded secrets and exposed config files.
* Security analyst and interns do not have access boundaries or logging of their activities.
* No formal password reset or onboarding/offboarding procedures for system users.
* No version control enforcement or pull request validation configured.
* No ownership clarity or change management logs for critical services like Apache or MySQL.

---

# Risk

### Web and Application Layer

* Apache server allows public access to `/phpinfo.php`, exposing sensitive info.
* World-writable directories in `/var/www/html` pose RCE and tampering risks.
* Default OpenCart admin credentials (`admin/admin`) still active.
* Theme editor and file manager modules allow arbitrary code injection (CVE-2024-36694).
* MySQL accessible via root with no password (`sudo mysql`).
* SQL Injection and XSS vulnerabilities observed in OpenCart forms.
* Customer data stored in plaintext with no TLS encryption.
* Uploaded product images not scanned or restricted; may contain malware.
* File upload functionality has no file type filtering.

### System and Infrastructure

* Apache and MySQL are not patched or monitored for CVEs.
* Ubuntu 22.04 firewall (UFW) is disabled.
* CUPS print service is enabled and exposed on port 631.
* Cron jobs lack permission control and log verification.
* System logs are not centralized or protected from tampering.
* No backup versioning, no disaster recovery tested.
* Paper notes with credentials are unprotected in physical space.
* Robots.txt exposes `/admin` and other hidden paths.

### Network and Access Control

* Internet router uses default admin credentials and permits remote login.
* NAT and port forwarding not reviewed; MySQL port 3306 exposed.
* No VLAN segmentation for internal/external traffic.
* No rate-limiting or brute-force detection at the OpenCart login endpoint.
* Audit Trail System lacks integrity controls (e.g., log signing).
* Email Notification Module lacks SPF/DKIM and is vulnerable to spam relay.
* Admin credentials stored in plaintext in DB or source files.
* Developer Notes include hardcoded passwords.
* Domain registrar account lacks MFA.

---

# Compliance

### ISO 27001

* Missing ISMS documentation, secure operations, cryptographic controls, and supplier evaluation.
* Access control (A.9), operations security (A.12), and system acquisition (A.14) not enforced.

### GDPR

* No privacy policy or consent collection UI.
* Data subjects cannot view, correct, or delete their data.
* No storage limitation or accuracy assurance.

### PCI DSS

* Cardholder environment is not encrypted or isolated.
* No firewall or AV; weak authentication; missing logs for CHD tracking.

### DPDPA (India)

* No user consent system, breach reporting, or security safeguards.
* Fiduciary roles not designated; no notification policy.

### IT Act 2000

* No safeguards for Sections 43A, 66, 72, and 72A.
* No user data confidentiality enforcement; admin access overly permissive.
* Logs not retained for investigation or audit purposes.

---