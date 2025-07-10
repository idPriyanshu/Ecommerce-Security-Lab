# GRC Summary – Phase 2

This document provides a detailed Governance, Risk, and Compliance (GRC) overview of the simulated e-commerce environment using OpenCart, Apache, MySQL, and PHP hosted on Ubuntu. The findings are based on 53 identified assets and their corresponding threats.

---

## Governance

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

## Risk

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

## Compliance

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