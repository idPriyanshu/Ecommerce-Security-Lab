# GRC Summary – Phase 2

This document summarizes the Governance, Risk, and Compliance posture of the simulated e-commerce environment configured using OpenCart, Apache, MySQL, and PHP on Ubuntu.

---

## Governance

- No segregation of roles; a single `admin` account manages the system
- No user access management strategy (no multi-user login, no RBAC)
- Absence of formal policies for information security, incident handling, and user access
- Configuration changes are applied directly with no documented change management process

---

## Risk

- Critical risk: Unrestricted access via default admin and MySQL root credentials
- Unfiltered inputs and exposed parameters may allow injection (XSS, SQLi)
- Open services on 3306 (MySQL), 631 (CUPS), and 80 (Apache) increase attack surface
- `phpinfo()` page revealed PHP config, exposing version and modules
- File permissions in `/var/www/html` and `/system/storage` allow misuse or tampering
- No backups, integrity checks, or centralized log monitoring

---

## Compliance

- **ISO 27001**: Missing ISMS framework, no access control enforcement or logging
- **GDPR**: No consent mechanism or privacy policy; no way to access or erase personal data
- **PCIDSS**: No encryption in transit (HTTPS), default passwords in use, no firewall
- **DPDPA (India)**: Lacks lawful processing, user consent, and data fiduciary structure
- **IT Act 2000**: No breach reporting, no logging for investigation, no data protection plan
