# DPDPA (India) Compliance Mapping Report

Mapping against the Indian Digital Personal Data Protection Act (DPDPA), 2023.

| DPDPA Provision                  | Applicable | Status        | Notes / Remediation Needed                                                  |
| -------------------------------- | ---------- | ------------- | --------------------------------------------------------------------------- |
| Consent-Based Processing         | Yes        | Not Compliant | No explicit or granular consent mechanism implemented.                      |
| Notice of Purpose                | Yes        | Not Compliant | No visible notice explaining why and how data is used.                      |
| Right to Withdraw Consent        | Yes        | Not Compliant | Users cannot withdraw or change consent preferences.                        |
| Data Minimization Principle      | Yes        | Partially     | Basic registration fields; some unnecessary fields and debug data retained. |
| Security Safeguards              | Yes        | Not Compliant | No SSL, insufficient access control, data stored in plaintext, weak auth.   |
| Breach Notification              | Yes        | Not Compliant | No detection, audit trail tampering possible, no breach notification plan.  |
| Data Fiduciary Responsibilities  | Yes        | Not Compliant | No DPO appointed, training absent, logging incomplete, roles unclear.       |
| Data Storage Limitation          | Yes        | Not Compliant | Logs, old backups, and outdated customer data retained indefinitely.        |
| Children's Data Protection       | Yes        | Not Compliant | No age verification, no parental consent process.                           |
| Grievance Redressal              | Yes        | Not Compliant | No contact method or escalation process provided.                           |
| Purpose Limitation               | Yes        | Not Compliant | No validation if user data is reused outside stated purpose.                |
| Accuracy of Personal Data        | Yes        | Partially     | No automated correction method; only manual update allowed.                 |
| Privacy by Design                | Yes        | Not Compliant | No logs for system changes, no RBAC, weak DevSecOps pipeline.               |
| Secure Processing by Third Party | Yes        | Not Compliant | Third-party plugins not verified, default credentials active.               |
| Consent Logging and Auditing     | Yes        | Not Compliant | No system logs who gave consent and when.                                   |
| Right to Data Portability        | Yes        | Not Compliant | No feature to export user data in readable format.                          |
| Right to Erasure                 | Yes        | Not Compliant | Users cannot request or trigger account/data deletion.                      |
| Third-Party Risk Disclosure      | Yes        | Not Compliant | No record or vetting of third-party plugin or cloud providers.              |
| Data Sharing Controls            | Yes        | Not Compliant | No mechanism to track data shared with external entities.                   |
| Physical Security                | Yes        | Partially     | Paper notes and printed data are not stored securely.                       |
