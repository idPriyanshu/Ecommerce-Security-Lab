# GDPR Compliance Mapping Report

This report assesses the alignment of the OpenCart-based e-commerce platform with key GDPR requirements.

| GDPR Article / Principle               | Applicable | Status        | Notes / Remediation Needed                                               |
| -------------------------------------- | ---------- | ------------- | ------------------------------------------------------------------------ |
| Lawful, Fair & Transparent Processing  | Yes        | Not Compliant | No privacy policy shown to users.                                        |
| Purpose Limitation                     | Yes        | Not Compliant | No clear statement on the purpose of data collection or processing.      |
| Data Minimization                      | Yes        | Partially     | Basic registration fields present; some fields and logs unnecessary.     |
| Accuracy                               | Yes        | Partially     | No auto-verification; updates possible only through manual intervention. |
| Storage Limitation                     | Yes        | Not Compliant | Old backups and user data retained indefinitely, no retention policy.    |
| Integrity & Confidentiality            | Yes        | Not Compliant | HTTP enabled, sensitive paths exposed, access control and hashing weak.  |
| Accountability                         | Yes        | Not Compliant | No audit logs, unmonitored admin actions, no DPO appointed.              |
| Consent (Articles 6–7)                 | Yes        | Not Compliant | No checkbox, logging mechanism, or separate consent per data purpose.    |
| Right to Access / Erasure (Art. 15–18) | Yes        | Not Compliant | No self-service user portal for data access/export/correction/deletion.  |
| Data Protection by Design & Default    | Yes        | Not Compliant | No RBAC, weak secrets handling, insecure backup locations.               |
| Processor Obligations (Art. 28–29)     | Yes        | Not Compliant | Third-party themes/plugins unverified; admin passwords weak.             |
| Data Breach Notification (Art. 33–34)  | Yes        | Not Compliant | No incident response, log monitoring, or user breach alert mechanism.    |
| Children's Data (Art. 8)               | Yes        | Not Compliant | No age verification or parental consent workflow.                        |
| Grievance Redressal / Contact DPO      | Yes        | Not Compliant | No grievance channel or DPO communication mechanism in place.            |
