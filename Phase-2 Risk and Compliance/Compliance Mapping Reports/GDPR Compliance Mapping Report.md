# GDPR Compliance Mapping Report

This report assesses the alignment of the OpenCart-based e-commerce platform with key GDPR requirements.

| GDPR Article / Principle               | Applicable | Status        | Notes / Remediation Needed                                    |
| -------------------------------------- | ---------- | ------------- | ------------------------------------------------------------- |
| Lawful, Fair & Transparent Processing  | Yes        | Not Compliant | No privacy policy shown to users.                             |
| Purpose Limitation                     | Yes        | Not Compliant | No clear statement on the purpose of data collection.         |
| Data Minimization                      | Yes        | Partially     | Basic registration fields present; review for necessity.      |
| Accuracy                               | Yes        | Not Compliant | No verification or user-editable options for correcting data. |
| Storage Limitation                     | Yes        | Not Compliant | No data retention policy enforced in database or app.         |
| Integrity & Confidentiality            | Yes        | Not Compliant | No HTTPS; phpinfo leak and default creds still present.       |
| Accountability                         | Yes        | Not Compliant | No logs, no designated DPO, no traceability.                  |
| Consent (Articles 6–7)                 | Yes        | Not Compliant | No checkbox, notice, or logging of consent.                   |
| Right to Access / Erasure (Art. 15–18) | Yes        | Not Compliant | No mechanism for user data access/export/deletion.            |
