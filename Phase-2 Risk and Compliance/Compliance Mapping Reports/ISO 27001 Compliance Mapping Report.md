# ISO/IEC 27001 Compliance Mapping Report

This report maps controls from ISO/IEC 27001 to the simulated e-commerce environment hosted on Ubuntu with OpenCart. It assesses the current implementation status and identifies gaps.

| ISO/IEC 27001 Clause                       | Applicable | Current Status | Notes / Remediation Needed                                                   |
| ------------------------------------------ | ---------- | -------------- | ---------------------------------------------------------------------------- |
| A.5 – Information Security Policies        | Yes        | Not Compliant  | No formal policy documents defined or implemented.                           |
| A.6 – Organization of ISMS                 | Yes        | Not Compliant  | Roles and responsibilities not clearly documented; no central governance.    |
| A.9 – Access Control                       | Yes        | Not Compliant  | Default credentials in use; no RBAC, MFA, or login audit trails.             |
| A.10 – Cryptography                        | Yes        | Not Compliant  | SSL/TLS missing; credentials stored in plaintext or weak hash.               |
| A.12 – Operations Security                 | Yes        | Partially      | Some logging enabled; backup unprotected; no job or service integrity check. |
| A.13 – Communications Security             | Yes        | Partially      | Data exchanged over HTTP; unencrypted SMTP; firewall misconfigurations.      |
| A.14 – System Acquisition, Development     | Yes        | Not Compliant  | No SDLC or review process for third-party modules or OpenCart extensions.    |
| A.15 – Supplier Relationships              | Yes        | Not Compliant  | No vendor risk assessments or contract clauses with third-party providers.   |
| A.16 – Information Security Incident Mgmt. | Yes        | Not Compliant  | No defined incident response procedure; no SIEM or alerting system.          |
| A.18 – Compliance                          | Yes        | Not Compliant  | Regulatory obligations not mapped; no audit trail or periodic assessments.   |
