# ISO 27001 Compliance Mapping Report

This report maps controls from ISO/IEC 27001 to the simulated e-commerce environment hosted on Ubuntu with OpenCart. It assesses the current implementation status and identifies gaps.

| ISO/IEC 27001 Clause                       | Applicable | Current Status | Notes / Remediation Needed                                             |
| ------------------------------------------ | ---------- | -------------- | ---------------------------------------------------------------------- |
| A.5 – Information Security Policies        | Yes        | Not Compliant  | No formal policy documents defined or implemented.                     |
| A.6 – Organization of ISMS                 | Yes        | Not Compliant  | Roles and responsibilities not clearly documented.                     |
| A.9 – Access Control                       | Yes        | Not Compliant  | Default credentials used; no RBAC or MFA configured in OpenCart.       |
| A.10 – Cryptography                        | Yes        | Not Compliant  | No SSL/TLS in place for admin or user communication.                   |
| A.12 – Operations Security                 | Yes        | Partially      | Apache logs are active, but MySQL logging and alerting not configured. |
| A.13 – Communications Security             | Yes        | Partially      | HTTP used instead of HTTPS; no encryption during data transit.         |
| A.14 – System Acquisition, Development     | Yes        | Not Compliant  | No secure SDLC observed; OpenCart plugins not reviewed.                |
| A.15 – Supplier Relationships              | Yes        | Not Compliant  | No vendor risk evaluation for external modules or dependencies.        |
| A.16 – Information Security Incident Mgmt. | Yes        | Not Compliant  | No incident response or breach reporting plan in place.                |
| A.18 – Compliance                          | Yes        | Not Compliant  | No regulatory compliance controls formally implemented.                |
