# IT Act 2000 Compliance Mapping Report

This document maps the OpenCart-based e-commerce setup to applicable provisions in the Indian IT Act, 2000.

| IT Act Provision                                       | Applicable | Status        | Notes / Remediation Needed                                          |
| ------------------------------------------------------ | ---------- | ------------- | ------------------------------------------------------------------- |
| Section 43A – Compensation for failure to protect data | Yes        | Not Compliant | Personal data not protected through SSL or access control.          |
| Section 66 – Hacking                                   | Yes        | Not Compliant | No intrusion detection; default credentials make system vulnerable. |
| Section 72 – Breach of confidentiality                 | Yes        | Not Compliant | No policies for handling user data or ensuring confidentiality.     |
| Section 72A – Disclosure without consent               | Yes        | Not Compliant | No user consent system; phpinfo exposure may lead to leakage.       |
| Section 79 – Intermediary due diligence                | Yes        | Not Compliant | No logging, security safeguards, or terms of service enforcement.   |
