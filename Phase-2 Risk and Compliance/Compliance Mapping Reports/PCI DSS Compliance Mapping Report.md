# PCI DSS Compliance Mapping Report

This report evaluates whether the e-commerce system aligns with PCI DSS requirements, particularly relevant if handling payment data.

| PCI DSS Requirement                  | Applicable | Status        | Notes / Remediation Needed                                        |
| ------------------------------------ | ---------- | ------------- | ----------------------------------------------------------------- |
| 1. Install and maintain firewall     | Yes        | Not Compliant | No firewall configured; ports exposed.                            |
| 2. No default passwords              | Yes        | Not Compliant | Default OpenCart admin and MySQL root accounts not changed.       |
| 3. Protect stored cardholder data    | No         | N/A           | Cardholder data not stored directly in current setup.             |
| 4. Encrypt transmission of CHD       | Yes        | Not Compliant | No SSL enabled for HTTP traffic.                                  |
| 5. Use and update antivirus software | Yes        | Not Compliant | No antivirus or malware detection mechanisms installed.           |
| 6. Develop secure systems and apps   | Yes        | Not Compliant | No secure coding or testing practices applied to custom code.     |
| 7. Restrict access to data           | Yes        | Not Compliant | No user access tiering or enforcement for admin roles.            |
| 8. Unique IDs for users              | Yes        | Partially     | Only default admin account used; no separate IDs for staff.       |
| 10. Track and monitor access         | Yes        | Partially     | Apache logs active; MySQL logs missing; user activity not logged. |
