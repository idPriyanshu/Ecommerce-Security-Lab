# Risk Assessment – Phase 2

This document presents a qualitative risk assessment of the simulated e-commerce environment created during Phase 1. The assessment includes confirmed vulnerabilities discovered during manual and tool-based analysis. Each risk is evaluated using a qualitative matrix based on **Likelihood** and **Impact**, and mitigation recommendations are proposed accordingly. This assessment directly corresponds to the assets defined in the accompanying Asset Register.

---

## Risk Rating Matrix

The following matrix is used to assign a qualitative **Risk Level**:

| Likelihood ↓ \ Impact → | Low    | Medium | High     |
| ----------------------- | ------ | ------ | -------- |
| Low                     | Low    | Low    | Medium   |
| Medium                  | Low    | Medium | High     |
| High                    | Medium | High   | Critical |

---

## Confirmed Vulnerabilities and Associated Asset Risks

| Risk Description                                     | Affected Asset                  | Likelihood | Impact | Risk Level | Recommendation                                                                                   |
| ---------------------------------------------------- | ------------------------------- | ---------- | ------ | ---------- | ------------------------------------------------------------------------------------------------ |
| Default OpenCart admin credentials (`admin:admin`)   | Admin Credentials               | High       | High   | Critical   | Immediately change default credentials and enforce strong password policy                        |
| MySQL root login without password                    | MySQL Database                  | High       | High   | Critical   | Set a strong root password and disable remote root login                                         |
| PHP info page accessible                             | Apache Web Server               | Medium     | Medium | Medium     | Remove `phpinfo.php` file and disable exposure in production                                     |
| Apache lacks security headers                        | Apache Web Server               | Medium     | High   | High       | Configure headers like `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security` |
| Open ports (3306, 631)                               | MySQL Database and CUPS Service | Medium     | Medium | Medium     | Restrict access to local interfaces or disable unused services                                   |
| World-writable `/storage` directory                  | OpenCart Web App                | Medium     | Medium | Medium     | Set restrictive permissions (e.g., `755` for dirs, `644` for files)                              |
| Disclosure of internal URL parameters via robots.txt | Robots.txt File                 | Medium     | Low    | Low        | Avoid exposing sensitive URL structures; review crawling policies in robots.txt                  |

---

## Testing Summary: XSS Attempt (Not Confirmed)

An attempt to test for **Cross-Site Scripting (XSS)** via the product review form was made. Multiple payloads were submitted to check for reflected or stored XSS vulnerabilities.

**Outcome:**
No XSS was confirmed. OpenCart appears to have some input filtering and sanitization in place. Further analysis using automated tools (e.g., Burp Suite Intruder, OWASP ZAP) may be required for assurance.

**Status:** Not confirmed
**Risk Level:** Low (no exploitation path currently verified)

---

## Suggested Next Steps

* Conduct a full automated vulnerability scan with tools such as OpenVAS or Nikto.
* Perform compliance-specific checks using tools like Lynis or ScoutSuite.
* Generate a risk treatment plan with timelines and responsibilities.
* Begin implementing layered security controls (WAF, file integrity monitoring, secure configurations).
* Link all future vulnerabilities to their respective asset as recorded in the Asset Register for consistency and traceability.
