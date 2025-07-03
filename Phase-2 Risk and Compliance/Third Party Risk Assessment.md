# Third-Party Risk Assessment

This document assesses the security risks associated with third-party components used in the simulated e-commerce environment, including OpenCart, Apache, PHP, and MySQL. The aim is to identify known vulnerabilities (CVEs), understand the impact, and propose mitigation strategies.

---

## 1. PHP Modules and Packages

### Installed Modules

* PHP Version: `8.3.6`
* Notable Modules: `curl`, `gd`, `mysqli`, `pdo_mysql`, `zip`, `openssl`, `json`, `opcache`, etc.

### Relevant CVEs

| CVE ID         | Description                                                                 | Severity | Component |
| -------------- | --------------------------------------------------------------------------- | -------- | --------- |
| CVE-2025-32293 | Deserialization of untrusted data in third-party theme (Finance Consultant) | High     | PHP       |
| CVE-2025-28944 | Local File Inclusion via dynamic `require()`                                | High     | PHP       |
| CVE-2025-32284 | Object injection via deserialization (Pet World theme)                      | High     | PHP       |

> These CVEs primarily affect unsafe third-party themes or modules, but the presence of vulnerable deserialization mechanisms in the stack poses a security risk if abused.

### Mitigation

* Avoid unverified OpenCart themes or extensions.
* Regularly apply security patches via `apt`.
* Use secure coding practices for all custom development.

---

## 2. Apache Web Server

### Installed Version: Apache 2.4.58

### Enabled Modules:

* Includes: `mod_rewrite`, `mod_php`, `mod_deflate`, `mod_authz_core`, `mod_autoindex`, `mod_status`, etc.

### Relevant CVEs

| CVE ID         | Description                                              | Severity | Module      |
| -------------- | -------------------------------------------------------- | -------- | ----------- |
| CVE-2022-23943 | Heap overwrite in `mod_sed`                              | High     | mod\_sed    |
| CVE-2022-22721 | Integer overflow in `LimitXMLRequestBody`                | High     | Apache Core |
| CVE-2022-22720 | HTTP Request Smuggling via incomplete connection closure | High     | Apache Core |

### Mitigation

* Keep Apache updated through the package manager.
* Disable unused modules (e.g., `mod_autoindex`).
* Review and restrict Apache configuration options like `LimitRequestBody` and `KeepAlive`.

---

## 3. OpenCart CMS

### Version: 4.0.2.3

### Known Vulnerabilities

| CVE ID         | Description                                      | Severity | Impact                  |
| -------------- | ------------------------------------------------ | -------- | ----------------------- |
| CVE-2024-36694 | Server-Side Template Injection via Theme Editor  | Critical | Remote Code Execution   |
| CVE-2024-21519 | Arbitrary File Creation via database restoration | Critical | Arbitrary PHP execution |
| CVE-2023-47444 | Configuration overwrite by authenticated users   | Critical | Remote Code Execution   |

### Mitigation

* Disable the Theme Editor and database restoration features in production.
* Protect `/admin` using `.htaccess` or IP whitelisting.
* Apply principle of least privilege (PoLP) for all admin users.
* Monitor OpenCart releases and upgrade when fixes become available.

---

## 4. MySQL Server

### Version: 8.0.42

### Initial Observations

* Root login without password was observed (`mysql -u root` worked without a password).
* MySQL is bound to localhost, reducing external attack surface.

### Known Vulnerabilities

| CVE ID         | Description                                        | Severity | Impact                    |
| -------------- | -------------------------------------------------- | -------- | ------------------------- |
| CVE-2020-14878 | Easily exploitable LDAP auth flaw (≤8.0.21)        | High     | Privilege escalation      |
| CVE-2016-6663  | Race condition in secure\_file\_priv functionality | High     | Local file overwrite risk |

> Your version (8.0.42) is not directly affected by these CVEs. However, ensuring a secure configuration is critical.

### Mitigation

* Set a strong root password immediately:

  ```sql
  ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'StrongPassword123!';
  ```
* Avoid using the `root` account for OpenCart operations.
* Create a dedicated low-privilege user (`oc_user`) for OpenCart:

  ```sql
  CREATE USER 'oc_user'@'localhost' IDENTIFIED BY 'SafePassword!';
  GRANT ALL PRIVILEGES ON opencart.* TO 'oc_user'@'localhost';
  FLUSH PRIVILEGES;
  ```
* Regularly monitor `mysql.error.log` and enable access logging.

---

## 5. Risk Summary Table

| Component               | Version | CVEs Identified   | Risk Level | Mitigation Summary                                             |
| ----------------------- | ------- | ----------------- | ---------- | -------------------------------------------------------------- |
| PHP                     | 8.3.6   | 3 (theme-related) | Medium     | Avoid insecure modules, update regularly                       |
| Apache HTTPD            | 2.4.58  | 3                 | High       | Monitor modules, patch regularly, disable unused functionality |
| OpenCart                | 4.0.2.3 | 3 (Critical)      | Critical   | Disable dangerous features, patch and monitor                  |
| MySQL                   | 8.0.42  | 2 (older version) | Medium     | Secure root login, use PoLP accounts                           |
| External Themes/Plugins | N/A     | Several           | Medium     | Avoid use unless vendor-verified                               |

---

## 6. Recommendations

* Maintain a list of all third-party components and their versions (Software Bill of Materials).
* Configure automatic security updates for Ubuntu packages where feasible.
* Apply the **Principle of Least Privilege** for all service accounts.
* Disable or uninstall unused PHP/Apache modules.
* Monitor CVE databases (e.g., NVD, MITRE, Snyk) and subscribe to security advisories.
* Consider integrating tools like:

  * `osv-scanner` for package-based CVEs
  * `cve-bin-tool` for binary-based CVE detection
  * `trivy` for filesystem and dependency scans

---

## 7. Suggested GitHub Structure

```bash
Phase-2/
├── third_party_risks.md
├── screenshots/
│   └── third_party/
│       ├── php_modules.png
│       ├── apache_modules.png
│       ├── dpkg_php.png
│       └── mysql_root_login.png
```
---
