# Asset Register – E-commerce Security Lab

This asset register includes a comprehensive list of physical, digital, human, document, service, and software assets relevant to the simulated e-commerce environment. Each asset is categorized and rated based on its sensitivity to security risks. Assets are a mix of actually implemented components in the lab and conceptual elements for educational and compliance practice.

| Asset Name                      | Description                                                      | Category           | Location                                         | Sensitivity |
| ------------------------------- | ---------------------------------------------------------------- | ------------------ | ------------------------------------------------ | ----------- |
| Default Admin Account           | Built-in OpenCart admin identity                                 | User (Human)       | Web App Interface                                | High        |
| Intern Users                    | Participants using personal laptops to run the simulation        | User (Human)       | Local Laptops                                    | Medium      |
| Customers                       | External users purchasing from the platform                      | User (Human)       | Public Web Access                                | High        |
| Security Analyst                | Simulated role responsible for monitoring and response           | Role               | Security Function                                | High        |
| Data Protection Officer         | Responsible for data governance and DPDPA compliance             | Role               | Compliance Team                                  | High        |
| IT Support Staff                | Provides support for systems and hardware                        | Role               | Internal Team                                    | Medium      |
| Compliance Officer              | Oversees regulatory compliance activities                        | Role               | Compliance Team                                  | High        |
| Cybersecurity Team (Extended)   | Responsible for threat hunting, incident response, and hardening | Team               | Security Department                              | High        |
| Developer Team                  | Maintains and enhances OpenCart codebase                         | Team               | Engineering                                      | High        |
| OpenCart Web App                | Customer-facing e-commerce platform                              | Web Application    | /var/www/html                                    | High        |
| OpenCart Admin Panel            | Backend management interface                                     | Web Application    | [http://localhost/admin](http://localhost/admin) | High        |
| Customer Login Module           | Allows customers to access their account                         | Web Application    | /index.php?route=account/login                   | High        |
| Password Reset Module           | Password recovery functionality                                  | Web Application    | /index.php?route=account/forgotten               | High        |
| Apache Web Server               | Serves the OpenCart application                                  | System Software    | Ubuntu VM                                        | High        |
| MySQL Database                  | Stores application data                                          | Database           | Localhost:3306                                   | High        |
| Ubuntu 22.04 OS                 | Operating system for the virtual environment                     | Operating System   | VMware VM                                        | Medium      |
| CUPS Print Service              | Inactive printing service                                        | System Service     | Ubuntu VM                                        | Medium      |
| Cron Jobs                       | Automates backups and log rotation                               | Configuration File | /etc/cron.d/                                     | Low         |
| Apache Config Files             | Controls behavior of Apache server                               | Configuration File | /etc/apache2/                                    | Medium      |
| Network Configuration           | Network settings and IP mappings                                 | Configuration File | /etc/network/                                    | Medium      |
| robots.txt File                 | Web crawler restriction file                                     | Content File       | /var/www/html                                    | Low         |
| Uploaded Product Images         | Product media visible to users                                   | Digital Asset      | /image/                                          | Medium      |
| System Logs                     | Web server access and error logs                                 | Log File           | /var/log/apache2/                                | Medium      |
| Authentication Logs             | Logs of user authentication attempts                             | Log File           | /var/log/auth.log                                | Medium      |
| Audit Logs                      | Tracks system-level activities                                   | Log File           | /var/log/                                        | High        |
| Customer Data                   | Personal and transaction information                             | Digital Asset      | MySQL Database                                   | High        |
| Admin Credentials               | OpenCart admin login details                                     | Credential         | Stored in Database                               | High        |
| Customer Credentials            | Login data of customers                                          | Credential         | MySQL Database                                   | High        |
| Backup Archives                 | Full application and database backups                            | Digital Asset      | /var/www/html/storage                            | High        |
| Developer Notes                 | Implementation and internal documentation                        | Digital Document   | GitHub/Git Readme                                | Low         |
| Google Cloud Free Tier          | Cloud service for remote hosting                                 | Cloud Service      | cloud.google.com                                 | Medium      |
| GitHub Repository               | Source code and version control                                  | Cloud Service      | github.com/project-repo                          | High        |
| Payment Gateway Plugin          | Plugin for processing transactions (e.g., PayPal, Razorpay)      | External Service   | Checkout Module                                  | High        |
| Internet Service Provider       | Provides connectivity to host and VM                             | External Service   | Home ISP                                         | Medium      |
| Domain Registrar Account        | Manages domain ownership                                         | External Service   | Domain Provider                                  | Medium      |
| Open-source Security Tools      | Tools used for security testing (Nikto, Nmap)                    | Security Tool      | Local Environment                                | Medium      |
| Anti-Malware Software           | Endpoint protection                                              | Security Tool      | Ubuntu VM & Host                                 | Medium      |
| SSL Certificate (Self-signed)   | Enables encrypted HTTPS traffic                                  | Security Component | Apache SSL Config                                | High        |
| Session Management Mechanism    | Manages user sessions securely                                   | Web Component      | OpenCart Core                                    | High        |
| Email Notification Module       | Sends order confirmations and alerts                             | Web Component      | OpenCart Module                                  | Medium      |
| Paper Notes                     | Intern's handwritten documentation                               | Paper Document     | Physical Desk/Notebook                           | Low         |
| Training Material               | Printed learning content                                         | Paper Document     | On Desk/Shared Folder                            | Low         |
| Risk Assessment Report          | Threat and risk identification summary                           | Document           | Security Folder                                  | High        |
| Compliance Checklist            | Mapping of regulations to controls                               | Document           | Security Folder                                  | High        |
| Access Control Policy Document  | Defines who has access to what                                   | Policy Document    | Security Folder                                  | High        |
| Incident Response Template      | Steps for managing a breach                                      | Policy Document    | Documentation Folder                             | Medium      |
| Business Continuity Plan        | Ensures minimal disruption during disaster                       | Policy Document    | Documentation Folder                             | Medium      |
| Privacy Policy                  | Outlines customer data usage and rights                          | Policy Document    | Public Web Folder                                | High        |
| Company-Owned Laptops           |  inventory of 100 organizational laptops                         | Physical Asset     | Inventory Sheet / Office                         | High        |
| Network Switch                  | Hardware to connect multiple devices                             | Network Hardware   | Server Room                                      | High        |
| Firewall Appliance              | Provides network perimeter defense                               | Network Security   | Perimeter/VM Host                                | High        |
| Storage Server                  | Centralized backup and file storage                              | Storage Asset      |  Storage Device                         | High        |
| Audit Trail System              | Centralized logging system for auditing                          | Monitoring System  | /var/log/ or Syslog server                       | High        |
