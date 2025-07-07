# Asset Register – E-commerce Security Lab

This asset register includes a comprehensive list of physical, digital, human, document, service, and software assets relevant to the simulated e-commerce environment. Each asset is categorized and rated based on its sensitivity to security risks.

| Asset Name              | Description                                           | Category           | Location                                         | Sensitivity |
| ----------------------- | ----------------------------------------------------- | ------------------ | ------------------------------------------------ | ----------- |
| OpenCart Web App        | E-commerce platform running on Apache                 | Web Application        | /var/www/html                                    | High        |
| OpenCart Admin Panel    | Management dashboard for store                        | Web Application    | [http://localhost/admin](http://localhost/admin) | High        |
| Default Admin Account   | Built-in OpenCart admin identity                      | User (Human)       | Web App Interface                                | High        |
| Apache Web Server       | Serves OpenCart over HTTP                             | System Software    | Ubuntu VM                                        | High        |
| MySQL Database          | Stores customer data, orders, and configs             | Database           | Localhost:3306                                   | High        |
| Admin Credentials       | Admin login for OpenCart                              | Credential         | Stored in DB                                     | High        |
| Customer Data           | Personally identifiable and transactional information | Digital Asset      | MySQL Database                                   | High        |
| Backup Archives         | Backups of code and database                          | Digital Asset      | /var/www/html/system/storage/backup                     | High        |
| VMware Workstation Host Machine | Host system (Windows 11) running the Ubuntu VM via VMware Workstation                        | Physical Asset     | Personal Laptop                                  | High        |
| Ubuntu 22.04 OS         | Base operating system                                 | Operating System   | VMware Workstation VM                                    | Medium      |
| Apache Config Files     | Controls server behavior                              | Configuration File | /etc/apache2/                                    | Medium      |
| System Logs             | Apache access/error logs                              | Log File           | /var/log/apache2/                                | Medium      |
| Network Configuration   | VM’s network settings                                 | Configuration File | /etc/network/                                    | Medium      |
| Internet Router         | Provides internet access to the VM via NAT/bridge through VMware Workstation                         | Physical Asset     | Home Network                                     | Medium      |
| CUPS Print Service       | Printing service running on port 631 (unused in current setup) | System Service      | Ubuntu VM                                    | Medium      |
| Robots.txt File         | Controls search engine behavior                       | Content File       | /var/www/html                                    | Low         |
| Paper Notes             | Intern's documentation, configs, written passwords    | Paper Document     | Physical Desk/Notebooks                          | Low         |




