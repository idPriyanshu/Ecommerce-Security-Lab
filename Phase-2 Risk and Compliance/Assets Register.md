# Asset Register – E-commerce Security Lab

| Asset Name          | Description                                   | Category       | Location             | Sensitivity |
|---------------------|-----------------------------------------------|----------------|----------------------|-------------|
| OpenCart Web App    | E-commerce platform running on Apache         | Application    | /var/www/html        | High        |
| Apache Web Server   | Serves OpenCart over HTTP                     | System Software| Ubuntu VM            | High        |
| MySQL Database      | Stores customer data, orders, and configs     | Database       | Localhost:3306       | High        |
| Admin Credentials   | Admin login for OpenCart                      | Credential     | Stored in DB         | High        |
| Ubuntu 22.04 OS     | Base operating system                         | OS             | VirtualBox VM        | Medium      |
| Apache Config Files | Controls server behavior                      | Configuration  | /etc/apache2/        | Medium      |
| Robots.txt File     | Controls search engine behavior               | Content File   | /var/www/html        | Low         |
| System Logs         | Apache access/error logs                      | Log File       | /var/log/apache2/    | Medium      |
