# Phase 1: Setup Steps – E-commerce Security Lab

This document outlines the step-by-step procedure for setting up a simulated e-commerce environment using VirtualBox, Ubuntu, and OpenCart as part of the 45-day cybersecurity internship project.

---

## 💽 1. System Requirements

* Host OS: Windows 11
* RAM: 8GB minimum (12GB+ recommended)
* Virtualization: Enabled in BIOS
* Tools Used:

  * [VirtualBox](https://www.virtualbox.org/)
  * [Ubuntu 22.04 LTS](https://ubuntu.com/download)
  * OpenCart 4.0.2.3

---

## 📦 2. Install VirtualBox

* Download and install from [https://www.virtualbox.org](https://www.virtualbox.org).
* Launch VirtualBox and click **New** to create a new VM.
* Configuration:

  * Name: `Ubuntu_Ecom_VM`
  * Type: Linux
  * Version: Ubuntu (64-bit)
  * RAM: 4096 MB or more
  * Hard Disk: 30 GB (Dynamically allocated)

---

## 🐧 3. Install Ubuntu 22.04 LTS on VM

* Attach Ubuntu ISO to the VM and boot.
* Proceed with standard installation steps:

  * Choose timezone, keyboard layout, and user credentials.
  * Select **Minimal Installation** and enable updates during install.
* Once installed, update the OS:

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 🌐 4. Install and Configure LAMP Stack

```bash
sudo apt install apache2 mysql-server php php-mysql libapache2-mod-php unzip curl -y
```

* Install missing PHP extensions required by OpenCart:

```bash
sudo apt install php-gd php-curl php-zip -y
```

* Enable Apache to start on boot:

```bash
sudo systemctl enable apache2
sudo systemctl start apache2
```

* Test: Visit `http://localhost` in your VM browser → Apache2 default page should appear.

---

## 🚖 5. Download and Setup OpenCart

* Navigate to web root:

```bash
cd /var/www/html
sudo rm index.html
```

* Download and unzip OpenCart:

```bash
sudo curl -L -o opencart.zip https://github.com/opencart/opencart/releases/download/4.0.2.3/opencart-4.0.2.3.zip
sudo unzip opencart.zip
```

* Move OpenCart files from the upload directory:

```bash
sudo mv opencart-4.0.2.3/upload/* .
sudo rm -rf opencart-4.0.2.3 upload opencart.zip
```

* Fix permissions:

```bash
sudo chown -R www-data:www-data /var/www/html/
sudo find /var/www/html/ -type d -exec chmod 755 {} \;
sudo find /var/www/html/ -type f -exec chmod 644 {} \;
```

* (Optional) Ensure Apache can write to storage/cache:

```bash
sudo chmod -R 775 /var/www/html/system/storage
```

---

## 🛠️ 6. Configure Apache for OpenCart

* Create a new virtual host config:

```bash
sudo nano /etc/apache2/sites-available/opencart.conf
```

* Paste the following:

```apache
<VirtualHost *:80>
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

* Enable site and mod\_rewrite:

```bash
sudo a2ensite opencart
sudo a2enmod rewrite
sudo systemctl restart apache2
```

---

## 🛡️ 7. Setup MySQL Database

```bash
sudo mysql
```

Inside MySQL shell:

```sql
CREATE DATABASE opencart;
CREATE USER 'oc_user'@'localhost' IDENTIFIED BY 'StrongPassword@123';
GRANT ALL PRIVILEGES ON opencart.* TO 'oc_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

---

## 🌐 8. Finish OpenCart Setup via Browser

* Open your browser inside VM → visit: `http://localhost`
* Follow OpenCart installation wizard:

  * Accept license
  * Verify PHP requirements (should all be green now)
  * Enter database credentials and admin account
* After successful installation, **remove the install folder**:

```bash
sudo rm -rf /var/www/html/install
```

---

## 🧠 9. Key Learnings from Phase 1

* Gained hands-on experience setting up a LAMP stack manually.
* Learned how e-commerce platforms like OpenCart are deployed and configured.
* Troubleshot real-world issues like:

  * Missing PHP extensions
  * File permission errors
  * Apache configuration
* Set up a working virtual e-commerce platform ready for applying layered security controls.

---

## 📸 10. Suggested Screenshots to Save

* Apache default page
* File extraction and permissions
* MySQL database setup
* OpenCart installation wizard (each step)
* Admin dashboard after successful login

---