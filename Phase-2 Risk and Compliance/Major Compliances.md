# Risk and Compliance Overview – Foundational Guide for Security Assessment

This document serves as an extensive primer on critical cybersecurity compliance frameworks and laws that form the foundation of digital security in modern organizations. Whether you're a student, a beginner in cybersecurity, or an engineer tasked with ensuring system resilience, this document provides deep insights into the **why**, **what**, and **how** of regulatory compliance.

---

## Why Compliance Matters

In the digital age, information is a strategic asset — but also a liability if not secured properly. Every organization that handles personal, financial, or business-critical data is bound by a set of legal, ethical, and industry-specific standards.

**Non-compliance can result in:**
- Financial penalties (up to millions of dollars)
- Legal action and criminal prosecution
- Data breaches and loss of customer trust
- Business disruption or shutdown

Understanding compliance frameworks helps ensure:
- **Data confidentiality, integrity, and availability (CIA)**
- **Trust with users, customers, and partners**
- **Preparedness for cyberattacks and audits**

---

## 1. ISO/IEC 27001 – The Global Standard for Information Security

**Full Name:** ISO/IEC 27001:2022 — Information Security, Cybersecurity and Privacy Protection

**Purpose:**  
To establish a robust Information Security Management System (ISMS) that protects sensitive information from being lost, stolen, altered, or misused.

**Audience:**  
Enterprises, governments, SMBs, cloud providers, startups — anyone who manages digital or physical information assets.

### Key Concepts:
| Term                | Description |
|---------------------|-------------|
| **ISMS**            | A formal system to manage and continuously improve information security risks. |
| **Annex A Controls**| A set of 93 reference security controls grouped under 4 themes: organizational, people, physical, and technological. |
| **PDCA Cycle**      | Plan-Do-Check-Act – continuous improvement model. |

### Compliance Steps:
1. Define security policies and leadership roles.
2. Identify assets, threats, vulnerabilities, and assess risks.
3. Select and implement relevant security controls.
4. Perform internal audits and get certified by external auditors.

### Example Controls:
- **Access Control**: Role-based access, multi-factor authentication.
- **Physical Security**: Securing server rooms, biometric access.
- **Cryptography**: Encryption at rest and in transit.
- **Incident Management**: Documented breach response procedure.

### Fun Fact:
ISO 27001 is so versatile that it's used by everything from hospitals to space agencies.

---

## 2. GDPR – General Data Protection Regulation (EU)

**Full Name:** Regulation (EU) 2016/679

**Purpose:**  
To empower individuals with control over their personal data and harmonize privacy laws across Europe.

**Audience:**  
Any organization — inside or outside the EU — that collects or processes the personal data of EU citizens.

### What is "Personal Data"?
Any information that can identify a person — name, email, IP address, location, health data, biometrics, etc.

### Core Principles:
| Principle                 | Description |
|---------------------------|-------------|
| **Lawfulness & Consent**  | Must have a valid reason and clear consent to collect data. |
| **Data Minimization**     | Only collect what is absolutely necessary. |
| **Storage Limitation**    | Don’t store personal data forever. |
| **Integrity & Security**  | Ensure data is not leaked or altered. |

### User Rights:
- Right to Access
- Right to be Forgotten (Erasure)
- Right to Data Portability
- Right to Object and Restrict Processing

### Penalties for Violations:
- Up to €20 million or 4% of annual global turnover — whichever is higher.

### Real-Life Example:
British Airways was fined £20 million in 2020 for GDPR violations after failing to protect customer data.

---

## 3. PCI-DSS – Payment Card Industry Data Security Standard

**Established By:**  
Visa, Mastercard, American Express, Discover, JCB

**Purpose:**  
To protect cardholder data in any environment that stores, processes, or transmits payment card information.

### Who Needs It?
- E-commerce websites
- Point-of-sale terminals
- Payment gateways and processors

### PCI-DSS Pillars (12 Requirements):

1. **Install firewalls and secure configurations**
2. **Do not use vendor-supplied default passwords**
3. **Protect stored cardholder data**
4. **Encrypt transmission of cardholder data**
5. **Use antivirus and update systems**
6. **Develop secure systems and apps**
7. **Restrict access to data on a need-to-know basis**
8. **Assign unique IDs to users**
9. **Physically secure systems**
10. **Track and monitor access**
11. **Test security systems**
12. **Maintain an information security policy**

### Technical Highlights:
- Use of TLS/SSL for secure connections
- Data masking (only showing last 4 digits of cards)
- Tokenization to avoid storing raw card numbers

### Penalty for Non-Compliance:
- Monthly fines by banks/card brands, often $5,000–$100,000
- Loss of payment processing privileges

---

## 4. DPDPA (India) – Digital Personal Data Protection Act, 2023

**Purpose:**  
India’s first comprehensive data protection law inspired by GDPR, enacted to safeguard citizens' digital privacy.

**Who Must Comply:**
- Any entity (private or public) processing the personal data of Indian citizens
- Data Fiduciaries (controllers) and Data Processors

### Key Principles:
| Principle         | Description |
|-------------------|-------------|
| **Consent-Based Processing** | Users must actively opt in. |
| **Purpose Limitation**       | Collect data only for specified, legal purposes. |
| **Data Minimization**        | Only collect what’s required. |
| **Right to Erasure**         | Individuals can request deletion of their data. |

### Rights of Data Principals (Users):
- Right to Know (about processing)
- Right to Correction and Erasure
- Right to Nominate (assign control in case of death or incapacity)
- Right to Redressal via Data Protection Board

### Data Breach Requirements:
- Must be reported to the **Data Protection Board of India**
- Penalties can go up to ₹250 crore (~$30 million)

### Interesting Insight:
DPDPA introduced the idea of “Privacy by Design,” making privacy features mandatory from the start of system development.

---

## 5. The Information Technology (IT) Act, 2000 – India’s Cyber Law

**Purpose:**  
To legally recognize electronic communications, transactions, and combat cybercrime in India.

**Key Features:**

| Section | Focus |
|---------|-------|
| **43**  | Penalty for unauthorized access, damage to data |
| **66**  | Hacking, identity theft, cyber fraud |
| **67**  | Obscene material online |
| **72**  | Breach of confidentiality and privacy |
| **CERT-In** | India's nodal agency for cyber incident response |

### 2008 Amendment:
- Introduced cyber terrorism (Section 66F)
- Made companies responsible for securing sensitive personal data
- Recognized digital signatures and e-contracts

### Technical Responsibilities for Businesses:
- Implement secure practices for handling data
- Secure critical infrastructure (websites, networks, servers)
- Report breaches to CERT-In within 6 hours (as per 2022 mandate)

---

## Summary of Framework Coverage

| Framework        | Scope                        | Main Audience             | Enforcement Authority                |
|------------------|------------------------------|---------------------------|--------------------------------------|
| ISO/IEC 27001    | Organizational InfoSec       | All organizations         | Private audit/certification bodies   |
| GDPR             | Personal data of EU citizens | Global organizations      | Data Protection Authorities (EU)     |
| PCI-DSS          | Payment card security        | Merchants, banks, fintech | PCI Security Standards Council       |
| DPDPA (India)    | Personal digital data        | Indian businesses         | Data Protection Board of India       |
| IT Act 2000      | Cyber law and offenses       | All IT systems in India   | Government of India, CERT-In         |

---

## Relevance to the E-Commerce Security Lab

The simulated e-commerce environment in this internship project processes both **personal** and **financial** information. Therefore, compliance with the above standards is critical.

| Component        | Frameworks Applicable                      |
|------------------|---------------------------------------------|
| Customer data    | GDPR, DPDPA, IT Act, ISO 27001              |
| Payment systems  | PCI-DSS, ISO 27001                          |
| Login systems    | ISO 27001, IT Act, GDPR                     |
| Logs and auditing| ISO 27001, PCI-DSS                          |
| Data storage     | DPDPA, GDPR, ISO 27001                      |

---

## Closing Note

Compliance is not just about checking boxes. It is about creating **secure, transparent, and resilient systems** that respect user trust and withstand legal and cyber threats. As future cybersecurity professionals, your role is not only to defend systems but to ensure they are **built securely from day one**.

If you're reading this and new to cybersecurity, consider diving deeper into:
- **NIST Cybersecurity Framework**
- **OWASP Top 10**
- **Zero Trust Architecture**
- **SOC2 / HIPAA / FedRAMP (for cloud compliance)**

---

