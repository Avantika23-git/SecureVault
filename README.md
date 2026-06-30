# SecureVault

SecureVault is a cybersecurity-focused web application that combines secure file storage with integrated threat detection. The system enables users to securely store sensitive files using encryption while identifying phishing emails and malicious URLs through built-in security modules.

The project aims to improve data confidentiality, integrity, and user awareness by bringing secure file management and threat analysis into a single platform.

---

## Features

### Secure File Vault
- User registration and authentication
- Secure file upload and download
- AES (Fernet)-based file encryption and decryption
- User-specific encrypted storage
- Activity logging

### PhishGuard
- Email phishing analysis
- Risk score generation
- Detection of phishing indicators and suspicious keywords
- Threat classification (Low, Medium, High)

### URL Scanner
- URL reputation analysis
- VirusTotal integration
- Domain and IP information
- Detection of malicious and suspicious URLs

---

## Technology Stack

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- Flask

### Database
- SQLite
- SQLAlchemy

### Security
- Cryptography (Fernet / AES Encryption)
- VirusTotal API

---

## Project Structure

```text
SecureVault/
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── files.html
│   ├── logs.html
│   ├── phishguard.html
│   ├── urlscanner.html
│   ├── reports.html
│   ├── settings.html
│   └── auditlog.html
│
├── uploads/
├── reports/
│   └── report_history.json
│
├── app.py
├── email_analyzer.py
├── requirements.txt
├── secret.key
└── README.md
```

---

## Installation

### Clone the repository

```bash
git clone https://github.com/yourusername/SecureVault.git
cd SecureVault
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the application

```bash
python app.py
```

Open your browser and navigate to:

```text
http://127.0.0.1:5000
```

---

## Modules

### SecureVault
Encrypts uploaded files before storing them and decrypts them only during authorized downloads, ensuring secure file management and data confidentiality.

### PhishGuard
Analyzes email content to detect phishing characteristics, generates a risk score, and highlights suspicious indicators to help users identify potential phishing attacks.

### URL Scanner
Checks URLs using the VirusTotal API and displays security information such as reputation, domain details, IP address, and malicious detection results.

---

## Future Enhancements

- Multi-factor authentication (MFA)
- Malware scanning for uploaded files
- AI-based phishing detection
- Real-time threat monitoring
- Cloud storage integration
- Role-based access control





## Team

* **Member 1:** User Authentication, Database, Dashboard
* **Member 2:** Secure File Vault, File Encryption & Management
* **Member 3:** PhishGuard, URL Scanner, UI Design, Testing & Documentation

---

## License

This project was developed for academic and educational purposes.


