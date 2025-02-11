<img src="screenshots/wpsec.png" style="display: block; margin: auto;" alt="WpSec">
        WpSeC - a powerful tool for Wordpress Security Scanning
 
-------------------------
![Supported OS](https://img.shields.io/badge/Supported%20OS-Linux-yellow.svg)
![License](https://img.shields.io/badge/license-intlicense--1.3-blue.svg)
![Owner](https://img.shields.io/badge/intSpLoiT-red.svg)
 
 # What is WpSeC
**WPSEC is a **command-line security scanner** designed to analyze WordPress websites for vulnerabilities, misconfigurations, and potential security risks. It automates various security checks to assist penetration testers, security researchers, and system administrators in assessing the security posture of WordPress-based web applications.**
 
  
# Features
- [x] **WordPress Detection**
- [x] **Open Port Scanning**
- [x] **Plugin & Theme Enumeration**
- [x] **WordPress Version Identification**
- [x] **User Enumeration & Credential Discovery**
- [x] **SQL Injection & XSS Scanner**
- [x] **Brute-Force Attack Module**
- [x] **Structured Logging**
- [x] **User Enumaration**

<img src="screenshots/lv_0_20250209114422.gif" style="display: block; margin: auto;" alt="WpSec">
# Usage
 
```
__ __ ___ __ ___ ___ __
 \ V  V / '_ (_-</ -_) _|
  \_/\_/| .__/__/\___\__|
        |_|
               wpsec - wordpresssecurity scanner by intSpLoiT


usage: scanner.py [-h] [-m {quick,default,deep}] [-l] [--sql] [--xss] [--brute] [--timeout TIMEOUT] [--verbose] url

WordPress Security Scanner

positional arguments:
  url                   Target WordPress site URL

options:
  -h, --help            show this help message and exit
  -m {quick,default,deep}, --mode {quick,default,deep}
                        Scan mode
  -l, --log             Save results to a log file
  --sql                 Run only SQL Injection scan
  --xss                 Run only XSS scan
  --brute               Run only brute-force attack
  --timeout TIMEOUT     Set request timeout (default: 5 seconds)
  --verbose             Enable detailed output
```
