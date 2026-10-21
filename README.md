
# WebShield — Automated Website Security Scanner

## Overview
WebShield is a Python and Flask web application that checks a website's HTTPS status and the presence of common HTTP security headers. It provides recommendations for missing headers and allows users to download a CSV report.

## Features
- Check a website's HTTPS status
- Inspect five common security headers
- Display present and missing headers
- Provide recommendations for missing headers
- Download a CSV security report

## Technologies Used
- Python
- Flask
- Requests
- HTML
- CSS

## Run Locally
1. Install Python 3.
2. Create and activate a virtual environment.
3. Install dependencies using `pip install -r requirements.txt`.
4. Start the application using `python app.py`.
5. Open `http://127.0.0.1:5001` in your browser.

## Security Headers Checked
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

## Limitations
This is an educational project, not a complete penetration-testing tool. Missing headers do not automatically mean a website is vulnerable, and present headers do not guarantee that a website is secure.

## Ethical Use
Only scan websites you own or have permission to test.

## Project Status
Student cybersecurity project — features should be tested before deployment.
