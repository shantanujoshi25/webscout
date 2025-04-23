# WebScout - Advanced Web Security Scanner 

## Overview

WebScout is a powerful Chrome extension that helps you identify security vulnerabilities in web applications. It scans web pages for common security issues such as Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), SQL Injection, and SSL/TLS configurations.

## Features

- **Quick Security Scanning**: Analyze any webpage for vulnerabilities with a single click
- **AI-Enhanced Detection**: Leverages advanced machine learning to identify complex security issues
- **Comprehensive Vulnerability Reports**: Get detailed explanations and remediation steps
- **Multiple Scan Depths**: Choose between quick, standard, or thorough scanning based on your needs
- **Exportable Reports**: Save and share your security findings easily
- **User-Friendly Interface**: Clean, intuitive design for both technical and non-technical users

## Detected Vulnerabilities

WebScout can detect a variety of security issues, including:

- **Cross-Site Scripting (XSS)**: Identifies potential script injection points
- **Cross-Site Request Forgery (CSRF)**: Detects forms without proper protection
- **SQL Injection**: Finds potential database query vulnerabilities
- **File Inclusion/Upload Vulnerabilities**: Identifies insecure file handling
- **Command Injection**: Detects potential OS command execution issues
- **SSL/TLS Issues**: Checks for proper HTTPS implementation and HSTS headers

## Installation

### From Chrome Web Store

1. Visit the [Chrome Web Store](https://chrome.google.com/webstore) (link to be added)
2. Search for "WebScout Security Scanner"
3. Click "Add to Chrome"

### Manual Installation (Developer Mode)

1. Download or clone this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" in the top-right corner
4. Click "Load unpacked" and select the downloaded folder
5. The extension should now appear in your toolbar

## Usage

1. Navigate to any website you want to scan
2. Click the WebScout icon in your browser toolbar
3. Click the "Scan Current Page" button
4. Review the results in the vulnerabilities section
5. Export the report if needed

## Backend Setup

WebScout requires a local backend server to perform advanced analysis:

1. Make sure you have Python and Flask installed
2. Navigate to the backend directory: `cd backend`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the server: `python app.py`
5. The server will start on `http://127.0.0.1:5000`

## Settings

- **Scan Depth**: Choose between quick, standard, or thorough scans
- **AI-Enhanced Detection**: Toggle advanced AI-based vulnerability detection
- **Auto-Scan**: Automatically scan pages when you visit them

## Project Structure
