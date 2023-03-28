# Burp Suite Extension: Sensitive Data Extractor

## Description

Sensitive Data Extractor is a Burp Suite extension created to automatically identify sensitive information leaked in HTTP responses. The extension can detect various types of data, such as passwords, API keys, tokens, and private keys. This tool helps security professionals and developers identify sensitive data leaks in their applications, allowing them to implement appropriate security measures.

## Features

- Scan HTTP responses for sensitive data
- Detect a wide variety of sensitive data patterns, including:
  - Passwords
  - Google API Keys
  - Firebase credentials
  - Google Captcha Keys
  - Amazon AWS Access Key IDs
  - Facebook Access Tokens
  - Authorization tokens
  - Mailgun API keys
  - Twilio API keys
  - RSA/SSH/PGP Private Keys
  - JSON Web Tokens
  - Slack Tokens
  - Many more...

## Usage

1. Ensure you have Burp Suite Professional installed.
2. Install the Jython environment for Burp Suite.
3. Load the provided script (`Sensitive_Data_Extractor.py`) in the Extender tab of Burp Suite.
4. Configure the extension to run as an HTTP listener.
5. The extension will automatically analyze HTTP responses and report any detected sensitive data in the Scanner issues tab.

## Limitations

This extension is designed to find sensitive data based on specific patterns. It may not detect all types of sensitive data, and there may be false positives. It is essential to verify the results manually.

## Author

Berk Can Geyikci

## Changelog

- Created on: 2023-03-20
- Last modified: 2023-03-29
