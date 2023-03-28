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

## Requirements

- Burp Suite Professional 2023 2.3 or later
- Jython 2.7.3 or later

## Installation and Usage

1. Download and install [Burp Suite Professional](https://portswigger.net/burp/pro).
2. Download and install [Jython](https://www.jython.org/download).
3. In Burp Suite, navigate to the Extender tab, then click on the Options tab.
4. Under Python Environment, locate the Jython standalone JAR file you installed previously.
5. Go to the Extensions tab in the Extender and click on the Add button.
6. In the Add extension dialog, set the Extension type to Python, and select the `Sensitive_Data_Extractor.py` script.
7. Click the Next button to load the extension.

Once the extension is loaded, it will automatically analyze HTTP responses and report any detected sensitive data in the Scanner issues tab.

## Limitations

This extension is designed to find sensitive data based on specific patterns. It may not detect all types of sensitive data, and there may be false positives. It is essential to verify the results manually.

## Author

Berk Can Geyikci

## Changelog

- Created on: 2023-03-20
- Last modified: 2023-03-29
