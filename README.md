# NetScan 🔎

## Description
NetScan is a tool designed to assist with external infrastructure and web application assessments. It simplifies the process of identifying valid web pages, detecting a range of vulnerabilities, and presenting the findings in easy-to-understand markdown tables for integration into Secure Portal.

## Requirements
To install this tool the following requirements need to be met:
- Homebrew installed
- Python installed
- Pip installed
- This tool can only be run on a Mac

## Installation
To install NetScan, follow these steps after downloading it from GitHub:

1. **Relocate the Installed Folder**: Move the downloaded folder to a permanent location on your system. Once set up, the folder cannot be moved as the startup script relies on its current location.
2. **Open Terminal**: Navigate to the folder in your terminal.
3. **Run Setup Script**: Execute `./setup.sh` in the terminal. This script installs all necessary dependencies and sets up the start script.

## Usage
To run NetScan, type `NetScan` in your terminal after installation and setup.



## Start a Scan

#### Nmap Input
- **File Type**: Accepts only `.txt` files.
- **Usage**: Upload a `.txt` file containing the full output of an Nmap scan. NetScan will parse this file and try each IP/port combination for public-facing web pages.

#### Domain Input
Enter hosts and ports you wish to scan in the domain input field, which accepts both valid domain names and IP addresses.

- **Default Ports**: Scans ports 80, 443, 8080, and 8443 by default.
- **Custom Ports**: To specify different ports, use the syntax:
  - `jackmason.com:443`
  - `jackmason.com:80,443`
- **Integration**: Matches domain names with inputs from an Nmap scan to access pages that require a valid domain name.

### Settings
Access the settings tab at the top right of the application to activate or deactivate modules. You must press the `Close and Save` button to update the settings; otherwise, they will not be saved.
- **Note**: Active scans require explicit permission from the customer.



## Current Modules

#### Headers
The Headers module checks the status of the recommended HTTP security headers and identifies any vulnerable HTTP headers.

#### JavaScript Software
This module checks for outdated software on a website through the website's terminal. If software is found, the following information is provided:
- **Current Version**
- **Latest Version**
- **CVEs**

#### Screenshots
This module provides a screenshot of what is on the webpage.

#### Cookies
This module evaluates whether the flags are set correctly on the website's cookies.

#### HTTP Methods
This module identifies any vulnerable HTTP methods that are allowed (TRACK, TRACE, etc.).

#### Basic Directories
This module checks for the following pages: Admin, Robots, Sitemap.

#### Basic Fuzzing
This module attempts to access 55 sensitive directories and shows the results based on unique pages.

#### Certificates
This module pulls back the certificate and highlights any vulnerabilities associated with it.

#### Ciphers
This module inspects the ciphers and highlights any vulnerable ciphers.



## Feedback
Your feedback is important. If you encounter any issues or have suggestions for improvement, please let me know.