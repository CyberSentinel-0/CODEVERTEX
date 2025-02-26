# CODEVERTEX Internship Projects

Welcome to my repository for the **CODEVERTEX Internship Projects**. During my first month of training at CODEVERTEX, I developed four small but impactful projects to deepen my understanding of various programming concepts and technologies. These projects include:

- **Encryption-Decryption**: A secure application for encrypting and decrypting messages.
- **Network Analyzer**: A tool to analyze network traffic and system connectivity.
- **New Webpage**: A modern, responsive webpage built to showcase web development techniques.
- **Password Strength Checker**: An application that evaluates password strength using regular expressions.

Each project has been packaged as a standalone application with an executable file (`.exe`) located in its respective `dist` folder. You can run the executable directly for a hassle-free experience.

## Table of Contents

- [Overview](#overview)
- [Projects](#projects)
  - [Encryption-Decryption](#encryption-decryption)
  - [Network Analyzer](#network-analyzer)
  - [New Webpage](#new-webpage)
  - [Password Checker](#password-checker)
- [Prerequisites](#prerequisites)
- [Installation & Usage](#installation--usage)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Overview

This repository contains the source code and executables for four projects developed during my internship at CODEVERTEX. Each project was designed to address a specific challenge:
- **Encryption-Decryption**: Implements AES encryption with padding, base64 encoding, and a graphical user interface (GUI) using Tkinter. It even copies results to the clipboard using `pyperclip`.
- **Network Analyzer**: Uses Scapy and psutil to capture and analyze network packets, with a GUI interface built using Tkinter.
- **New Webpage**: A modern webpage project showcasing HTML, CSS, and JavaScript to create a responsive and interactive website.
- **Password Checker**: Utilizes regular expressions to assess password strength, featuring a user-friendly interface built with Tkinter.

For each project, you can find the source code along with a compiled executable located in the `dist` folder. This structure ensures you can both review the code and run the application directly.

## Projects

### Encryption-Decryption

- **Description:** A desktop application that encrypts and decrypts messages using AES encryption. The application uses the Python `pycryptodome` library, ensuring that data is securely processed. It features a GUI built with Tkinter and integrates clipboard functionality using `pyperclip`.
- **Technologies:** Python, AES (Crypto), Tkinter, pyperclip
- **Executable:** Located in `encryption-decryption/dist/encrypt_decrypt_tool/encrypt_decrypt_tool.exe`

### Network Analyzer

- **Description:** An application designed to analyze network traffic and display various statistics about incoming and outgoing packets. Built using Scapy for packet handling and psutil for system monitoring, this tool also features a multi-threaded design to keep the user interface responsive.
- **Technologies:** Python, Scapy, psutil, Tkinter, threading
- **Executable:** Located in `network-analyzer/dist/network_analyzer/network_analyzer.exe`

### New Webpage

- **Description:** A modern and responsive webpage project created to demonstrate current state of phishing awareness site. The project includes HTML, CSS, and JavaScript files that work together to create an interactive user experience.
- **Technologies:** HTML, CSS, JavaScript
- **Executable:** The webpage is packaged as an executable (using a framework like Electron or a similar tool) and is located in `new-webpage/main.html`
- **Note:** If you prefer to view or modify the source code, simply open the project folder in your code editor.

### Password Checker

- **Description:** This project provides a simple yet effective way to check the strength of a password using regular expressions. With a clear and concise GUI built with Tkinter, users can quickly determine if their chosen password meets recommended security standards.
- **Technologies:** Python, Tkinter, re (Regular Expressions)
- **Executable:** Located in `password-checker/dist/password_checker/password_checker.exe`

## Prerequisites

To run or build these projects, ensure you have the following installed on your system:

- **Python 3.x** (required for running the source code)
- **pip** (Python package installer)
- The following Python packages:
  - `pycryptodome` (for Encryption-Decryption)
  - `pyperclip` (for clipboard operations in Encryption-Decryption)
  - `tkinter` (for GUI applications – typically included with Python)
  - `scapy` (for Network Analyzer)
  - `psutil` (for Network Analyzer)
- **Node.js/NPM** (if you plan to work on or modify the New Webpage project, depending on the build system used)
- A Windows environment (to run the provided `.exe` files)

> **Note:** Each project has its own set of dependencies. For detailed installation instructions for the source code, please refer to the individual project documentation within their respective folders.

## Installation & Usage

Each project has been self-contained within its own folder. To run a project:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/CyberSentinel-0/CODEVERTEX.git
   cd CODEVERTEX
