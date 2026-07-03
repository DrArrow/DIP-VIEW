# DIP VIEW 🚀

### High-Performance Encrypted Archive Recovery Engine for Digital Forensics & Incident Response (DFIR)


Recover encrypted ZIP and RAR archives faster using an optimized multi-core processing engine built for Digital Forensics and Incident Response investigations.



[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)



---

# 🔍 Why DIP VIEW?

During **Digital Forensics and Incident Response (DFIR)** investigations, analysts frequently encounter password-protected archives that contain valuable evidence but cannot be examined until access is recovered.

These encrypted archives may contain:

- Malware samples
- Stolen corporate documents
- Browser credentials
- Configuration files
- Memory artifacts
- Log files
- Source code
- Threat actor toolkits
- Exfiltrated data

Traditional recovery workflows often require multiple tools, repeated archive parsing, excessive file I/O, or manual preparation before GPU acceleration can begin.

**DIP VIEW streamlines this workflow by providing a fast, CPU-optimized archive recovery engine that minimizes overhead and enables investigators to access encrypted evidence efficiently.**

---

# 🎬 Demonstration

The GIF below demonstrates DIP VIEW recovering the password of an encrypted archive during an authorized DFIR investigation.

<p align="center">
  <img src="demo.gif" alt="DIP VIEW Demo" width="900">
</p>

**Highlights**

- Multi-core password recovery
- ZIP & RAR support
- Wordlist and brute-force modes
- Custom archive path support
- Optimized CPU utilization

---

# 🛠 Investigation Workflow

```text
Evidence Acquisition
        │
        ▼
Encrypted ZIP / RAR Archive
        │
        ▼
      DIP VIEW
        │
        ▼
Password Recovery
        │
        ▼
Evidence Extraction
        │
        ▼
Malware Analysis
Credential Analysis
Timeline Reconstruction
IOC Collection
```

---

# ✨ Key Features

- 🚀 High-performance multi-core password recovery
- ⚡ Warm-cache worker architecture for reduced filesystem I/O
- 🔐 Automatic ZIP, AES-ZIP and RAR encryption detection
- 📂 Scan archives from the current directory
- 📁 Specify a custom archive path anywhere on the system
- 📚 Use built-in security dictionaries (RockYou, SecLists)
- 📄 Load your own custom password wordlists
- 🔢 Configurable brute-force password recovery
- ⚙️ Export hashes for Hashcat and John the Ripper
- 🔄 Automatic dependency installation and validation
- 💻 Optimized for Linux & Kali Linux
- 🛡️ Designed for Digital Forensics and Incident Response workflows

---

# 🎯 Recovery Modes

| Mode | Description | Recommended Use |
|------|-------------|-----------------|
| 📚 Wordlist Attack | Tests passwords from built-in or custom dictionaries | Credential leaks, corporate dictionaries |
| 🔢 Brute Force Attack | Generates password combinations dynamically | Unknown or short passwords |
| ⚙️ Hash Export | Exports archive hashes | GPU acceleration using Hashcat or John the Ripper |

---

# 🏗 Architecture

## Multi-Core Processing

Utilizes Python's `ProcessPoolExecutor` to distribute password verification across all available CPU cores, bypassing Python's Global Interpreter Lock (GIL).

## Warm-Cache Worker Context

Each worker initializes archive handlers only once and keeps them resident in memory to minimize repeated parsing and filesystem overhead.

## Optimized Verification

Performs lightweight validation to reduce unnecessary archive extraction while verifying password candidates.

---

# 📂 Supported Formats

| Archive | Supported |
|---------|-----------|
| ZIP | ✅ |
| AES Encrypted ZIP | ✅ |
| RAR | ✅ |

---

# ⚙️ Installation

## Requirements

- Python 3.8+
- Linux (Recommended)
- Kali Linux

### Optional System Packages

```bash
sudo apt update
sudo apt install rar unrar john -y
```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

# 🚀 Usage

Launch DIP VIEW:

```bash
python3 dipview.py
```

The interactive interface allows you to:

- 📂 Select an archive from the current directory
- 📁 Enter a custom archive path anywhere on the filesystem
- 📚 Use built-in or custom password wordlists
- 🔢 Run brute-force password recovery
- ⚙️ Export hashes for GPU-based recovery

---

# 📋 Example Session

```text
====================================================
                 DIP VIEW
====================================================

Archive Selection

1. Scan Current Directory
2. Enter Custom Archive Path

Choice: 2

Archive:
/home/analyst/evidence/Finance/backup.zip

----------------------------------------------------

Recovery Mode

1. Wordlist Attack
2. Brute Force Attack
3. Export Hash

Choice: 1

----------------------------------------------------

Wordlist

1. RockYou
2. SecLists
3. Custom Wordlist

Choice: 3

Wordlist:
/home/analyst/wordlists/company_passwords.txt

----------------------------------------------------

Status

Running...

Password Found : Finance@2025

Time Elapsed   : 00:00:18
```

---

# 💼 Use Cases

DIP VIEW is intended for authorized security operations including:

- Digital Forensics
- Incident Response
- Malware Analysis
- Threat Hunting
- Security Research
- Password Recovery for Authorized Archives
- Analysis of encrypted malware collections
- Investigation of compressed exfiltrated data
- Recovery of encrypted evidence archives

---

# 🗺 Roadmap

- GPU acceleration enhancements
- Additional archive format support
- Resume interrupted sessions
- Distributed password recovery
- GUI interface
- HTML/PDF forensic reports
- Performance benchmarking dashboard

---

# ⚠️ Disclaimer

DIP VIEW is intended **solely for authorized digital forensic investigations, incident response activities, security research, and educational purposes.**

Users are responsible for ensuring they have appropriate authorization before using this software. Unauthorized access to systems or data may violate applicable laws and regulations.

---

# 🤝 Contributing

Contributions are welcome.

If you'd like to improve DIP VIEW by adding features, fixing bugs, or optimizing performance, feel free to submit a pull request or open an issue.

---

# 📄 License

This project is licensed under the **MIT License**.

Copyright (c) 2026 DrArrow

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

<p align="center">

**Built for the Digital Forensics & Incident Response Community ❤️**

</p>