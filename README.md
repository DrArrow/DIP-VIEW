# DIP VIEW 🚀

### High-Performance Encrypted Archive Recovery Engine for Digital Forensics & Incident Response (DFIR)

<p align="center">
  <img src="demo.gif" alt="DIP VIEW Demo" width="900">
</p>

<p align="center">
Recover encrypted ZIP and RAR archives faster with optimized multi-core processing designed for forensic investigations.
</p>

<p align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</p>

---

# Why DIP VIEW?

During Digital Forensics and Incident Response (DFIR) investigations, analysts frequently encounter password-protected archives containing evidence that cannot be examined until access is recovered.

These archives may contain:

- Malware samples
- Stolen corporate documents
- Browser credentials
- Configuration files
- Log files
- Memory dump artifacts
- Source code
- Exfiltrated data

Traditional recovery workflows often require multiple tools, repeated archive parsing, and manual preparation before GPU acceleration can begin.

**DIP VIEW streamlines this process by providing a fast, CPU-optimized archive recovery engine that reduces unnecessary overhead and helps investigators access encrypted evidence more efficiently.**

---

# Investigation Workflow

```text
Evidence Acquisition
        │
        ▼
Encrypted ZIP/RAR Located
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
Malware Analysis • Timeline Analysis • IOC Collection
```

---

# Key Features

✅ Multi-core parallel processing

✅ Warm-cache worker architecture

✅ ZIP & RAR archive support

✅ Automatic encryption detection

✅ Wordlist attack mode

✅ Brute-force attack mode

✅ Hash export for Hashcat / John the Ripper

✅ Automatic dependency management

✅ Linux & Kali optimized

---

# Use Cases

DIP VIEW is designed for authorized security operations including:

- Digital Forensics
- Incident Response
- Malware Analysis
- Threat Hunting
- Security Research
- Red Team Labs
- Password Recovery for Authorized Archives

---

# Architecture

### Multi-Core Processing

Distributes password verification across all available CPU cores.

### Warm Cache

Archive handlers remain loaded in memory to reduce repeated file I/O.

### Optimized Verification

Performs lightweight validation to minimize unnecessary archive extraction.

---

# Installation

```bash
git clone https://github.com/yourusername/DIPVIEW.git

cd DIPVIEW

pip install -r requirements.txt
```

---

# Usage

```bash
python3 dipview.py
```

---

# Example

```
Target Archive : confidential.zip

Attack Mode : Wordlist

Wordlist : rockyou.txt

Status : Running...

Password Found : Password123
```

---

# Supported Formats

| Format | Status |
|---------|--------|
| ZIP | ✅ |
| AES ZIP | ✅ |
| RAR | ✅ |

---

# Roadmap

- GPU integration improvements
- Additional archive formats
- Session resume
- Distributed recovery
- GUI interface
- Enhanced reporting

---

# Disclaimer

DIP VIEW is intended solely for authorized digital forensic investigations, incident response activities, security research, and educational purposes.

Users are responsible for ensuring they have appropriate authorization before using this software.

---

# License

MIT License
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