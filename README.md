# 🛡️ Malviz – Real-Time Threat Monitoring & Analysis Platform

Malviz is a **real-time Windows threat monitoring and analysis system** designed to detect, analyze, and visualize suspicious system activity.
It combines **process monitoring, syscall tracing, network analysis, and behavioral detection** into a unified dashboard.

---

## 🚀 Features

### 🔍 Process Monitoring

* Live process tracking (PID, user, path, status)
* Detection of suspicious execution paths (e.g., `ProgramData`, `Temp`)
* Privilege & token inspection

### ⚙️ Syscall Tracing

* Real-time syscall logging
* Detection of abnormal patterns (memory allocation, injection behavior)
* Useful for malware behavior analysis

### 🌐 Network Analyzer

* Packet capture (DNS, TCP, UDP)
* Source → Destination tracking
* Payload hex dump inspection
* Real-time dashboard routing to external Network IP addresses
* Detection of suspicious outbound connections

### 🧬 Deep Process Inspection

* Execution command line analysis
* Loaded DLLs & handles
* Memory usage & runtime behavior
* SHA-256 hashing for file integrity
* PE (Portable Executable) analysis:

  * DOS Header
  * File Header
  * Imported APIs

### 🧠 Threat Detection Engine

* Rule-based detection system
* Behavioral anomaly detection
* Suspicious execution alerts
* MITRE ATT&CK mapping

### 📜 Threat History & Alerting

* Logs all detected threats into SQLite
* Retains a persistent 24-hour Privilege Escalation tracker
* Native background Desktop Notifications via Web Push APIs
* Severity levels (Warning / Critical)
* Context-aware detection messages
* Deep inspection support for each event

### 🧪 Simulation Engine (Demo Mode)

* Simulate real attack scenarios:

  * Privilege escalation
  * Suspicious shell execution
  * Masquerading attacks
  * UAC Bypasses & Hijacking
* Scripts run infinitely to allow manual kill testing
* Helps demonstrate detection capabilities

---

## 🧠 Detection Capabilities

Malviz detects behaviors such as:

* Execution from non-standard directories
* Suspicious parent-child process relationships
* Use of system binaries (LOLBins)
* Network communication to unknown hosts
* Potential privilege escalation attempts

---

## 🖥️ Dashboard Overview

* 📊 System metrics (CPU, Memory, Disk, Network)
* ⚠️ Threat level indicator
* 🔎 Top suspicious processes
* 📡 Live process and network monitoring
* 📜 Historical threat logs

---

## 🏗️ Project Structure

```
backend/
├── main.py                 # Entry point
├── inspector.py           # Process inspection logic
├── threat_engine.py       # Detection logic
├── database.py            # Data handling
├── test_features.py       # Testing utilities
├── test_*.bat             # Attack simulation scripts
├── run_all_tests.bat      # Master simulation orchestrator
├── static/               # Frontend assets
└── .gitignore
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository

```bash
git clone git@github.com:HimanshuP601/Malviz.git
cd Malviz/backend
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python main.py
```

### 4. Open dashboard

```
http://localhost:8000
```

---

## 🔐 Security Note

* This project is intended for **educational and research purposes**
* Simulated attacks are used for demonstration only
* Do not deploy in production environments without hardening

---

## 🧪 Future Improvements

* 🔗 Attack chain correlation engine
* 🧠 Advanced behavioral scoring (AI/ML)
* 🌍 Geo-IP mapping for network connections
* 🧬 Memory injection detection

---

## 👨‍💻 Author

**Himanshu Parate**
Cybersecurity Enthusiast | Red Team Aspirant

---

## ⭐ Acknowledgment

Inspired by real-world EDR systems like:

* CrowdStrike Falcon
* Microsoft Defender for Endpoint
* Sysmon + SIEM tools

---

## 📌 Disclaimer

This tool is built for:

* Learning
* Demonstration
* Security research

Use responsibly.
