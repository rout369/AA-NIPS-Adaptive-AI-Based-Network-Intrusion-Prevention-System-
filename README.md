# 🛡️ **ML-Powered Adaptive Firewall System**

## *AI-Driven Network Security | Final Year Project | Proof of Concept*

[![License: Custom](https://img.shields.io/badge/License-Custom-red.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Go 1.19+](https://img.shields.io/badge/Go-1.19+-00ADD8.svg)](https://golang.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-black.svg)](https://flask.palletsprojects.com/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.0+-FF6F00.svg)](https://tensorflow.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.0+-orange.svg)](https://scikit-learn.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-1.6+-green.svg)](https://xgboost.readthedocs.io/)
[![Status: Proof of Concept](https://img.shields.io/badge/Status-Proof%20of%20Concept-yellowgreen)]()

---

## 📋 **TABLE OF CONTENTS**
- [Project Overview](#-project-overview)
- [Core Features](#-core-features)
- [ML Pipeline Capabilities](#-ml-pipeline-capabilities)
- [Firewall Capabilities](#-firewall-capabilities)
- [Current Limitations](#-current-limitations--future-scope)
- [Demonstration Scenarios](#-demonstration-scenarios)
- [Technology Stack](#-technology-stack)
- [Getting Started](#-getting-started)
- [Project Structure](#-project-structure)
- [Contributors](#-contributors)
- [License](#-license)

---

## 🎯 **PROJECT OVERVIEW**

### **What Is This Project?**

This is a **final year academic project** that demonstrates how **Machine Learning can enhance traditional firewall systems** with **5-class attack classification** and **zero-day anomaly detection**. It bridges two worlds:

| Traditional Firewall | + | Machine Learning | = | **Adaptive Security** |
|---------------------|---|---|-----------------|---|
| Static rules | | Ensemble of 9+ classifiers | | Dynamic threat blocking |
| Manual updates | | Self-learning via feedback | | Zero-day detection |
| Known threats only | | Autoencoder anomaly detection | | Unknown attack prevention |

**This is a PROOF OF CONCEPT, designed to:**
- ✅ Demonstrate technical competency in both **Network Security** and **Machine Learning**
- ✅ Show **practical integration** between Python (ML) and Go (High-performance networking)
- ✅ Provide **visual, interactive demonstrations** for academic presentations
- ✅ Create a **foundation** that future students can build upon

---

## ✨ **CORE FEATURES**

### 🧠 **5-Class Machine Learning Detection** ⭐ *PRIMARY NOVELTY*

| Attack Class | Description | Examples |
|--------------|-------------|----------|
| **Normal** | Benign traffic | Web browsing, email, file transfer |
| **DoS** | Denial of Service | SYN flood, UDP flood, ICMP flood |
| **Probe** | Network scanning | Port scans, OS fingerprinting, vulnerability probing |
| **R2L** | Remote to Local | SSH brute force, FTP password guessing |
| **U2R** | User to Root | Buffer overflow, privilege escalation |

### 🔥 **Ensemble Model Architecture**
- **9 base models**: Random Forest, Decision Tree, Logistic Regression, Linear SVM, KNN, Naive Bayes, Neural Network (MLP), Gradient Boosting, XGBoost (plus optional LightGBM/CatBoost if installed)
- **Weighted voting** based on validation accuracy
- **Consensus scoring** to indicate model agreement
- **Per-class probabilities** for explainability

### 🚨 **Zero-Day Attack Detection**
- **Autoencoder** trained on normal traffic only (9 features from CIC-IDS-2017)
- Reconstruction error threshold flags anomalies (final threshold: **0.2960**)
- Separate "suspicious" and "critical" anomaly levels (strict threshold: **2.0398**)
- Detects never-before-seen attack patterns

### 🔄 **Bidirectional ML-Firewall Integration**

| Feature | Description | Status |
|--------|-------------|--------|
| **ML → Firewall** | Detected threats (with confidence) can auto-create temporary block rules | ✅ **Implemented** |
| **Firewall → ML** | False positive/missed attack feedback sent to ML service | ✅ **Implemented** |
| **Retraining** | After 4500 feedback samples, models can be retrained | ✅ **Implemented** |
| **Confidence Thresholds** | Per-attack-type thresholds for blocking decisions | ✅ **Implemented** |
| **Rule Expiry** | ML-generated rules auto-expire (24h default) | ✅ **Implemented** |

### 📊 **Comprehensive Logging & Dashboard**
- Structured JSON logs with attack type, confidence, action
- **Go-based web dashboard** for real-time visualization
- Filter connections by IP, threat level, attack type
- Provide feedback directly from dashboard
- Export history as JSON

### ⚡ **DDoS Protection Module**
- Per-IP rate tracking (1-minute sliding windows)
- Auto-block at 30+ connections/min for 2 minutes
- Warning at 15 connections/min
- Active attack display with remaining block time

### 🎛️ **Hyperparameter Tuner (Autoencoder)**
- Web interface to tune autoencoder architecture (layer sizes, regularization, etc.)
- Live training loss updates via WebSocket
- Export tuned model for deployment

---

## 🧠 **ML PIPELINE CAPABILITIES**

### **Multi-Model Ensemble Performance**

Trained on balanced NSL-KDD dataset (102,538 training samples, 40 features). Validation on 25,195 samples gave the following results:

| Model | Accuracy | F1 Macro | F1 (DoS) | F1 (Normal) | F1 (Probe) | F1 (R2L) | F1 (U2R) | Training Time |
|-------|----------|----------|----------|-------------|------------|----------|----------|---------------|
| **XGBoost** | **0.9968** | **0.9684** | 0.9993 | 0.9970 | 0.9890 | 0.9567 | **0.9000** | 1.2s |
| Random Forest | 0.9985 | 0.9566 | 0.9998 | 0.9986 | 0.9961 | 0.9701 | 0.8182 | 1.1s |
| Gradient Boosting | 0.9976 | 0.9496 | 0.9997 | 0.9978 | 0.9909 | 0.9770 | 0.7826 | 71.8s |
| Neural Network (MLP) | 0.9969 | 0.9214 | 0.9995 | 0.9972 | 0.9908 | 0.9529 | 0.6667 | 33.5s |
| KNN | 0.9964 | 0.9210 | 0.9989 | 0.9968 | 0.9903 | 0.9526 | 0.6667 | 0.02s |
| Decision Tree | 0.9921 | 0.8043 | 0.9995 | 0.9926 | 0.9897 | 0.8024 | 0.2373 | 0.9s |
| Linear SVM | 0.9472 | 0.6889 | 0.9890 | 0.9523 | 0.8356 | 0.5747 | 0.0930 | 49.6s |
| Logistic Regression | 0.9284 | 0.6479 | 0.9909 | 0.9322 | 0.8504 | 0.4277 | 0.0382 | 36.3s |
| Naive Bayes | 0.4982 | 0.3517 | 0.6888 | 0.1805 | 0.6632 | 0.2188 | 0.0075 | 0.1s |

**🏆 BEST MODEL: XGBoost** – selected automatically based on validation F1 macro score (**0.9684**).

### **Zero-Day Autoencoder Performance**

- **Architecture**: 9 input features, convolutional layers + dense layers, bottleneck size 8, attention mechanism
- **Dataset**: 99,906 samples of normal traffic from CIC-IDS-2017 (9 selected features)
- **Reconstruction error (validation)**: Mean = 0.1262, Std = 1.4504
- **Detection threshold** (95th percentile): **0.2960**
- **Strict threshold** (99th percentile): **2.0398**
- **Best validation loss**: 0.2081

### **Features Extracted from Live Traffic**

**41 NSL-KDD features (for 5‑class classification):**
- **Basic**: duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent
- **Content**: hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_host_login, is_guest_login
- **Traffic (time-based)**: count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate
- **Host-based**: dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate

**9 autoencoder features (for zero‑day detection):**
- Destination_Port, Flow_Duration, Total_Fwd_Packets, Total_Backward_Packets, Fwd_Packet_Length_Mean, Flow_Bytes/s, Flow_Packets/s, Init_Win_bytes_forward, Init_Win_bytes_backward

### **Test Set Evaluation (KDDTest+ with Novel Attacks)**

When evaluated on the full KDDTest+ dataset (22,544 samples, including 17 novel attack types not seen in training), the best model (XGBoost) achieved:

| Metric | Value |
|--------|-------|
| Accuracy | 0.7405 |
| F1 Macro | 0.5226 |
| F1 (DoS) | 0.8503 |
| F1 (Normal) | 0.7754 |
| F1 (Probe) | 0.7049 |
| F1 (R2L) | 0.0090 |
| F1 (U2R) | 0.2737 |

*Note: The drop in R2L and U2R performance is expected due to the extremely low representation of these classes in training and the novelty of many attacks in the test set. This highlights the challenge of detecting rare and novel attack types – exactly why we include a separate zero‑day autoencoder.*

### **Feedback & Retraining**
- Feedback stored in `feedback/feedback_with_features.jsonl`
- Minimum **4500 samples** required for retraining
- Retraining combines original data + feedback, retrains all models, updates weights
- API endpoints to check status and trigger retraining

---

## 🔥 **FIREWALL CAPABILITIES**

### **Rule System (Enhanced)**

**Rule Structure:**
```
ID: rule-1647358921-42  or  ml-1234567890-5
Type: block | allow
Source: 192.168.1.0/24 | 10.0.0.* | any
Destination: 8.8.8.8 | any
Port: 22 | 443 | 0 (any)
Protocol: tcp | udp | icmp | any
Priority: 1-100 (higher = more important)
Enabled: true | false
Description: "Block malicious IP"
MLGenerated: true/false
AttackType: "DoS" | "Probe" | etc. (if ML)
ExpiresAt: timestamp (for ML rules)
```

**Priority Levels:**
```
Priority 100: 🔴 CRITICAL - Active attacks (U2R, high‑confidence DoS)
Priority 80:  🟠 HIGH - ML‑generated threats
Priority 50:  🟡 MEDIUM - Suspicious subnets
Priority 20:  🟢 LOW - Default allow rules
Priority 1:   ⚪ INFO - Logging only
```

### **ML Integration in Firewall**
- On each packet, the firewall extracts 41 features and calls the ML service's `/multiclass_score` endpoint.
- Receives per‑class probabilities, predicted class, confidence, consensus.
- Anomaly score optionally obtained from `/anomaly_score`.
- Based on attack type and confidence, firewall decides to block, alert, or allow.
- If confidence is high enough, an ML‑generated temporary rule is auto‑created.

### **CLI Commands (Updated)**

| Command | Description | Example |
|--------|-------------|---------|
| `help` | Show all commands | `help` |
| `rules` | List all firewall rules | `rules` |
| `add` | Add simple rule | `add block 1.2.3.4 any tcp 0 "Bad IP"` |
| `add-priority` | Add rule with priority | `add-priority allow 10.0.0.5 any any 0 50 "Trusted"` |
| `remove` | Remove rule by ID | `remove rule-12345` |
| `enable`/`disable` | Toggle rules | `enable rule-12345` |
| `test` | Test a connection | `test 1.2.3.4 8.8.8.8 80 tcp` |
| `stats` | Show firewall statistics | `stats` |
| `attack-stats` | Show attack type breakdown | `attack-stats` |
| `ddos-stats` | Show DDoS protection stats | `ddos-stats` |
| `attacks` | Show active DDoS attacks | `attacks` |
| `logs` | View recent logs | `logs 50` |
| `logs-search` | Search logs by IP | `logs-search 192.168.1.100` |
| `monitor` | Show monitoring status | `monitor` |
| `ml-status` | Show ML service status and model info | `ml-status` |
| `analyze` | Analyze PCAP file with ML | `analyze suspicious.pcap 0.7` |
| `feedback-stats` | Show feedback statistics | `feedback-stats` |
| `retrain` | Trigger model retraining | `retrain` |
| `history` | Launch web dashboard | `history` |
| `exit` | Quit firewall | `exit` |

### **Web Dashboard (Go)**
- Accessible at `http://localhost:8081`
- Real‑time connection history with filtering by IP, threat level, attack type
- Detailed per‑connection ML scores and model contributions
- Inline feedback submission
- Export data as JSON

---

## ⚠️ **CURRENT LIMITATIONS & FUTURE SCOPE**

*This section outlines intentional scope boundaries for this academic project.*

### 🔴 **1. DETECTION MODE ONLY (By Design)**

```
┌─────────────────────────────────────────────────────────────────┐
│                      CURRENT BEHAVIOR                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   🔍 ML DETECTS THREAT → 🔴 SHOWS "BLOCK" DECISION              │
│         ↓                                                       │
│   📝 PACKET PASSES THROUGH → 📋 LOGGED FOR ANALYSIS            │
│         ↓                                                       │
│   👨‍🏫 PROFESSOR SEES: "System correctly identified attack!"      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**🎓 WHY THIS IS OKAY FOR OUR PROJECT:**
- ✅ **Safe for lab environment** – No risk of disrupting university network
- ✅ **Still proves the concept** – Detection is the hard part; enforcement is trivial
- ✅ **Better for demos** – You SEE the red "BLOCKED" message without actually breaking connections
- ✅ **Academic integrity** – Demonstrates understanding without causing harm

**🔧 EASY FUTURE ENHANCEMENT:**
- Add `--enforce` flag that calls OS firewall (iptables, pf, Windows Firewall)

---

### 🔴 **2. IN-MEMORY STORAGE ONLY (By Design)**

```
┌─────────────────────────────────────────────────────────────────┐
│                      CURRENT BEHAVIOR                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   💾 RULES STORED IN RAM ONLY                                   │
│   💀 CLOSE PROGRAM → LOSE ALL RULES                             │
│   📊 LOGS: LAST 10000 CONNECTIONS IN MEMORY                     │
│   📋 FEEDBACK: PERSISTED TO JSONL FILES                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**🎓 WHY THIS IS OKAY:**
- ✅ **Simpler code** – Students can understand it quickly
- ✅ **Fresh start each run** – Perfect for repeated demonstrations
- ✅ **No database dependency** – Works immediately after git clone
- ✅ **Feedback still persists** – Important for retraining demonstration

**🔧 EASY FUTURE ENHANCEMENT:**
- Save rules to JSON on exit and load on startup

---

### 🔴 **3. SINGLE MACHINE DEPLOYMENT (By Design)**

```
┌─────────────────────────────────────────────────────────────────┐
│                      CURRENT BEHAVIOR                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   🖥️ FIREWALL + ML = SAME LAPTOP                               │
│   🌐 ONLY MONITORS TRAFFIC OF THAT MACHINE                     │
│   🎯 PERFECT FOR: Classroom demos, lab exercises               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**🎓 WHY THIS IS OKAY:**
- ✅ **Zero infrastructure** – No servers, no cloud, no networking headaches
- ✅ **Works offline** – Present anywhere, anytime
- ✅ **Easy debugging** – Everything in one place
- ✅ **Cost free** – No AWS/Azure credits needed

**🔧 EASY FUTURE ENHANCEMENT:**
- Package as Docker containers for distributed deployment

---

### 🔴 **4. TRAINED ON PUBLIC DATASETS**

```
┌─────────────────────────────────────────────────────────────────┐
│                      CURRENT BEHAVIOR                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   📚 TRAINING DATA:                                            │
│   • NSL-KDD (balanced, 5‑class)                                 │
│   • CIC-IDS-2017 (for autoencoder)                              │
│                                                                 │
│   ✅ PREDICTABLE, REPRODUCIBLE RESULTS                         │
│   ❌ MAY NOT GENERALIZE TO ALL REAL TRAFFIC                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**🎓 WHY THIS IS OKAY:**
- ✅ **Controlled experiments** – Know exactly what the model should detect
- ✅ **No privacy concerns** – No real user data involved
- ✅ **Quick training** – Minutes instead of days
- ✅ **Academic honesty** – Clear provenance of training data

**🔧 EASY FUTURE ENHANCEMENT:**
- Collect opt‑in traffic with ethics approval
- Use more recent datasets (CSE‑CIC‑IDS‑2018, UNSW‑NB15)

---

### 🔴 **5. IPv4 ONLY**

```
┌─────────────────────────────────────────────────────────────────┐
│                      CURRENT BEHAVIOR                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   🌍 IPv4: ✅ FULLY SUPPORTED                                  │
│   🌏 IPv6: ❌ NOT SUPPORTED                                    │
│                                                                 │
│   📌 94% OF INTERNET TRAFFIC IS STILL IPv4                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**🎓 WHY THIS IS OKAY:**
- ✅ **IPv4 is sufficient** for demonstrating ALL core concepts
- ✅ **Simpler code** – No dual‑stack complexity
- ✅ **Wider compatibility** – Works in more lab environments

**🔧 EASY FUTURE ENHANCEMENT:**
- Add IPv6 parsing in packet monitor

---

## 🎓 **DEMONSTRATION SCENARIOS**

### **Scenario 1: 5-Class Detection of Port Scan**
```
1. 👨‍🏫 Start ML service:   python ml_service.py
2. 👨‍🏫 Start firewall:      ./firewall --ml
3. 🖥️ In another terminal:  nmap -sS localhost
4. 🔴 Firewall output:
   🟠 Probe attack detected! (confidence 94%)
   🔴 FIREWALL BLOCK: 127.0.0.1:54321 → 127.0.0.1:22 tcp (Probe)
5. 📋 Check logs: logs-search 127.0.0.1
6. 🎯 Result: "System correctly identified probe/scan activity!"
```

### **Scenario 2: Zero-Day Anomaly Detection**
```
1. 👨‍🏫 Start ML service (autoencoder loaded)
2. 👨‍🏫 Start firewall with --ml
3. 🖥️ Run a custom exploit script (not in training data)
4. 🔴 Firewall shows:
   ═════ ZERO-DAY ANOMALY DETECTION ═════
   Reconstruction Error: 0.5234 🔴
   Status: critical
   🚨 ZERO-DAY CANDIDATE!
   Highly anomalous - Unknown attack pattern
5. 🎯 Result: "System flagged a never‑before‑seen attack pattern!"
```

### **Scenario 3: Feedback Loop & Retraining**
```
1. 👨‍🏫 While monitoring, a false positive occurs (ML flagged normal as DoS).
2. 👨‍🏫 In dashboard or CLI: feedback-stats shows 1 false positive.
3. 🖥️ Provide feedback via CLI or dashboard.
4. 📊 After collecting 4500 samples, check retrain status.
5. 🔄 Trigger retrain: retrain
   ✅ Retraining complete! New accuracy: 97.5% (was 96.8%)
6. 🎯 Result: "The system improved itself using human feedback!"
```

---

## 🛠️ **TECHNOLOGY STACK**

### **Machine Learning Service (Python)**
| Component | Library | Purpose |
|-----------|---------|---------|
| **Web Framework** | Flask | REST API for ML inference |
| **ML Models** | scikit-learn, XGBoost | 5‑class classifiers (9 models) |
| **Deep Learning** | TensorFlow/Keras | Autoencoder for zero‑day |
| **Data Processing** | pandas, numpy, joblib | Feature extraction, serialization |
| **Packet Parsing** | scapy | PCAP analysis |
| **Visualization** | matplotlib, seaborn, shap | Training plots, feature importance |
| **Hyperparameter Tuning** | Flask + WebSockets | Tuner web app |

### **Firewall Engine (Go)**
| Component | Library | Purpose |
|-----------|---------|---------|
| **Packet Capture** | gopacket/pcap | Live traffic monitoring |
| **HTTP Client** | net/http | Communicate with ML service |
| **Concurrency** | goroutines, sync | Parallel packet processing |
| **CLI Interface** | bufio, flag | Command handling |
| **Web Dashboard** | net/http, html/template, embed | Built‑in UI |
| **JSON Handling** | encoding/json | Log formatting, API data |

---

## 🚀 **GETTING STARTED**

### **Prerequisites**
- Python 3.9+
- Go 1.19+
- libpcap / WinPcap / Npcap
- 8GB RAM (recommended for training)
- 2GB disk space

### **Quick Start (5 minutes)**

```bash
# 1. Clone repository
git clone https://github.com/rout369/AA-NIPS-Adaptive-AI-Based-Network-Intrusion-Prevention-System-
cd AA-NIPS-Adaptive-AI-Based-Network-Intrusion-Prevention-System-

# 2. Setup Python environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# 3. (Optional) Train models – already provided in models/ folder
#    To retrain from scratch:
#    cd model_trainer
#    python supervised_model_trainer.py   # trains 9 models (~2-3 min)
#    python unsupervised_model_trainer.py # trains autoencoder (~2 min)

# 4. Start ML service
cd ml_pipeline
python ml_service.py

# In a new terminal:

# 5. Build and run Go firewall
cd ../go_firewall
go mod download
go build -o firewall.exe
./firewall.exe --ml

# 6. In a third terminal, generate test traffic (optional)
python examples/attack_simulator.py --type port_scan

# 7. Open dashboard (after stopping monitoring with Ctrl+C)
firewall> history
```

### **Verify Installation**
```bash
firewall> ml-status
✅ Service: Connected
   Models loaded: 9
   🏆 Best model: XGBoost (F1 Score: 96.8%)
   Features: 41
   Auto-block threshold: 80%

firewall> test 1.2.3.4 8.8.8.8 80 tcp
✅ ALLOWED: 1.2.3.4 -> 8.8.8.8:80 tcp (Default allow)

firewall> stats
📊 Firewall Statistics
Total Rules: 5
ML Rules: 0
DDoS Blocks: 0
ML Blocks: 0
```

---

## 📂 **PROJECT STRUCTURE**

```
ml-adaptive-firewall/
│
├── 📁 ml_pipeline/                 # Python ML Service
│   ├── ml_service.py              # Flask REST API
│   ├── supervised_model_trainer.py # Train 5‑class models
│   ├── unsupervised_model_trainer.py # Train autoencoder
│   ├── retrain.py                  # Retrain with feedback
│   ├── tuner_app.py                # Autoencoder hyperparameter tuner
│   ├── 📁 models/                   # Saved models, scalers, weights
│   ├── 📁 feedback/                  # JSONL feedback files
│   └── requirements.txt
│
├── 📁 model_trainer/               # (Optional) Standalone training scripts
│   ├── supervised_model_trainer.py
│   ├── unsupervised_model_trainer.py
│   └── ...
│
├── 📁 go_firewall/                 # Go Firewall Engine
│   ├── main.go                     # CLI entry point
│   ├── firewall.go                 # Core firewall logic
│   ├── packet_monitor.go           # Live packet capture
│   ├── ml_client.go                # ML service client
│   ├── dashboard.go                 # Web dashboard server
│   ├── 📁 static/                    # Dashboard assets (CSS, JS)
│   ├── 📁 templates/                  # HTML templates
│   └── go.mod
│
├── 📁 examples/                    # Demo Materials
│   ├── attack_simulator.py         # Generate test attacks
│   └── 📁 pcaps/                   # Sample PCAP files
│
├── 📁 docs/                        # Documentation
│   ├── architecture.md
│   └── demo_guide.md
│
├── README.md                       # This file
└── LICENSE
```

---

## 👥 **CONTRIBUTORS**

### **Project Lead**
- **Biswajit Rout** – Final Year Student, Computer Science
  - ML Pipeline Development
  - Firewall Rule Engine
  - System Integration

### **Supervisor**
- **Professor Name** – Department of Computer Science

### **Acknowledgments**
- Open source maintainers of scikit‑learn, XGBoost, gopacket, TensorFlow, Flask

---

## 📄 **LICENSE**

**OTHER License** – All rights reserved.

```
Copyright (c) 2026 Biswajit Rout

All rights reserved.

This repository and its contents are provided solely for
private research, academic review, and internal development.

Permission is granted to access, view, and execute the code
for evaluation and research purposes only.

No permission is granted to:
- copy, modify, or redistribute the code
- use the code for commercial purposes
- publish derived works
- train models or systems using this code

This code may not be disclosed publicly without explicit
written permission from the author.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## 🏆 **PROJECT SUMMARY**

| **Title** | ML‑Powered Adaptive Firewall System (5‑Class + Zero‑Day) |
|-----------|---------------------------------------------------------|
| **Author**| Biswajit Rout, Final Year B.Tech CSE |
| **Supervisor** | [Professor Name] |
| **Institution** | [Your University Name] |
| **Year** | 2026 |
| **Keywords** | Network Security, Machine Learning, Ensemble Learning, Autoencoder, Zero‑Day Detection, Firewall, DDoS, Intrusion Detection, NSL‑KDD, CIC‑IDS‑2017 |
| **Technologies** | Python, scikit‑learn, XGBoost, TensorFlow, Flask, Go, gopacket, PCAP |
| **GitHub** | [github.com/rout369/AA-NIPS-Adaptive-AI-Based-Network-Intrusion-Prevention-System-](https://github.com/rout369/AA-NIPS-Adaptive-AI-Based-Network-Intrusion-Prevention-System-) |

---
