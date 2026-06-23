# 🛡️ Real-Time Intrusion Detection System (IDS)

A machine learning-powered Real-Time Intrusion Detection System that monitors network traffic, detects known cyberattacks, and identifies unknown anomalies using a combination of supervised and unsupervised learning — all accessible through a Flask web application.

---

## 📌 Project Overview

Traditional rule-based intrusion detection systems often fail to catch sophisticated or unknown attacks. In this project, I built a real-time IDS that combines **Random Forest** (supervised learning) for detecting known attack patterns and an **Autoencoder** (unsupervised learning) for anomaly detection — making it capable of identifying both familiar and novel threats in live network traffic.

---

## ✨ Key Features

- **Real-time network traffic capture** — captures and processes live network packets using Npcap
- **Dual-layer ML detection** — Random Forest for known attacks + Autoencoder for anomaly detection
- **Preprocessing pipeline** — automated feature extraction and data transformation
- **Web-based dashboard** — Flask-powered interface for live monitoring at `http://localhost:5000`
- **Audit logging** — detailed logs of all network activity and detection results
- **Security hardened** — protected against XSS, SQL Injection, with role-based access control

---

## 📁 Repository Structure

```
Real-Time-Intrusion-Detection-System/
│
├── application.py                        # Main Flask application entry point
├── input_logs.csv                        # Sample input network logs
├── IDS_Audit_Log.csv                     # Audit log of detection results
├── requirements.txt                      # Python dependencies
├── PROJECT_DESCRIPTION.txt               # Detailed project documentation
├── quotation.html                        # HTML template
├── test_models.py                        # Model testing script
├── test_models_simple.py                 # Simplified model tests
├── test_concise.py                       # Concise test suite
└── .venv/                                # Python virtual environment
```

---

## 🏗️ System Architecture

The system is built across four layers:

**1. Data Collection Layer**
- Captures live network packets using Npcap
- Extracts flow-level features from raw packet data

**2. Preprocessing Layer**
- Cleans and transforms raw network data
- Applies a saved preprocessing pipeline (`preprocess_pipeline_AE_39ft.save`)

**3. Machine Learning Layer**
- **Random Forest** (Supervised) — trained on CICIDS 2018 & SCVIC-APT datasets to classify known attack patterns
- **Autoencoder** (Unsupervised) — detects anomalies by reconstructing input and flagging deviations from normal behavior (`autoencoder_39ft.hdf5`)

**4. Web Application Layer**
- Built with Flask
- Displays real-time network flow overview and per-flow drill-down details

---

## 🔐 Security Layers Implemented

- Network traffic monitoring and real-time packet analysis
- Feature extraction for enhanced detection accuracy
- Supervised attack classification (known threats)
- Unsupervised anomaly detection (unknown/zero-day threats)
- Data encryption for secure storage and transmission
- Role-based access control
- Detailed audit logging for forensic analysis
- Web app protection against XSS and SQL Injection

---

## 🧰 Tools & Libraries

| Tool / Library | Purpose |
|----------------|---------|
| Python 3.9 | Core language |
| Flask | Web application framework |
| scikit-learn | Random Forest model |
| TensorFlow / Keras | Autoencoder model |
| Pandas & NumPy | Data manipulation and preprocessing |
| Matplotlib & Seaborn | Data visualization |
| Npcap | Live network packet capture |
| h5py | Saving and loading Autoencoder model |

---

## 🚀 How to Run

1. **Clone the repository**
   ```bash
   git clone https://github.com/Rishabh2170/Real-Time-Intrusion-Detection-System.git
   cd Real-Time-Intrusion-Detection-System
   ```

2. **Install Npcap**  
   Download and install from [npcap.com](https://npcap.com) (required for packet capture)

3. **Set up virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate      # On Windows: .venv\Scripts\activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the application**
   ```bash
   python application.py
   ```

6. **Open the dashboard**  
   Visit `http://localhost:5000` in your browser

---

## 🤖 ML Models Used

**Random Forest (Supervised)**
- Trained on CICIDS 2018 & SCVIC-APT datasets
- Classifies network flows into known attack categories
- High accuracy on labeled threat patterns

**Autoencoder (Unsupervised)**
- Learns the pattern of normal network traffic
- Flags flows that deviate significantly as anomalies
- Effective against unknown and zero-day attacks

---

## 📊 Datasets

| Dataset | Purpose |
|---------|---------|
| CICIDS 2018 | Training the Random Forest on known attack types |
| SCVIC-APT | Advanced Persistent Threat detection |

---

## 🔮 Future Enhancements

- Add support for additional network security datasets
- Implement more advanced anomaly detection algorithms (e.g. Isolation Forest, LSTM)
- Enhance the web dashboard with richer visualizations and alerting
- Add email/SMS notifications for critical threat detections

---

## 👤 Author

**Rishabh**  
GitHub: [@Rishabh2170](https://github.com/Rishabh2170)
