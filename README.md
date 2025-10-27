## 🔥 Red Team Campaign Simulator

**Red Team Campaign Simulator** is an educational web based cybersecurity platform that allows users to create virtual network environments, assign CVEs mapped to the MITRE ATT&CK framework, and simulate deterministic red team attack campaigns.  
It provides visual representations of attack paths, tracks techniques, and generates detailed Markdown or PDF reports without performing any real network operations.


## Features

### 🎯 Host Management
- Create and manage virtual network hosts  
- Configure IP addresses, operating systems, and open ports  
- Assign vulnerabilities from a CVE database  
- Set business criticality levels (Low, Medium, High, Critical)

### ⚔️ Campaign Simulation
- Deterministic turn based attack modeling  
- Multi phase attack progression (Initial Access → Reconnaissance → Exploitation → Lateral Movement)  
- Reproducible results using random seeds  
- MITRE ATT&CK framework mapping for each attack step  

## Network Visualization
- Interactive graph visualization using Cytoscape.js  
- Real time attack progression display  
- Visual indicators for compromised hosts  
- Network topology and relationship analysis  

## Attack Logging and Reporting
- Real time console style attack logs  
- Detailed timeline of each simulated attack  
- MITRE ATT&CK technique tracking  
- Downloadable Markdown or PDF reports containing:  
  - Executive summaries  
  - Attack timelines  
  - Technique analysis  
  - Remediation recommendations  

## 🧰 Technology Stack

**Backend**
- Flask  
- SQLite  
- NetworkX  

**Frontend**
- Bootstrap 5  
- Cytoscape.js  
- JavaScript  

**Reporting**
- ReportLab  
- Markdown2  

## ⚙️ Installation

### Prerequisites
- Python 3.11 or higher  
- pip installed and available in PATH  

### Setup

## Clone the repository
git clone https://github.com/Talhagurmani/Red_Team_Simulator.git
cd Red_Team_Simulator

##  Create and activate a virtual environment
python -m venv .venv

## Run the application
python main.py


Then open your browser and go to
http://localhost:5000



## Dependencies

The project uses the following Python libraries:

- Flask
- Flask-Cors
- SQLAlchemy
- NetworkX
- NumPy
- Pillow
- Werkzeug
- Markdown2
- ReportLab
- Python-Magic-Bin

## You can install them manually with:

pip install flask flask-cors sqlalchemy networkx numpy pillow werkzeug markdown2 reportlab python-magic-bin


## 🔧 Usage Guide

### 1. Add Virtual Hosts

- Navigate to **Host Management**
- Add a new host with details such as name, IP address, OS, and open ports
- Assign vulnerabilities from the built in CVE database
- Choose a business criticality level

### 2. Create and Run Campaigns

- Go to the **Campaigns** section
- Provide a campaign name and description
- Select target hosts or use random targeting
- Execute the campaign to begin simulation

### 3. View and Export Results

- Observe attack progression in the **Network Visualization** panel
- Review all actions in the **Attack Logs**
- Generate and download a detailed **PDF or Markdown report**


## Screenshots

### Host Management

<img width="1366" height="625" alt="Screenshot (141)" src="https://github.com/user-attachments/assets/90d7e1a3-ae02-4ab6-b5df-d87f028d438d" />

<img width="1344" height="605" alt="Screenshot (140)" src="https://github.com/user-attachments/assets/b77bed4c-f412-4242-b193-bf4b7416a649" />


### Campaign Execution

<img width="1366" height="619" alt="Screenshot (142)" src="https://github.com/user-attachments/assets/0f2d058d-dd1a-48c1-a79d-0bce85cb20a3" />

<img width="1366" height="624" alt="Screenshot (143)" src="https://github.com/user-attachments/assets/c5db9780-5e64-4830-9d34-c68dff7b95e3" />

<img width="1366" height="619" alt="Screenshot (144)" src="https://github.com/user-attachments/assets/be44004f-47ca-4c43-aa05-762e83e546f2" />


### Network Visualization

<img width="1366" height="625" alt="Screenshot (145)" src="https://github.com/user-attachments/assets/b5c9a9b6-938a-4123-8ec2-8aacde5eb72d" />

### Attack logs

<img width="1366" height="621" alt="Screenshot (149)" src="https://github.com/user-attachments/assets/45a50094-1e68-4dc5-9c93-5243a25eace4" />


### Generated Report

<img width="811" height="565" alt="Screenshot (146)" src="https://github.com/user-attachments/assets/5af2c8f3-b57b-4aab-900e-c949fe6507d9" />

<img width="813" height="397" alt="Screenshot (147)" src="https://github.com/user-attachments/assets/7fe7f143-732d-47fd-99fc-b80cf630d32d" />

<img width="726" height="565" alt="Screenshot (148)" src="https://github.com/user-attachments/assets/53f73a01-4e72-49af-80e1-ea19346e3ffe" />


## 🧪 Sample Vulnerabilities

The simulator includes a predefined vulnerability list, including:

- CVE 2021 44228 (Log4Shell)
- CVE 2017 0144 (EternalBlue)
- CVE 2014 0160 (Heartbleed)
- CVE 2019 0708 (BlueKeep)
- CVE 2021 26855 (ProxyLogon)


## 🎯 MITRE ATT&CK Techniques

The simulator maps attacks to MITRE ATT&CK techniques such as:

- T1133 External Remote Services
- T1046 Network Service Scanning
- T1190 Exploit Public Facing Application
- T1021 Remote Services
- T1550 Pass the Hash



## 🎓 Educational Purpose

This tool is designed for **cybersecurity education, research, and red team training**.
It simulates attack logic within a virtual environment and does **not perform real network operations**.

Use it responsibly to learn, teach, and demonstrate safe red team methodologies.


## ⚠️ Disclaimer

Use this simulator responsibly. This project is intended solely for authorized education and training.
Do not use any knowledge or code from this project for unauthorized access to computer systems.



