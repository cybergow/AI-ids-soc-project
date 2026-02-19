# AI-Based Intrusion Detection System & SOC Platform

## Project Overview

This project is a hybrid **Intrusion Detection System (IDS)** and **Security Operations Center (SOC)** platform that combines traditional signature-based detection with advanced AI/ML capabilities. It provides real-time monitoring of both network traffic and system command activities, offering a comprehensive defense against modern cyber threats.

The system utilizes a multi-model ensemble (Isolation Forest, Random Forest, Graph Neural Networks) to detect network anomalies and a hybrid Regex+AI engine to identify malicious command-line execution.

![Architecture Diagram](https://gitdiagram.com/api/diagram?url=https://github.com/iamgi/AI-ids-soc-project/blob/main/README.md)
*(Note: Visual diagram requires hosting this README on GitHub with the correct link structure)*

## Key Features

*   **Real-time Network Monitoring**: Captures and analyzes network flows using Scapy.
*   **AI-Powered Detection**:
    *   **Isolation Forest**: Unsupervised anomaly detection.
    *   **Random Forest**: Supervised attack classification.
    *   **Graph Neural Network (GNN)**: Spatial relationship analysis of network flows.
*   **Hybrid Command Monitoring**:
    *   **Regex Engine**: Detects known malicious patterns (47+ signatures).
    *   **AI Model**: Analyzes command intent using natural language processing.
*   **Interactive Dashboard**: Real-time visualization of alerts, metrics, and system status via WebSockets.
*   **Database Integration**: Stores all alerts and flow data in SQLite for historical analysis.

## System Architecture

```mermaid
graph TD
    subgraph "Data Collection Layer"
        NC[Network Capture (Scapy)]
        CM[Command Monitor]
    end

    subgraph "Analysis & Detection Layer (Backend)"
        BS[Flask Backend Server]
        ME[ML Ensemble Engine]
        HD[Hybrid Command Detector]
        DB[(SQLite Database)]
        
        NC --> BS
        CM --> BS
        BS --> ME
        BS --> HD
        ME --> DB
        HD --> DB
    end

    subgraph "Visualization Layer (Frontend)"
        D[Real-time Dashboard]
        WS[WebSocket Stream]
        
        BS --> WS
        WS --> D
        DB -.-> D
    end
    
    subgraph "ML Models"
        IF[Isolation Forest]
        RF[Random Forest]
        GNN[Graph Neural Network]
        
        ME --> IF
        ME --> RF
        ME --> GNN
    end
```

## Setup & Installation

### Prerequisites
*   Python 3.8+
*   Node.js (optional, for advanced frontend dev)
*   Wireshark/Npcap (for Windows packet capture)

### Installation Steps

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/AI-ids-soc-project.git
    cd AI-ids-soc-project
    ```

2.  **Create Virtual Environment**
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Linux/Mac
    .venv\Scripts\activate     # Windows
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: GNN support requires `torch` and `torch_geometric`)*

4.  **Initialize Database**
    The database `alerts.db` will be automatically created on the first run.

## Usage

### 1. Start the Backend Server
This starts the web server, API, and detection engine.
```bash
python backend/detector_server.py
```

### 2. Start Flow Capture (Optional)
If you want to capture live network traffic from your interface:
```bash
python backend/flow_extractor.py
```

### 3. Access the Dashboard
Open your browser and navigate to:
`http://localhost:5000`

### 4. Test the System
Send simulated attacks to verify detection:
```bash
python send_real_attacks.py
```

## Project Structure

*   `backend/` - Core Python server and detection logic.
    *   `detector_server.py` - Main entry point.
    *   `flow_model_ensemble.py` - Orchestrates ML models.
    *   `cmd_detector_hybrid.py` - Command line monitoring logic.
    *   `gnn_flow_model.py` - Graph Neural Network implementation.
*   `frontend/` - HTML/JS dashboard files.
*   `training_data/` - Datasets for model training.

## Contributors
*   **Project Lead**: [Your Name]
*   **AI-IDS SOC Team**

## License
MIT License
