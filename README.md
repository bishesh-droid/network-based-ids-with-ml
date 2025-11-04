# Network-based IDS with Machine Learning

This project implements a conceptual Network-based Intrusion Detection System (NIDS) that leverages machine learning to detect anomalous network traffic. Unlike traditional signature-based IDS, this system aims to identify new and unknown threats by learning patterns of normal network behavior and flagging deviations.

## Features

-   **Packet Sniffing/PCAP Analysis:** Captures live network traffic from a specified interface or reads from a PCAP file using Scapy.
-   **Feature Extraction:** Extracts key numerical features from network packets (e.g., packet length, protocol types, TCP flags, ports).
-   **Machine Learning Inference:** Uses a simplified, pre-trained machine learning model (Decision Tree Classifier) to classify each packet as 'normal' or 'anomalous'.
-   **Anomaly Detection:** Alerts are generated for packets classified as anomalous, providing details about the packet and its extracted features.
-   **Logging:** Logs all detected anomalies and system activities.
-   **Command-Line Interface:** Easy-to-use CLI for starting the IDS and configuring the network interface or PCAP input.

## Project Structure

```
.
├── ml_ids/
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Command-line interface
│   ├── detector.py        # Core logic for packet sniffing, feature extraction, and ML inference
│   ├── model.py           # (Conceptual) ML model definition, training (dummy), and loading
│   ├── logger.py          # Configures logging for the IDS
│   └── config.py          # Configuration for network interface, model path, and logging
├── logs/
│   └── ml_ids.log         # Log file for IDS alerts
├── tests/
│   ├── __init__.py
│   └── test_detector.py   # Unit tests for feature extraction and (mocked) model inference
├── .env.example           # Example environment variables
├── .gitignore
├── conceptual_analysis.txt
├── README.md
└── requirements.txt
```

## Prerequisites

-   Python 3.7+
-   `pip` for installing dependencies
-   **Scapy dependencies:** Scapy often requires `libpcap` (Linux/macOS) or WinPcap/Npcap (Windows). Ensure these are installed on your system.
    -   **Linux:** `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RHEL/CentOS)
    -   **Windows:** Install Npcap (recommended over WinPcap) from [nmap.org/npcap/](https://nmap.org/npcap/)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/ML-based-NIDS.git
    cd ML-based-NIDS
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the ML-based IDS from the project root directory. **Note:** Packet sniffing typically requires root/administrator privileges.

```bash
sudo python -m ml_ids.cli
```

**Examples:**

-   **Start live monitoring on the default interface (eth0):**
    ```bash
    sudo python -m ml_ids.cli
    ```

-   **Monitor a specific interface (e.g., wlan0):**
    ```bash
    sudo python -m ml_ids.cli -i wlan0
    ```

-   **Analyze packets from a PCAP file:**
    ```bash
    python -m ml_ids.cli -p /path/to/your/traffic.pcap
    ```

-   **Process a limited number of packets from live traffic:**
    ```bash
    sudo python -m ml_ids.cli -c 1000
    ```

-   **To stop live monitoring:** Press `Ctrl+C` in the terminal where it is running.

**Monitoring Logs:**
All detected anomalies and activities are logged to `logs/ml_ids.log` and optionally printed to the console.

## Ethical Considerations

-   **Authorization:** Only run this IDS on networks you own or have explicit permission to monitor. Unauthorized network monitoring can be illegal.
-   **Privacy:** Be mindful of the data you are capturing. Network traffic can contain sensitive information.
-   **Educational Purpose:** This tool is for educational and research purposes only. The ML model is a simplified demonstration. It is not a substitute for commercial, production-grade security solutions and should not be relied upon for real-world threat detection.

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.