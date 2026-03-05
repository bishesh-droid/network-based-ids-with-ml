# Network-based IDS with Machine Learning

A Network-based Intrusion Detection System (NIDS) that uses a Random Forest classifier to detect anomalous network traffic in real time or from PCAP files.  Unlike signature-based systems, it learns what normal traffic looks like and flags statistical deviations — making it effective against novel/unknown attack patterns.

---

## Features

- **Live capture & PCAP analysis** — sniffs a network interface with Scapy or reads an offline `.pcap` file.
- **13-feature vector extraction** — packet length, TTL, protocol flags, ports, IP header fields (ihl, ToS, fragment offset), and more.
- **Random Forest classifier** — pre-trained model auto-loaded on startup; a balanced dummy model is trained and saved automatically if no model file is present.
- **Threat classification** — anomalous packets are further categorised as: SYN Flood, Fragmentation Attack, Suspicious Port, Anomalous Payload, or generic Anomalous Traffic.
- **Session statistics** — tracks total packets, anomaly count/rate, and per-protocol / per-threat-type breakdowns; summary printed at session end.
- **Versioned model persistence** — the pickle file stores a `version` tag; any schema change triggers automatic retraining so stale models are never silently used.
- **Structured logging** — separate file (DEBUG+) and console (INFO+) handlers; no duplicate-handler bugs.
- **CLI** — `click`-based interface with `--verbose`, `--interface`, `--pcap`, `--count`, `--model-path`, and `--log-file` options.

---

## Project Structure

```
.
├── ml_ids/
│   ├── __init__.py     # Package init
│   ├── cli.py          # Click-based command-line interface
│   ├── config.py       # Central config (interface, paths, model version, threshold)
│   ├── detector.py     # Core engine: PacketStats, MLIntrusionDetector
│   ├── logger.py       # Logger setup (duplicate-handler-safe)
│   └── model.py        # Feature extraction, ThreatType enum, model train/load
├── tests/
│   ├── __init__.py
│   ├── test_detector.py  # 20 unit tests covering all major components
│   └── test_main.py
├── conceptual_analysis.txt
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Prerequisites

- Python 3.8+
- `libpcap` (Linux/macOS) or Npcap (Windows) for live capture:
  - **Debian/Ubuntu:** `sudo apt-get install libpcap-dev`
  - **Windows:** install Npcap from [nmap.org/npcap/](https://nmap.org/npcap/)

---

## Installation

```bash
git clone https://github.com/your-username/network-based-ids-with-ml.git
cd network-based-ids-with-ml

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## Usage

Live capture requires root / administrator privileges.

```bash
# Live monitoring on the default interface (eth0)
sudo python -m ml_ids.cli

# Specific interface
sudo python -m ml_ids.cli -i wlan0

# Analyse a PCAP file (no root needed)
python -m ml_ids.cli -p /path/to/capture.pcap

# Process only 500 packets then print a session summary
sudo python -m ml_ids.cli -c 500

# Enable DEBUG console output
sudo python -m ml_ids.cli -v

# Custom model and log paths
sudo python -m ml_ids.cli -m /opt/ids/model.pkl -l /var/log/ids.log

# Stop live monitoring
# Press Ctrl+C — a session summary is printed before exit
```

### CLI options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | `eth0` | Network interface for live sniffing |
| `--pcap` | `-p` | — | PCAP file to analyse (skips live capture) |
| `--count` | `-c` | `0` | Max packets (0 = unlimited) |
| `--model-path` | `-m` | `ml_model.pkl` | Path to pickled ML model |
| `--log-file` | `-l` | `logs/ml_ids.log` | Destination log file |
| `--verbose` | `-v` | off | Show DEBUG messages on the console |

---

## How It Works

1. **Feature extraction** (`model.extract_features`) — each IP packet is reduced to a 13-element numerical vector.
2. **ML inference** — the `RandomForestClassifier` assigns a binary label: `0` (Normal) or `1` (Attack).
3. **Threat classification** (`model.classify_threat`) — heuristic post-processing on the same feature vector maps anomalous packets to a human-readable threat category.
4. **Statistics** — `PacketStats` accumulates counts per protocol and per threat type, reporting at session end.

### Feature vector (13 elements)

| Index | Feature | Notes |
|-------|---------|-------|
| 0 | Packet length | bytes |
| 1 | IP TTL | |
| 2 | Is TCP | 0/1 |
| 3 | Is UDP | 0/1 |
| 4 | Is ICMP | 0/1 |
| 5 | Has Raw payload | 0/1 |
| 6 | TCP flags sum | SYN=2, ACK=16, … |
| 7 | Source port | 0 for non-TCP/UDP |
| 8 | Destination port | 0 for non-TCP/UDP |
| 9 | IP flags field | |
| 10 | IP fragment offset | |
| 11 | IP header length (ihl) | in 4-byte words |
| 12 | IP ToS / DSCP byte | |

---

## Testing

```bash
python -m unittest discover tests -v
```

21 tests covering feature extraction, model load/versioning, threat classification, packet processing, statistics tracking, and error handling.

---

## Configuration

Edit `ml_ids/config.py` to change defaults without touching the CLI flags:

```python
NETWORK_INTERFACE = "eth0"      # Default sniffing interface
MODEL_PATH        = "ml_model.pkl"
LOG_FILE          = "logs/ml_ids.log"
MODEL_VERSION     = "1.1"       # Bump to force model retraining on next start
ANOMALY_THRESHOLD = 0.5         # Reserved for probability-threshold mode
```

---

## Ethical Considerations

- **Authorisation** — only monitor networks you own or have explicit written permission to analyse.
- **Privacy** — captured traffic may contain credentials and personal data; handle logs accordingly.
- **Educational purpose** — the bundled dummy model is a demonstration tool. Do not rely on it for production security decisions.

---

## License

MIT
