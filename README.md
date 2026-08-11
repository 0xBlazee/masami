# masami

A high-density, multi-layered packet parsing and network telemetry system built for Unix environments. This project pipelines low-level network intercepts directly into parallel, asynchronous analysis frameworks to track protocol structures in real time.

---

## 🛠️ Architecture Stack

- **sniffer (C++ Core Interceptor):** Interrogates raw network sockets to grab link-layer frames straight from the network card. It forces the physical interface into promiscuous mode via `libpcap` to capture incoming and outgoing bytes before the operating system standardizes them.
- **processor (Go Core Aggregator):** Ingests streaming metrics concurrently over localized worker channels (`goroutines`) to handle massive frame volumes without memory starvation.
- **analyzer (Python Behavioral Script):** Implements asynchronous execution loops via `asyncio` and `ProcessPoolExecutor` to calculate cryptographic frame signatures and trace payload data text patterns.
- **manifest (JSON Structural Interface):** Defines the exact serialization layout schemas shared between the multi-language compiled binaries.

---

## 📂 Repository Blueprint

```text
masami/
├── manifest     # JSON protocol routing definitions
├── sniffer      # C++ Link and transport layer frame interceptor
├── processor    # Go parallel data thread stream aggregator
├── analyzer     # Python behavioral payload parsing script
├── dashboard    # Bash real-time multiplexed panel orchestrator
├── blacklist    # Plaintext target security filtering rules
├── storage      # Local persistent cache and disk sync guidelines
├── .gitignore   # Local file compilation exclusion blocks
└── LICENSE      # MIT open source usage permission protocol
```

---

## ⚡ Deployment and System Orchestration

### 1. Synchronize Development Header Toolchains
Before running the deployment scripts, load the required architecture developer tools and compiler libraries onto your system:
```bash
sudo apt update && sudo apt install -y build-essential libpcap-dev golang tmux python3
```

### 2. Multi-Language Compilation Phase
Compile the low-level C++ network frame interceptor using level-3 runtime performance adjustments (`-O3`), and assemble the Go asynchronous stream processor binary:
```bash
g++ -O3 -std=c++17 sniffer.cpp -o sniffer -lpcap
go build -o processor processor.go
chmod +x dashboard
chmod +x analyzer
```

### 3. Execution Pipeline Setup
Locate your targeted system network device interface identifier string via `ip link show` (e.g., `eth0` or `wlan0`), and pipe your runtime layers directly together to track data:
```bash
sudo ./sniffer eth0 | ./processor
```
To run the deep-packet inspection and security analytics tracking layers simultaneously:
```bash
sudo ./sniffer eth0 | python3 analyzer
```

---

## 📊 Structural Serialization Interface Schema

The system uses standard input/output redirection channels to pass metrics directly out of the memory buffer using this exact JSON layout structure:

```json
{
  "id": "uint64",
  "time": "int64_epoch_milliseconds",
  "src": "string_ip_address",
  "dst": "string_ip_address",
  "ttl": "int",
  "version": "int",
  "proto": "string_tcp_or_udp",
  "sport": "int_port_source",
  "dport": "int_port_destination",
  "flags": "string_tcp_control_flags",
  "hex": "string_raw_hexadecimal_stream",
  "ascii": "string_extracted_application_text"
}
```
