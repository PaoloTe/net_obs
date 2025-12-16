# Net Obs - Network Performance Analysis

**Net Obs** is a containerized Client-Server framework designed to analyze network performance with high granularity. It goes beyond standard speed tests by comparing **Round-Trip Time (RTT)** across multiple layers of the networking stack (Application vs. Kernel vs. Wire) and logging detailed metrics into a persistent MySQL database.

---

##  Project Objectives

The primary goal of this script is to **isolate and quantify latency overhead** introduced by the software stack. By capturing timestamps at three distinct levels, **Net Obs** aims to:

1.  **Measure Processing Delay:** Determine exactly how much latency is added by the OS kernel and the Python interpreter compared to the raw network transmission.
2.  **Benchmark Performance:** Provide reliable throughput and jitter metrics.
3.  **Identify Bottlenecks:** Distinguish between actual network issues  and application performance issues.


---

##  System Architecture

The project runs on a **Dockerized** environment with the following components:

1.  **Client Container**: Runs Python automation scripts (`Main.py`, `RTT_Client.py`). It is equipped with `tshark`, `scapy`, and `iperf3` for traffic generation and packet sniffing.
2.  **Server Container**: Acts as the target endpoint. It runs `iperf3` servers in the background and listens for UDP echo requests.
3.  **Database**: A **MySQL 8.0** instance stores all performance metrics (`network_performance` DB).
4.  **Visualization**: **Grafana** and **PhpMyAdmin** are included for data analysis and management.

---

##  Project Modules

### 1. General Network Conditions (`Main.py`)
A "sanity check" script that evaluates the overall link quality.
* **Throughput**: Measures Upload and Download speeds using `iperf3` (JSON output analysis).
* **Latency**: Measures basic ICMP latency and Jitter using system `ping`.
* **Connectivity**: Detects **Public IP** (via `ipify` API) and **Private IP** (via DNS socket).
* **Storage**: Logs results to the `udp_metrics` table.

### 2. Multi-Layer RTT Analysis (`RTT_Client.py` / `RTT_Server.py`)
This is the core research module. It sends numbered UDP packets and attempts to measure RTT from **three simultaneous viewpoints** to isolate OS/Driver overhead:

1.  **Socket Level (App Layer)**:
    * Uses standard Python `time.time()` before send and after receive.
    * *Includes Python interpreter overhead and OS buffering.*
2.  **Scapy Sniffer (Kernel/Driver Layer)**:
    * Uses a background thread to sniff packets via `AF_PACKET`.
    * Matches packet payloads to calculate timestamps closer to the kernel.
3.  **PyShark Sniffer (Wire Layer)**:
    * Wraps `tshark` (Wireshark CLI) to capture packets directly from the interface.
    * Provides the highest fidelity timestamps (`sniff_timestamp`).

---

##  Prerequisites & Installation

### Option A: Docker (Recommended)
This ensures all dependencies (`tshark`, `scapy`, privileges) are handled automatically.

1.  **Clone/Copy** the project files into a folder.
2.  **Start the environment**:
    ```bash
    docker compose up --build
    ```
    * This builds the `ubuntu:22.04` image, installs Wireshark/Python dependencies, and starts the DB.
    * The `server` container automatically starts `iperf3` listeners on ports 5092/5093.

### Option B: Local Execution (Linux)
If running outside Docker, you need:
* Python 3.8+
* System tools: `iperf3`, `tshark`, `ping`.
* Python libs:
    ```bash
    pip install mysql-connector-python scapy pyshark requests numpy
    ```

---

###  Usage Guide

All commands should be run inside the **Client** and **Server** container:

**1. Access the Client Shell**
```bash
docker exec -it client bash
```
**2. Access the Server Shell**
```bash
docker exec -it server bash
```
**3. Run Main.py in the Client Shell**
```bash
pyton3 Main.py
```
**4. Run RTT.Server.py in the Server Shell**
```bash
pyton3 RTT.Server.py
```

**5. Run RTT.Client.py in the Client Shell**
```bash
pyton3 RTT.Client.py
```