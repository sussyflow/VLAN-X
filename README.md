# VLAN Hunter

### Overview
VLAN Hunter is a non-invasive diagnostic engine designed for Service Providers and Network Administrators. It provides a structured view of upstream service availability by enumerating 802.1Q tags and analyzing broadcast responses across the full VLAN ID spectrum (0-4095).

### Runtime Isolation Logic
To ensure host system stability and maintain a "zero-footprint" profile, the utility executes the following automated workflow:

1.  **Dependency Validation:** Performs a pre-flight check for `python3`, `curl`, `ethtool`, and `mktemp`.
2.  **Virtualization:** Initializes an ephemeral Python 3 virtual environment (`venv`) within a randomized `/tmp` directory.
3.  **NIC Configuration:** Temporarily disables hardware-level VLAN offloading (`rxvlan`) via `ethtool` to allow the Scapy-driven engine to inspect raw 802.1Q headers.
4.  **Parallel Analysis:** Dispatches multi-threaded probes (PADI and DHCP Discover) and initializes an asynchronous sniffer to capture and correlate upstream responses.
5.  **Restoration:** Re-enables original hardware offloading settings and recursively purges the temporary workspace.

### Technical Specifications
* **Injection Engine:** Scapy-based raw frame construction.
* **Concurrency:** Multi-threaded worker pool with configurable `CONCURRENCY_FACTOR`.
* **Traffic Capture:** Asynchronous sniffing with 802.1Q tag persistence.
* **Service Classification:** Heuristic mapping of Service-Names and Vendor-Class-IDs.

### Deployment and Execution
The utility is optimized for direct remote deployment, bypasssing the need for manual repository management:

```bash
curl -sSL https://github.com/sussyflow/VLAN-X/blob/main/VLAN_Hunter.sh | sudo bash
```

### Security and Compliance
VLAN Hunter is a "live-run" utility. It does not modify system configuration files, install persistent binary packages, or alter the global Python environment. All operations are confined to memory and ephemeral directories.

### Disclaimer
This utility is intended for authorized network diagnostics. It performs low-level operations that are visible to network monitoring systems and upstream providers. Use this tool only on infrastructure where you have explicit authority to perform diagnostic assessments.

**Author:** sussyflow  
**License:** GNU General Public License v3.0
