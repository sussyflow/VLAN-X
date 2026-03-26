# VLAN Hunter

### Description
**VLAN Hunter** is a high-performance network diagnostic engine designed to identify active PPPoE and IPoE services across 802.1Q virtual segments. It utilizes raw frame injection and asynchronous sniffing to map upstream ISP infrastructure, categorized by service type: **Internet, IPTV, VoIP, or Management**.

### Purpose
The utility provides a structured, non-persistent assessment of network segmentation. It is engineered to bypass hardware-level VLAN filtering, allowing administrators to verify service provisioning and detect hidden 802.1Q tags without modifying the host's global configuration.

### Deployment & Direct Execution

**Using curl:**
```bash
curl -sSL https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash
```

**Using wget:**
```bash
wget -qO- https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash
```

**Using fetch:**
```bash
fetch -o - https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash
```

### Technical Lifecycle
* **Isolation:** Initializes an ephemeral Python `venv` in a randomized `/tmp` directory.
* **Offloading:** Disables NIC `rxvlan` via `ethtool` for raw software-layer inspection.
* **Injection:** Dispatches multi-threaded PADI and DHCP Discover probes across the 0–4096 VLAN range.
* **Correlation:** Sniffs for responses to map `Service-Name` and `Vendor-ID` to specific tags.
* **Restoration:** Re-enables hardware settings and purges all temporary artifacts upon exit.

### Disclaimer and License
> [!IMPORTANT]
> **Diagnostic Authorization:** Intended for authorized testing only. Operations are performed via raw sockets and are visible to upstream monitoring systems.

**Author:** sussyflow  
**License:** GNU General Public License v3.0
