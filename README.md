# VLAN Hunter

### Description
VLAN Hunter is a high-performance network diagnostic engine designed to identify active PPPoE and IPoE services across 802.1Q virtual segments. It utilizes raw frame injection and asynchronous sniffing to map upstream ISP infrastructure with precision, categorized by service type (Internet, IPTV, VoIP, or Management).

### Purpose
The utility provides a structured, non-persistent assessment of network segmentation. It is engineered to bypass hardware-level VLAN filtering, allowing administrators to verify service provisioning and detect hidden 802.1Q tags without modifying the host's global configuration or persistent file system.

### Deployment and Arguments
The script is optimized for direct remote execution via a single command:

```bash
curl -sSL https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash
```

**CLI Reference:**
| Flag | Long Form | Description | Example |
| :--- | :--- | :--- | :--- |
| `-i` | `--interface` | Target physical network interface | `-i eth0` |
| `-v` | `--vlan` | Specific ID or range to investigate | `-v 10-500` |

### Behavior and Runtime Logic
To maintain a "zero-footprint" profile, the utility follows a strict execution lifecycle:
1. **Pre-flight Check:** Validates presence of `python3`, `curl`, `ethtool`, `tput`, and `mktemp`.
2. **Isolation:** Initializes an ephemeral Python `venv` within a randomized `/tmp` directory.
3. **Hardware Toggle:** Disables NIC `rxvlan` offloading via `ethtool` to permit raw tag inspection.
4. **Injection:** Construct and dispatches multi-threaded PADI and DHCP Discover probes.
5. **Correlation:** Sniffs for upstream responses and heuristic-maps Service-Names and Vendor-IDs.
6. **Restoration:** Re-enables hardware settings and recursively purges the temporary workspace.

### Disclaimer and License
**Disclaimer:** This utility is intended for authorized diagnostics only. Operations are performed via raw sockets and are visible to upstream monitoring systems. Use only where you have explicit authority to perform testing.

**Author:** sussyflow  
**License:** GNU General Public License v3.0
