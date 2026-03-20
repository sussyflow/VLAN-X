# VLAN Hunter

**VLAN Hunter** is a high-performance network diagnostic utility for Linux. It is engineered to scan network interfaces and identify active internet or multimedia services partitioned across virtual segments (VLANs) by using a parallel, non-persistent approach.

## Key Capabilities

The utility provides comprehensive service discovery by identifying multiple broadcast protocols simultaneously.

* **Environmental Isolation:** Operates within a temporary, isolated environment that is purged after execution to ensure zero impact on the host system.
* **Hardware Management:** Automatically manages system network settings to detect service tags that are often hidden from standard diagnostic tools.
* **Intelligent Mapping:** Categorizes detected services into logical groups such as Internet, Video, Voice, or Management.
* **High-Speed Assessment:** Employs multi-threaded processing to complete large-scale scans across thousands of segments rapidly.

## Requirements

Operation requires a modern Linux distribution and administrative (root) privileges for low-level network access. The script depends on standard system utilities: `python3`, `curl`, and `ethtool`.

## Getting Started

Grant the script execution permissions and launch it from your terminal:

```bash
chmod +x vlan_hunter.sh
sudo ./vlan_hunter.sh
```

## Usage

VLAN Hunter functions as a guided interactive tool or accepts specific instructions via the command line:

```bash
sudo ./vlan_hunter.sh -i [interface] -v [range]
```

* **Interface Selection (-i):** Defines which network hardware to scan.
* **Segment Range (-v):** Defines the specific segment or range of segments to investigate.

*Note: The system utilizes a fixed 3-second observation window to capture all upstream service responses.*

## Operational Logic

The utility broadcasts discovery requests across the network and listens for responses from upstream providers. It temporarily bypasses hardware filters to observe all incoming traffic tags, correlates the data into a readable report, and restores original hardware settings before exiting.

## Disclaimer

This utility is intended for diagnostic purposes and performs low-level operations visible to network administrators. Use this tool only on infrastructure where you have explicit authority to perform testing.

**Author:** sussyflow  
**License:** GNU General Public License v3.0
