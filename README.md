# VLAN Hunter - Reliable VLAN Discovery Tool for Linux
**VLAN Hunter** is a high-performance network diagnostic utility designed to identify active PPPoE and IPoE services across 802.1Q virtual segments. By utilizing raw frame injection and asynchronous sniffing, it maps upstream ISP infrastructure and categorizes services such as **Internet, IPTV, VoIP, and Management**.

## Description
The utility is engineered to bypass hardware-level VLAN filtering, allowing administrators to verify service provisioning and detect hidden tags without modifying the host's persistent global configuration. It provides a structured, non-persistent assessment of network segmentation, identifying service types by correlating `Service-Name` (PPPoE) and `Vendor-Class-ID` (DHCP) to specific VLAN tags.

## Requirements
### System
- Linux
- Root privileges
- iproute2
- ethtool
- coreutils
- ncurses

### Python
- Python 3
- Scapy

### Notes
- The `--auto` flag can automatically install missing dependencies
- Supported package managers: apt, dnf, yum, pacman, zypper, apk

## Deployment & Execution
### Remote Execution
Execute the engine directly from the source without a local footprint:

```bash
curl -sSL https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash
```

### Local Execution
```bash
# Download and prepare the script
curl -O https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh
chmod +x VLAN_Hunter.sh

# Execute with root privileges
sudo ./VLAN_Hunter.sh
```

### Command Line Arguments
| Flag | Parameter | Description | Example |
| :--- | :--- | :--- | :--- |
| **`-i`** | `--interface` | Defines the target NIC (skips selection menu). | `-i eth0` |
| **`-v`** | `--vlan` | Sets a specific VLAN or range (Default: 0-4095). | `-v 10-100` |
| **`-a`** | `--auto` | Automatically resolves system dependencies. | `-a` |
| | `--accept` | Bypasses interactive legal authorization prompts. | `--accept` |

**Local Usage Example:**
```bash
sudo ./VLAN_Hunter.sh -i eth1 -v 10-500 -a --accept
```

**Remote Usage Example:**
```bash
curl -sSL [URL] | sudo bash -s -- -i eth1 -v 10-500 -a --accept
```

## Technical Architecture
VLAN Hunter utilizes a streamlined operational sequence to maximize discovery depth while maintaining a minimal system footprint:

* **Ephemeral Workspace:** Initializes a temporary environment in volatile memory (`/run` or `/tmp`) to ensure no persistent logs or artifacts remain on the host filesystem.
* **Interface Optimization:** Scales MTU to **1512** and disables **RX-VLAN offloading**, allowing the sniffer to capture raw tagged frames without hardware interference.
* **Hybrid Discovery Logic:** Combines a baseline untagged DHCP broadcast with high-speed concurrent PPPoE probes, supported by an asynchronous listener to capture late-arriving responses.
* **State Restoration:** Automatically reverts MTU/RX settings and purges the workspace upon completion or interruption (`SIGINT`).

## Disclaimer
> [!CAUTION]
> **Assumption of Risk**  
> The user assumes all risks and responsibilities associated with the installation, use, and results of this software, including, without limitation, any impact on systems, networks, hardware, or data, as well as any legal or regulatory consequences arising from its use.
>
> **Limitation of Liability**  
> To the fullest extent permitted by applicable law, in no event shall the authors or copyright holders be liable for any claims, damages, or other liabilities, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software, or the use of or inability to use the software.
>
> **Authorized Use**  
> This software is intended solely for lawful and authorized administrative or testing purposes. The user is responsible for ensuring that all use complies with applicable laws, regulations, and any relevant service or contractual obligations.


> [!IMPORTANT]
> This software is provided “AS IS”, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. The entire risk as to the quality and performance of the software is with the user.

**Author:** sussyflow  
**Copyright:** © 2026 sussyflow  
**License:** GNU General Public License v3.0
