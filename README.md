# VLAN Hunter - Reliable VLAN Discovery Tool for Linux

**VLAN Hunter** is a high-performance network diagnostic utility designed to identify active PPPoE and IPoE services across 802.1Q virtual segments. By combining raw frame injection with asynchronous sniffing, it rapidly maps upstream ISP infrastructure and classifies discovered networks into distinct service tags: **Internet, IPTV, VoIP, and Management**.

## Description

The utility is engineered to bypass hardware-level VLAN filtering, enabling administrators to verify service provisioning and detect hidden tags without modifying permanent host configurations. It provides a non-persistent assessment of network segmentation, correlating `Service-Name` (PPPoE) and `Vendor-Class-ID` (DHCP) payloads directly to their respective VLAN IDs.

## Requirements

### System Dependencies

* **OS:** Linux (Requires `root` privileges)
* **Utilities:** `iproute2`, `ethtool`, `coreutils`, `ncurses`

### Python Environment

* Python 3
* Scapy

## Deployment & Execution

### Remote Execution

Run the engine directly from the remote repository without leaving a local footprint:

```bash
curl -sSL https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash

```

### Local Execution

```bash
# Download the wrapper script
curl -O https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh
chmod +x VLAN_Hunter.sh

# Run locally
sudo ./VLAN_Hunter.sh

```

### Command Line Arguments

| Flag | Long Parameter | Description | Syntax Example |
| --- | --- | --- | --- |
| **`-i`** | `--interface` | Defines the target NIC directly (skips interactive menu). | `-i eth0` |
| **`-v`** | `--vlan` | Sets a specific VLAN or hyphenated range (Default: 0-4095). | `-v 10-100` |
| **`-a`** | `--auto` | Automatically installs missing system and python packages. | `-a` |
|  | `--accept` | Bypasses interactive legal authorization prompts. | `--accept` |

#### Parameterized Invocation Examples:

```bash
# Local:
sudo ./VLAN_Hunter.sh -i eth1 -v 10-500 -a --accept
```
```
# Remote:
curl -sSL [URL] | sudo bash -s -- -i eth1 -v 10-500 -a --accept
```

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
