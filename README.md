# VLAN Hunter - Reliable VLAN Discovery Tool for Linux

**VLAN Hunter** is a network discovery utility for Linux that identifies active VLANs and detects services such as **Internet, IPTV, VoIP, and Management** networks. Using a combination of active probing and passive monitoring, it helps reveal how services are delivered across 802.1Q VLANs.

## Description

VLAN Hunter is designed for VLAN discovery, service validation, and network troubleshooting. It can actively probe VLANs using PPPoE, DHCP, and IGMP discovery traffic, or passively monitor tagged traffic already present on the network.

The tool correlates discovered services with their VLAN IDs, helping administrators and technicians quickly identify service VLAN assignments without making permanent changes to the host system. Any temporary interface optimizations performed during a scan are automatically restored when the program exits.

## Requirements

* Linux (with root privileges)
* Python 3
* Scapy

> Missing dependencies can be installed automatically using the `-a` (`--auto`) option.

## Installation & Usage

### Run Directly

```bash
curl -sSL https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash
```

### Download & Run

```bash
curl -O https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh
chmod +x VLAN_Hunter.sh
sudo ./VLAN_Hunter.sh
```

## Command Line Arguments

| Flag | Long Parameter | Description                                 | Example                |
| :--- | :------------- | :------------------------------------------ | :--------------------- |
| `-i` | `--interface`  | Select the network interface.               | `-i eth0`              |
| `-m` | `--mac`        | Use a custom source MAC address.            | `-m 02:11:22:33:44:55` |
| `-v` | `--vlan`       | Scan a single VLAN or VLAN range.           | `-v 10-100`            |
| `-a` | `--auto`       | Automatically install missing dependencies. | `-a`                   |
|      | `--pppoe`      | Enable PPPoE discovery.                     | `--pppoe`              |
|      | `--dhcp`       | Enable DHCP discovery.                      | `--dhcp`               |
|      | `--igmp`       | Enable IGMP discovery.                      | `--igmp`               |
|      | `--active`     | Use active discovery mode.                  | `--active`             |
|      | `--passive`    | Use passive monitoring mode.                | `--passive`            |
|      | `--accept`     | Skip the Terms of Use prompt.               | `--accept`             |

## Examples

```bash
# Active PPPoE discovery
sudo ./VLAN_Hunter.sh -i eth0 --pppoe -v 1-500 --accept
```

```bash
# DHCP and IGMP discovery
sudo ./VLAN_Hunter.sh -i eth0 --dhcp --igmp -v 100-500 --accept
```

```bash
# Passive monitoring
sudo ./VLAN_Hunter.sh -i eth0 --passive --accept
```

```bash
# Custom MAC address
sudo ./VLAN_Hunter.sh -i eth0 -m 02:11:22:33:44:55 --pppoe --accept
```

```bash
# Automated scan with dependency installation
sudo ./VLAN_Hunter.sh -i eth0 --pppoe --dhcp -v 10-500 -a --accept
```

```bash
# Remote execution
curl -sSL https://raw.githubusercontent.com/sussyflow/VLAN-X/main/VLAN_Hunter.sh | sudo bash -s -- -i eth0 --pppoe -v 10-500 --accept
```

## Example Output

```text
[12:41:03] VLAN probing started (ACTIVE)

DISCOVERY RESULTS
----------------------------------------------------------------------
VLAN   PROTO    TYPE       IDENTITY                 MAC ADDRESS
----------------------------------------------------------------------
35     PPPoE    INTERNET   INTERNET                 aa:bb:cc:dd:ee:ff
838    DHCP     IPTV       VCI: IPTV-STB            11:22:33:44:55:66
840    DHCP     MGMT       VCI: TR069               22:33:44:55:66:77
----------------------------------------------------------------------
```

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
