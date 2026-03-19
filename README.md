# VLAN Hunter

**VLAN Hunter** is a high-performance VLAN discovery tool for Linux that detects active PPPoE and IPoE (DHCP) services by injecting raw discovery frames.

It is designed for fast, parallel scanning of VLAN ranges with minimal system impact using an isolated runtime environment.

---

## Features

* Detects **PPPoE (PADO)** responses
* Detects **IPoE / DHCP servers**
* Supports **full VLAN range scanning (0–4095)**
* Parallel packet injection for speed
* Automatic interface selection
* Optional **MAC address spoofing**
* Clean, formatted output with service classification
* Uses a **temporary virtual environment** (no global installs)

---

## Requirements

* Linux (tested on modern distributions)
* Root privileges
* Python 3
* Network interface capable of raw packet injection

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/vlan-hunter.git
cd vlan-hunter
chmod +x vlan-hunter.sh
```

---

## Usage

Run the script as root:

```bash
sudo ./vlan-hunter.sh
```

---

### Options

You can pass arguments directly:

```bash
sudo ./vlan-hunter.sh -i eth0 -v 100-200
```

#### Available flags:

* `-i` → नेटवर्क interface (e.g., `eth0`)
* `-v` → VLAN ID or range (e.g., `100` or `10-200`)
* `-m` → Spoof MAC address (e.g., `00:11:22:33:44:55`)
* `-t` → Timeout in seconds for response listening

---

## Example

```bash
sudo ./vlan-hunter.sh -i eth0 -v 0-500 -t 5
```

---

## Output

The tool will display:

* VLAN ID
* Protocol (PPPoE / DHCP)
* Service type (INTERNET / IPTV / VOIP)
* Identity (e.g., ISP name or DHCP info)
* MAC address of responding device

---

## How It Works

* Sends **PPPoE discovery (PADI)** frames across VLANs
* Sends **DHCP discover packets** for IPoE detection
* Listens for:

  * PPPoE PADO responses
  * DHCP offers
* Correlates responses with VLAN IDs

---

## Disclaimer

This tool performs low-level network operations and may be detected as abnormal or intrusive by network infrastructure.

* Use **only on networks you own or have explicit permission to test**
* Unauthorized use may violate laws or ISP policies
* The author is **not responsible** for any misuse, damage, or service disruption caused by this tool

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Author

Niggesh

---

## Notes

* Some networks may rate-limit or block discovery packets
* Results depend on ISP configuration and response behavior
* Running in virtualized environments may affect accuracy

---
