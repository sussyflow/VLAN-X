#!/bin/bash

[ "$EUID" -ne 0 ] && echo "[!] ERROR: ROOT REQUIRED" && exit 1
[ ! -w "." ] && echo "[!] ERROR: Current directory is not writable." && exit 1
command -v python3 >/dev/null 2>&1 || { echo "[!] ERROR: python3 missing."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "[!] ERROR: curl missing. Required for pip setup."; exit 1; }
command -v ethtool >/dev/null 2>&1 || { echo "[!] ERROR: ethtool missing. Required for VLAN offloading."; exit 1; }

export PACKET_DELAY=0.025
export CONCURRENCY_FACTOR=16

BASE=$(mktemp -d /tmp/VLAN_Hunter.XXXXXX)
VENV="$BASE/venv"

WDTH=$(tput cols 2>/dev/null || echo 80)
[ "$WDTH" -lt 60 ] && WDTH=60
export DS_W=$WDTH

LINE() { printf '%*s\n' "$WDTH" '' | tr ' ' '-'; }

EXIT_FUNC() {
    echo -e "\n[*] Cleaning up temporary runtime files..."
    [ -d "$BASE" ] && rm -rf "$BASE"
}

trap EXIT_FUNC EXIT SIGINT SIGTERM

clear
LINE
printf "%$(((WDTH + 26) / 2))s\n" "VLAN HUNTER - TERMS OF USE"
LINE

echo ""
echo "This utility discovers active PPPoE/IPoE VLAN IDs via raw frame injection. As a low-level network diagnostic requiring root privileges, this activity may be logged as anomalous or disruptive by upstream ISP infrastructure."
echo ""
echo "To guarantee host system integrity, execution is strictly confined to an ephemeral virtual environment. No global packages are modified, and all temporary runtime artifacts are securely purged upon termination."
echo ""
echo "By typing 'ACCEPT', you acknowledge the potential for service disruption and assume complete liability for all operational consequences."
echo ""

LINE
printf "Type 'ACCEPT' to continue: "
read USIN
if [ "$USIN" != "ACCEPT" ]; then 
    echo "[!] Aborted by user."
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

if ! python3 -m venv -h >/dev/null 2>&1; then
    echo "[!] ERROR: Python 'venv' module is missing."
    echo "    Debian/Ubuntu: apt-get install python3-venv"
    echo "    RHEL/Fedora:   dnf install python3"
    echo "    Alpine:        apk add python3"
    exit 1
fi

if [ -d "$VENV" ]; then
    if [ ! -f "$VENV/bin/python3" ]; then
        echo "[!] Removing incomplete environment..."
        rm -rf "$VENV"
    fi
fi

if [ ! -d "$VENV" ]; then
    echo "[*] Creating isolated environment..."
    if python3 -m ensurepip --version >/dev/null 2>&1; then
        python3 -m venv "$VENV"
    else
        python3 -m venv --without-pip "$VENV"
    fi
fi

if [ ! -f "$VENV/bin/pip" ]; then
    echo "[*] Bootstrapping pip manually..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | "$VENV/bin/python3" > /dev/null 2>&1
fi

if ! "$VENV/bin/python3" -c "import scapy" >/dev/null 2>&1; then
    echo "[*] Installing Scapy dependency..."
    "$VENV/bin/pip" install scapy || { echo "[!] Scapy installation failed."; exit 1; }
fi

TEMP=$(mktemp -d "$BASE/run.XXXXXX")
PYFS="$TEMP/engine.py"

cat << 'EOF' > "$PYFS"
import os, threading, queue, time, sys, argparse, binascii
from scapy.all import get_if_list, get_if_hwaddr, Ether, Dot1Q, PPPoED, IP, UDP, BOOTP, DHCP, sendp, AsyncSniffer, conf

PACKET_DELAY = float(os.getenv('PACKET_DELAY', 0.001))
CONCURRENCY_FACTOR = int(os.getenv('CONCURRENCY_FACTOR', 16))
DS_W = int(os.getenv('DS_W', 80))

conf.verb = 0
RE_Q = queue.Queue()
STOP = threading.Event()
PROG_LOCK = threading.Lock()
COMPLETED = 0

def TY_P(vlan, name):
    n = name.upper()
    if any(x in n for x in ["IPTV", "TV", "VIDEO", "VOD"]): return "IPTV"
    if any(x in n for x in ["VOIP", "VOICE", "SIP", "PHONE"]): return "VOIP"
    if any(x in n for x in ["MGMT", "CWMP", "TR069", "ACS", "MANAGEMENT"]): return "MGMT"
    return "INTERNET" if vlan > 0 else "UNTAGGED"

def CB_K(pkt):
    try:
        vlan = pkt[Dot1Q].vlan if Dot1Q in pkt else 0
        if pkt.haslayer(PPPoED) and pkt[PPPoED].code in [0x07, 0x65]:
            raw, name = bytes(pkt[PPPoED].payload), 'UNKNOWN'
            i = 0
            while i + 4 <= len(raw):
                tt, tl = (raw[i] << 8) + raw[i+1], (raw[i+2] << 8) + raw[i+3]
                if tt == 0x0102:
                    name = raw[i+4:i+4+tl].decode(errors='ignore')
                    break
                i += 4 + tl
            RE_Q.put({'v':vlan, 'm':pkt[Ether].src, 'n':name, 't':TY_P(vlan,name), 'p':'PPPoE'})
        elif pkt.haslayer(BOOTP) and pkt[BOOTP].op == 2:
            name = "DHCP Server"
            if pkt.haslayer(DHCP):
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'vendor_class_id':
                        name = f"VCI: {opt[1].decode(errors='ignore')}"
                        break
            if name == "DHCP Server" and pkt.haslayer(IP):
                name = f"IPoE: {pkt[IP].src}"
            RE_Q.put({'v':vlan, 'm':pkt[Ether].src, 'n':name, 't':TY_P(vlan,name), 'p':'DHCP'})
    except: pass

def format_time(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h > 0: return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"

def PROGRESS_MONITOR(total):
    start_time = time.time()
    while not STOP.is_set() and COMPLETED < total:
        curr = COMPLETED
        if curr == 0:
            sys.stdout.write(f"\r[*] Scanning... 0/{total} (0.0%)")
        else:
            pct = (curr / total) * 100
            sys.stdout.write(f"\r[*] Scanning... {curr}/{total} ({pct:.1f}%)")
        sys.stdout.flush()
        time.sleep(0.025)
        
    if COMPLETED >= total:
        sys.stdout.write(f"\r[*] Scanning... {total}/{total} (100.0%)\n")
        sys.stdout.flush()

def WORKER(ifce, v_list, hw_mac, mac_bytes):
    global COMPLETED
    for v in v_list:
        if STOP.is_set(): break
        base = Ether(src=hw_mac, dst="ff:ff:ff:ff:ff:ff")
        base_pppoe = Ether(src=hw_mac, dst="ff:ff:ff:ff:ff:ff", type=0x8863)
        base_ipv4 = Ether(src=hw_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0800)
        p = PPPoED(version=1, type=1, code=0x09, sessionid=0)
        d = IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=mac_bytes + b'\x00'*10, xid=v)/DHCP(options=[("message-type", "discover"), "end"])
        pkts = [base/Dot1Q(vlan=v, type=0x8863)/p, base/Dot1Q(vlan=v, type=0x0800)/d] if v > 0 else [base_pppoe/p, base_ipv4/d]
        sendp(pkts, iface=ifce, verbose=0)
        with PROG_LOCK:
            COMPLETED += 1
        if PACKET_DELAY > 0: time.sleep(PACKET_DELAY)

def MAIN():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", dest="ifce"); parser.add_argument("-v", dest="vlan")
    args = parser.parse_args()
    list_if = [(i, get_if_hwaddr(i)) for i in get_if_list() if get_if_hwaddr(i) != '00:00:00:00:00:00']
    ifce = args.ifce; hw_mac = None
    
    print()
    if ifce:
        for n, m in list_if:
            if n == ifce: hw_mac = m
    else:
        print("INTERFACE SELECTION")
        print("-" * 40)
        for i, (n, m) in enumerate(list_if, 1): print(f" {i:>2}. {n:<18} [ {m} ]")
        try:
            sel = int(input("\nENTER INDEX: ")) - 1
            ifce, hw_mac = list_if[sel]
        except: return
        
    if not hw_mac: return
    clean_mac = hw_mac.replace(':', '')
    if len(clean_mac) != 12:
        print(f"\n[!] Invalid MAC address length ({len(clean_mac)}) for selected interface. Skipping.")
        return
    mac_bytes = binascii.unhexlify(clean_mac)

    v_rg = list(range(0, 4096)) if not args.vlan else ([int(args.vlan)] if "-" not in args.vlan else list(range(int(args.vlan.split("-")[0]), int(args.vlan.split("-")[1]) + 1)))

    print("\nINITIALIZING ENGINE")
    print("-" * 40)
    print(f" Interface:  {ifce}")
    print(f" Source MAC: {hw_mac}\n")
    
    os.system(f"ethtool -K {ifce} rxvlan off >/dev/null 2>&1")

    sniffer = AsyncSniffer(iface=ifce, prn=CB_K, store=0)
    sniffer.start()

    time.sleep(0.025)

    total_vlans = len(v_rg)
    
    t_monitor = threading.Thread(target=PROGRESS_MONITOR, args=(total_vlans,))
    t_monitor.daemon = True
    t_monitor.start()

    chunks = [v_rg[i::CONCURRENCY_FACTOR] for i in range(CONCURRENCY_FACTOR)]
    threads = []
    for chunk in chunks:
        if not chunk: continue
        t = threading.Thread(target=WORKER, args=(ifce, chunk, hw_mac, mac_bytes))
        t.start(); threads.append(t)
        
    for t in threads: t.join()
    
    global COMPLETED
    COMPLETED = total_vlans
    t_monitor.join()

    sys.stdout.write(f"\n[*] Probe dispatch complete. Waiting for ISP responses...\n")

    sys.stdout.flush()
    time.sleep(3)
    STOP.set()
    sniffer.stop()
    os.system(f"ethtool -K {ifce} rxvlan on >/dev/null 2>&1")

    data = {}
    while not RE_Q.empty():
        item = RE_Q.get()
        data[f"{item['v']}-{item['p']}-{item['n']}"] = item

    ac_w = max(15, DS_W - 55)
    h_fm = f" {{:<6}} {{:<7}} {{:<12}} {{:<{ac_w}}} {{:<17}} "
    
    print("\nDISCOVERY RESULTS")
    print("-" * DS_W)
    print(h_fm.format("VLAN", "PROTO", "TYPE", "IDENTITY", "MAC ADDRESS"))
    print("-" * DS_W)
    
    sk = sorted(data.keys(), key=lambda x: (int(x.split('-')[0]), x.split('-')[1]))
    for i, k in enumerate(sk, 1):
        d = data[k]
        print(h_fm.format(str(d['v']), d['p'], d['t'], d['n'][:ac_w-1], d['m']))
        
    if not data: 
        print(" No active PPPoE or IPoE services detected.")
    print("-" * DS_W + "\n")

if __name__ == "__main__":
    try: MAIN()
    except KeyboardInterrupt: 
        STOP.set()
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
EOF

echo "[*] Launching Engine..."
"$VENV/bin/python3" "$PYFS" "$@"
