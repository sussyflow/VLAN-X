#!/bin/bash


# AUTHOR & METADATA

# Title:       VLAN Hunter
# Author:      Niggesh
# Description: Reliable PPPoE/IPoE VLAN Discovery Tool (Linux)


# 1. PREFLIGHT CHECKS

[ "$EUID" -ne 0 ] && echo "ERROR: ROOT REQUIRED" && exit 1
[ ! -w "." ] && echo "ERROR: Current directory is not writable." && exit 1
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 missing."; exit 1; }


# 2. ENGINE CONFIGURATION (Adjust these to tune performance)

export BURST_SIZE=250    # VLANs processed per chunk/thread
export BURST_PARALLEL_COUNT=4    # Max concurrent sending threads allowed
export BURST_DELAY=0.5     # Seconds to wait between starting new threads
export PRE_SLEEP=0.25   # Seconds to wait for sniffer to initialize before sending
export POST_SLEEP=3.0  # Seconds to wait for ISP responses after all frames are sent


# 3. GLOBAL VARIABLES & PATHS

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" &> /dev/null && pwd)"
BASE="$SCRIPT_DIR/VLAN Hunter TMP"
VENV="$BASE/venv"
TEMP=$(mktemp -d "$BASE/run.XXXXXX")
PYFS="$TEMP/engine.py"

WDTH=$(tput cols)
[ -z "$WDTH" ] && WDTH=80
[ "$WDTH" -lt 40 ] && WDTH=40
INWD=$((WDTH - 2))
export DS_W=$WDTH


# 4. UI FUNCTIONS & CLEANUP

LINE() { printf '%.0s=' $(seq 1 $(($WDTH))); echo; }

CNTR() {
    local TEXT="$1"
    local SIZE="$2"
    local PADD=$(( (SIZE - ${#TEXT}) / 2 ))
    [ $PADD -lt 0 ] && PADD=0
    printf "%${PADD}s%s\n" "" "$TEXT"
}

JUST() {
    python3 -c "
import sys, textwrap
w = int(sys.argv[1])
t = sys.stdin.read().split('\n\n')
for p in t:
    ls = textwrap.wrap(p.replace('\n', ' '), w)
    for l in ls[:-1]:
        ws = l.split()
        if len(ws) > 1:
            sa = w - sum(len(x) for x in ws)
            sb, ex = divmod(sa, len(ws) - 1)
            o = ''
            for i, x in enumerate(ws[:-1]):
                o += x + ' ' * (sb + (1 if i < ex else 0))
            print(' ' + o + ws[-1])
        else:
            print(' ' + l)
    if ls:
        print(' ' + ls[-1])
    print()
" "$INWD"
}

EXIT_FUNC() {
    echo -e "\n[!] Cleaning up temporary runtime files..."
    [ -d "$TEMP" ] && rm -rf "$TEMP"
}
trap EXIT_FUNC EXIT SIGINT SIGTERM


# 5. INITIALIZATION

clear
LINE
CNTR "TERMS OF USE" "$WDTH"
LINE

cat << EOF | JUST
This utility identifies active VLAN IDs for PPPoE/IPoE by injecting raw discovery frames. This low-level network operation requires root privileges and may be flagged as unusual activity by upstream equipment.

To ensure system integrity, a local virtual environment and isolated temporary directory are used. No global packages are installed, and all runtime files are purged automatically upon exit.

By typing 'ACCEPT', the user acknowledges the risks of service disruption and accepts full liability for all consequences.
EOF

LINE
printf "Type 'ACCEPT' to continue: "
read USIN
if [ "$USIN" != "ACCEPT" ]; then exit 1; fi

mkdir -p "$BASE"


# 6. PYTHON ENGINE GENERATION

cat << 'EOF' > "$PYFS"
import os, threading, queue, time, sys, signal, argparse, binascii, re
from scapy.all import get_if_list, get_if_hwaddr, Ether, Dot1Q, PPPoED, IP, UDP, BOOTP, DHCP, sendp, sniff, conf

# --- LOAD CONFIGURATION FROM BASH ---
BURST_SIZE = int(os.getenv('BURST_SIZE', 250))
BURST_PARALLEL_COUNT = int(os.getenv('BURST_PARALLEL_COUNT', 4))
BURST_DELAY = float(os.getenv('BURST_DELAY', 0.5))
PRE_SLEEP = float(os.getenv('PRE_SLEEP', 0.5))
POST_SLEEP = float(os.getenv('POST_SLEEP', 3.0))
DS_W = int(os.getenv('DS_W', 80))

conf.verb = 0
RE_Q = queue.Queue()
STOP = threading.Event()
SEM = threading.Semaphore(BURST_PARALLEL_COUNT)

# Progress Tracking
PROG_LOCK = threading.Lock()
COMPLETED_CHUNKS = 0
TOTAL_CHUNKS = 1

def TY_P(vlan, name):
    n = name.upper()
    if any(x in n for x in ["IPTV", "TV", "VCI: IPTV"]): return "IPTV"
    if any(x in n for x in ["VOIP", "VOICE", "VCI: VOIP"]): return "VOIP"
    return "INTERNET" if vlan > 0 else "UNTAGGED"

def CB_K(pkt):
    try:
        vlan = pkt[Dot1Q].vlan if Dot1Q in pkt else 0
        
        # PPPoE Detection
        if pkt.haslayer(PPPoED) and pkt[PPPoED].code == 0x07:
            raw, name = bytes(pkt[PPPoED].payload), 'UNKNOWN'
            i = 0
            while i + 4 <= len(raw):
                tt, tl = (raw[i] << 8) + raw[i+1], (raw[i+2] << 8) + raw[i+3]
                if tt == 0x0102:
                    name = raw[i+4:i+4+tl].decode(errors='ignore')
                    break
                i += 4 + tl
            RE_Q.put({'v':vlan, 'm':pkt[Ether].src, 'n':name, 't':TY_P(vlan,name), 'p':'PPPoE'})
            
        # DHCP/IPoE Detection
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
    except Exception:
        pass # Ignore malformed packets

def SN_F(ifce):
    sniff(iface=ifce, filter="(ether proto 0x8863) or (vlan and (ether proto 0x8863 or udp port 67 or udp port 68))",
          prn=CB_K, store=0, stop_filter=lambda x: STOP.is_set())

def SEND_CHUNK(vlan_subgroup, macs, mac_bytes, ifce):
    global COMPLETED_CHUNKS, TOTAL_CHUNKS
    with SEM:
        batch = []
        for v in vlan_subgroup:
            base = Ether(src=macs, dst="ff:ff:ff:ff:ff:ff")
            pppo = PPPoED(version=1, type=1, code=0x09, sessionid=0)
            dhcp = IP(src="0.0.0.0", dst="255.255.255.255") \
                   / UDP(sport=68, dport=67) \
                   / BOOTP(chaddr=mac_bytes + b'\x00'*10, xid=v) \
                   / DHCP(options=[("message-type", "discover"), "end"])
            
            if v > 0:
                batch.append(base/Dot1Q(vlan=v, type=0x8863)/pppo)
                batch.append(base/Dot1Q(vlan=v, type=0x0800)/dhcp)
            else:
                batch.append(base/pppo)
                batch.append(base/dhcp)
        
        sendp(batch, iface=ifce, verbose=0)
        
        with PROG_LOCK:
            COMPLETED_CHUNKS += 1
            pct = (COMPLETED_CHUNKS / TOTAL_CHUNKS) * 100
            sys.stdout.write(f"\r\033[K[*] Scanning... [ {pct:.1f}% | {COMPLETED_CHUNKS}/{TOTAL_CHUNKS} Chunks ]")
            sys.stdout.flush()

def val_mac(mstr):
    clnm = re.sub(r'[^0-9a-fA-F]', '', mstr)
    if len(clnm) == 12:
        return ":".join(clnm[i:i+2] for i in range(0, 12, 2)).lower()
    raise argparse.ArgumentTypeError("Invalid MAC format. Use format 00:11:22:33:44:55")

def MAIN():
    global POST_SLEEP, TOTAL_CHUNKS
    
    pars = argparse.ArgumentParser()
    pars.add_argument("-i", dest="ifce", help="Network interface")
    pars.add_argument("-v", dest="vlan", help="VLAN or range (e.g. 100 or 10-200)")
    pars.add_argument("-m", "--mac", dest="mac", type=val_mac, help="Spoof source MAC address")
    pars.add_argument("-t", "--timeout", dest="timeout", type=float, help="Listen timeout in seconds")
    args = pars.parse_args()

    if args.timeout is not None:
        POST_SLEEP = args.timeout

    list_if = [(i, get_if_hwaddr(i)) for i in get_if_list() if i != 'lo']

    ifce = args.ifce
    hw_mac = None

    # Handle Interface Selection
    if ifce:
        for n, m in list_if:
            if n == ifce: hw_mac = m
    else:
        print("\n" + "NETWORK INTERFACE SELECTION".center(DS_W))
        print("-" * DS_W)
        for i, (n, m) in enumerate(list_if, 1):
            print(f" {i:>2}. {n:<18} [ {m} ]")
        try:
            sel = int(input(f"\nENTER INDEX: ")) - 1
            ifce, hw_mac = list_if[sel]
        except: return

    if not hw_mac and not args.mac: return

    # Determine final MAC (Spoofed or Hardware)
    macs = args.mac if args.mac else hw_mac

    if args.vlan:
        if "-" in args.vlan:
            beg, end = map(int, args.vlan.split("-"))
            v_rg = list(range(beg, end + 1))
        else:
            v_rg = [int(args.vlan)]
    else:
        v_rg = list(range(0, 4096))

    TOTAL_CHUNKS = (len(v_rg) + BURST_SIZE - 1) // BURST_SIZE

    print("\n" + "VLAN DISCOVERY ENGINE".center(DS_W))
    print(f"IFACE: {ifce} | SOURCE MAC: {macs}{' (SPOOFED)' if args.mac else ''}".center(DS_W))
    print("-" * DS_W)

    t1 = threading.Thread(target=SN_F, args=(ifce,))
    t1.daemon = True
    t1.start()
    time.sleep(PRE_SLEEP)

    mac_bytes = binascii.unhexlify(macs.replace(':', ''))
    
    # Trigger Parallel Sending
    threads = []
    sys.stdout.write(f"\r\033[K[*] Scanning... [ 0.0% | 0/{TOTAL_CHUNKS} Chunks ]")
    sys.stdout.flush()
    
    for i in range(0, len(v_rg), BURST_SIZE):
        vlan_subgroup = v_rg[i : i + BURST_SIZE]
        t = threading.Thread(target=SEND_CHUNK, args=(vlan_subgroup, macs, mac_bytes, ifce))
        t.start()
        threads.append(t)
        time.sleep(BURST_DELAY)

    # Wait for completion
    for t in threads:
        t.join()

    sys.stdout.write(f"\n[*] All frames dispatched. Waiting {POST_SLEEP}s for ISP responses...\n")
    sys.stdout.flush()
    time.sleep(POST_SLEEP)
    STOP.set()

    data = {}
    while not RE_Q.empty():
        item = RE_Q.get()
        data[f"{item['v']}-{item['m']}-{item.get('p', 'UNK')}"] = item

    ac_w = max(10, DS_W - 55)
    h_fm = "{:^5} {:^7} {:^8} {:^10} {:^" + str(ac_w) + "} {:^18}"
    print("\n" + h_fm.format("#", "VLAN", "PROTO", "TYPE", "IDENTITY", "MAC ADDRESS"))
    print("-" * DS_W)

    for i, k in enumerate(sorted(data.keys(), key=lambda x: int(x.split('-')[0])), 1):
        d = data[k]
        print(h_fm.format(str(i), str(d['v']), d['p'], d['t'], d['n'][:ac_w], d['m']))
    
    if not data:
        print(h_fm.format("-", "NONE", "-", "-", "NO ACTIVE SERVICES DETECTED", "-"))
        
    print("-" * DS_W + "\n")

if __name__ == "__main__":
    MAIN()
EOF


# 7. EXECUTION

if [ ! -d "$VENV" ]; then
    echo "[*] Initializing local virtual environment. This may take a moment..."
    python3 -m venv "$VENV" >/dev/null 2>&1
    "$VENV/bin/pip" install --no-cache-dir -q scapy
fi

"$VENV/bin/python3" "$PYFS" "$@"