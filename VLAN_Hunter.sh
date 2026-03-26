#!/bin/bash

# AUTHOR & METADATA
# Title:        VLAN Hunter
# Author:       sussyflow
# Description:  Reliable PPPoE/IPoE VLAN Discovery Tool (Linux)

[ "$EUID" -ne 0 ] && echo "[!] ERROR: ROOT REQUIRED" && exit 1

for CMND in python3 curl ethtool tput mktemp clear; do
    command -v "$CMND" >/dev/null 2>&1 || { echo "[!] ERROR: $CMND missing."; exit 1; }
done

[[ ! -t 0 || ! -w "." ]] && WDIR="/tmp" || WDIR="."

BASE=$(mktemp -d "$WDIR/vlan.XXXXXX")
VENV="$BASE/venv"

WDTH=$(tput cols 2>/dev/null || echo 80)
[ "$WDTH" -lt 60 ] && WDTH=60
export DSWD=$WDTH

LINE() {
  printf '%*s\n' "$WDTH" '' | tr ' ' '='
}

CLND=0

EXIT() {
    if [ "$CLND" -eq 0 ]; then
        echo "[*] Terminating & cleaning up environment..."
        rm -rf "$BASE"
        CLND=1
    fi
}

trap EXIT EXIT SIGINT SIGTERM

clear
LINE
printf "%$(((WDTH + 26) / 2))s\n" "VLAN HUNTER - TERMS OF USE"
LINE
echo ""

echo "This utility discovers active PPPoE/IPoE VLAN IDs via raw frame injection. As a low-level network diagnostic requiring root privileges, this activity may be logged as anomalous or disruptive by upstream ISP infrastructure."
echo ""
echo "Execution is strictly confined to an ephemeral virtual environment. No global packages are modified. Temporary runtime artifacts are securely purged."
echo ""
echo "By typing 'ACCEPT', you acknowledge the potential for service disruption and assume complete liability for all operational consequences."
echo ""

LINE
printf "Enter ACCEPT to continue: "
read USIN < /dev/tty

USIN=$(echo "$USIN" | tr '[:lower:]' '[:upper:]')

if [ "$USIN" != "ACCEPT" ]; then 
    echo ""
    echo "[!] Operation aborted."
    echo ""
    exit 1
else
    echo ""
    echo "[+] Terms accepted. Initializing sequence..."
    echo ""
fi

PYVR=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

if ! python3 -m venv -h >/dev/null 2>&1; then
    echo "[!] ERROR: Python 'venv' module is missing."
    echo "    Debian/Ubuntu: apt-get install python3-venv"
    echo "    RHEL/Fedora:   dnf install python3"
    echo "    Alpine:        apk add python3"
    exit 1
fi

if [ -d "$VENV" ]; then
    if [ ! -f "$VENV/bin/python3" ]; then
        rm -rf "$VENV"
    fi
fi

if [ ! -d "$VENV" ]; then
    echo "[*] Building isolated Python environment..."
    if python3 -m ensurepip --version >/dev/null 2>&1; then
        python3 -m venv "$VENV"
    else
        python3 -m venv --without-pip "$VENV"
    fi
fi

if "$VENV/bin/python3" -c "import scapy" >/dev/null 2>&1; then
    echo "[+] Network engine (Scapy) verified."

elif python3 -c "import scapy" >/dev/null 2>&1; then
    echo "[i] Using system-level network engine (Scapy)."
    USCP=1

else
    echo "[*] Fetching required dependencies..."

    if curl -s --max-time 2 https://pypi.org >/dev/null 2>&1; then
        if [ ! -f "$VENV/bin/pip" ]; then
            curl -sS https://bootstrap.pypa.io/get-pip.py | "$VENV/bin/python3" >/dev/null 2>&1
        fi

        "$VENV/bin/pip" install scapy -q >/dev/null 2>&1 || {
            echo "[!] Dependency resolution failed."
            exit 1
        }
    else
        echo "[!] Offline mode: Dependency missing."
        echo "    Install manually: apt install python3-scapy"
        exit 1
    fi
fi

TEMP=$(mktemp -d "$BASE/r.XXXXXX") && chmod 700 "$TEMP"
PYFS="$TEMP/core.py"

cat << 'EOF' > "$PYFS"
import os, threading, queue, time, sys, binascii
from scapy.all import get_if_list, get_if_hwaddr, Ether, Dot1Q, PPPoED, IP, UDP, BOOTP, DHCP, sendp, AsyncSniffer, conf

PDLY = 0.25
CFTR = 16
DSWD = int(os.getenv('DSWD', 80))

conf.verb = 0
REQQ = queue.Queue()
STOP = threading.Event()
PLCK = threading.Lock()
CPLT = 0

def TYPP(VLAN, NAME):
    NNNN = NAME.upper()
    if any(XXXX in NNNN for XXXX in ["IPTV", "TV", "VIDEO", "VOD"]): return "IPTV"
    if any(XXXX in NNNN for XXXX in ["VOIP", "VOICE", "SIP", "PHONE"]): return "VOIP"
    if any(XXXX in NNNN for XXXX in ["MGMT", "CWMP", "TR069", "ACS", "MANAGEMENT"]): return "MGMT"
    return "INTERNET" if VLAN > 0 else "UNTAGGED"

def CBBK(PKTT):
    try:
        VLAN = PKTT[Dot1Q].vlan if Dot1Q in PKTT else 0
        if PKTT.haslayer(PPPoED) and PKTT[PPPoED].code in [0x07, 0x65]:
            RAWW, NAME = bytes(PKTT[PPPoED].payload), 'UNKNOWN'
            INDX = 0
            while INDX + 4 <= len(RAWW):
                TTTT, TLLL = (RAWW[INDX] << 8) + RAWW[INDX+1], (RAWW[INDX+2] << 8) + RAWW[INDX+3]
                if TTTT == 0x0102:
                    NAME = RAWW[INDX+4:INDX+4+TLLL].decode(errors='ignore')
                    break
                INDX += 4 + TLLL
            REQQ.put({'vvvv':VLAN, 'mmmm':PKTT[Ether].src, 'nnnn':NAME, 'tttt':TYPP(VLAN,NAME), 'pppp':'PPPoE'})
        elif PKTT.haslayer(BOOTP) and PKTT[BOOTP].op == 2:
            NAME = "DHCP Server"
            if PKTT.haslayer(DHCP):
                for OPTT in PKTT[DHCP].options:
                    if isinstance(OPTT, tuple) and OPTT[0] == 'vendor_class_id':
                        NAME = f"VCI: {OPTT[1].decode(errors='ignore')}"
                        break
            if NAME == "DHCP Server" and PKTT.haslayer(IP):
                NAME = f"IPoE: {PKTT[IP].src}"
            REQQ.put({'vvvv':VLAN, 'mmmm':PKTT[Ether].src, 'nnnn':NAME, 'tttt':TYPP(VLAN,NAME), 'pppp':'DHCP'})
    except: pass

def FMTT(SECS):
    MINS, SECC = divmod(int(SECS), 60)
    HRSS, MINS = divmod(MINS, 60)
    if HRSS > 0: return f"{HRSS:02d}:{MINS:02d}:{SECC:02d}"
    return f"{MINS:02d}:{SECC:02d}"

def PROG(TOTL):
    STRT = time.time()
    while not STOP.is_set() and CPLT < TOTL:
        CURR = CPLT
        PCTT = (CURR / TOTL) * 100 if TOTL else 0
        BLEN = 30
        FILL = int((CURR / TOTL) * BLEN) if TOTL else 0
        BARR = '=' * FILL + ' ' * (BLEN - FILL)
        sys.stdout.write(f"\r[*] Scanning: [{BARR}] {PCTT:.1f}% ({CURR}/{TOTL})")
        sys.stdout.flush()
        time.sleep(0.05)
        
    if CPLT >= TOTL:
        sys.stdout.write(f"\r[+] Scanning: [==============================] 100.0% ({TOTL}/{TOTL})\n")
        sys.stdout.flush()

def WRKR(IFCE, VLST, HMAC, MBYT):
    global CPLT
    for VVVV in VLST:
        if STOP.is_set(): break
        BASE = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff")
        BPPP = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff", type=0x8863)
        BIPV = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff", type=0x0800)
        PPPP = PPPoED(version=1, type=1, code=0x09, sessionid=0)
        DDDD = IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=MBYT + b'\x00'*10, xid=VVVV)/DHCP(options=[("message-type", "discover"), "end"])
        PKTS = [BASE/Dot1Q(vlan=VVVV, type=0x8863)/PPPP, BASE/Dot1Q(vlan=VVVV, type=0x0800)/DDDD] if VVVV > 0 else [BPPP/PPPP, BIPV/DDDD]
        sendp(PKTS, iface=IFCE, verbose=0)
        with PLCK:
            CPLT += 1
        if PDLY > 0: time.sleep(PDLY)

def MAIN():
    LSTF = [(INDX, get_if_hwaddr(INDX)) for INDX in get_if_list() if get_if_hwaddr(INDX) != '00:00:00:00:00:00']
    IFCE = None
    HMAC = None
    
    print("\nNETWORK INTERFACES")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    for INDX, (NNNN, MMMM) in enumerate(LSTF, 1):
        print(f" {INDX:>2}. {NNNN:<18} [ {MMMM} ]")
    
    try:
        print("\nSelect interface index: ", end="", flush=True)
        SELL = int(open("/dev/tty").readline().strip()) - 1

        if SELL < 0 or SELL >= len(LSTF):
            print("\n[!] Selection out of range.")
            return
        IFCE, HMAC = LSTF[SELL]
    except:
        print("\n[!] Invalid selection.")
        return

    if not HMAC: return
    CMAC = HMAC.replace(':', '')
    if len(CMAC) != 12:
        print(f"\n[!] Invalid MAC address length ({len(CMAC)}) for selected interface. Skipping.")
        return
    MBYT = binascii.unhexlify(CMAC)

    VRGG = list(range(0, 4096))

    print("\nINITIALIZING SCAN")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f" Interface  : {IFCE}")
    print(f" Source MAC : {HMAC}\n")
    
    os.system(f"ethtool -K {IFCE} rxvlan off >/dev/null 2>&1")

    SNFF = AsyncSniffer(iface=IFCE, prn=CBBK, store=0)
    SNFF.start()

    time.sleep(0.025)

    TVLN = len(VRGG)
    
    TMON = threading.Thread(target=PROG, args=(TVLN,))
    TMON.daemon = True
    TMON.start()

    CHKS = [VRGG[INDX::CFTR] for INDX in range(CFTR)]
    THDS = []
    for CHNK in CHKS:
        if not CHNK: continue
        THRD = threading.Thread(target=WRKR, args=(IFCE, CHNK, HMAC, MBYT))
        THRD.start(); THDS.append(THRD)
        
    for THRD in THDS: THRD.join()
    
    global CPLT
    CPLT = TVLN
    TMON.join()

    sys.stdout.write("\n[*] Awaiting network responses...\n")

    sys.stdout.flush()
    time.sleep(3)
    STOP.set()
    SNFF.stop()
    os.system(f"ethtool -K {IFCE} rxvlan on >/dev/null 2>&1")

    DATA = {}
    while not REQQ.empty():
        ITEM = REQQ.get()
        DATA[f"{ITEM['vvvv']}-{ITEM['pppp']}-{ITEM['nnnn']}"] = ITEM

    ACWW = max(15, DSWD - 55)
    HFFM = f" {{:<6}} {{:<7}} {{:<12}} {{:<{ACWW}}} {{:<17}} "
    
    print("\nDISCOVERY RESULTS")
    print("━" * DSWD)
    print(HFFM.format('VLAN', 'PROTO', 'TYPE', 'IDENTITY', 'MAC ADDRESS'))
    print("━" * DSWD)
    
    SKKK = sorted(DATA.keys(), key=lambda XXXX: (int(XXXX.split('-')[0]), XXXX.split('-')[1]))
    for INDX, KKKK in enumerate(SKKK, 1):
        DDDD = DATA[KKKK]
        print(HFFM.format(str(DDDD['vvvv']), DDDD['pppp'], DDDD['tttt'], DDDD['nnnn'][:ACWW-1], DDDD['mmmm']))
        
    if not DATA: 
        print("[!] No services detected.")
    print("━" * DSWD + "\n")

if __name__ == "__main__":
    try: MAIN()
    except KeyboardInterrupt: 
        STOP.set()
        print("\n[!] Scan manually interrupted.")
        sys.exit(0)
EOF

echo ""
echo "[*] Launching scan engine..."
if [ "$USCP" = "1" ]; then
    python3 "$PYFS"
else
    "$VENV/bin/python3" "$PYFS"
fi
