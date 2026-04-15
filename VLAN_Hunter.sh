#!/usr/bin/env bash

# Title:        VLAN Hunter
# Author:       sussyflow
# Copyright:    (c) 2026 sussyflow
# License:      GNU General Public License v3.0
# Description:  Reliable VLAN Discovery Tool for Linux

export PYTHONDONTWRITEBYTECODE=1

stty -echoctl < /dev/tty 2>/dev/null

BASE_DIR=""
for d in "/run" "/tmp" "/home"; do
    if [ -d "$d" ] && [ -w "$d" ]; then
        BASE_DIR="$d"
        break
    fi
done

if [ -z "$BASE_DIR" ]; then
    echo "Error: No writable directory found for workspace."
    exit 1
fi

export _VLAN_WORKSPACE=$(mktemp -d "$BASE_DIR/VLAN-XXXXXX" 2>/dev/null)

if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME=$HOME
fi
[ -z "$USER_HOME" ] && USER_HOME="/root"

if [ -d "$USER_HOME/Desktop" ] && [ -w "$USER_HOME/Desktop" ]; then
    LOG_FILE="$USER_HOME/Desktop/VLAN_Hunter_Execution.log"
else
    LOG_FILE="$USER_HOME/VLAN_Hunter_Execution.log"
fi
touch "$LOG_FILE" 2>/dev/null

WDTH=64
T_COLS=$(tput cols 2>/dev/null || echo $WDTH)
if [ "$T_COLS" -gt "$WDTH" ]; then
    UI_W=$WDTH
else
    UI_W=$T_COLS
fi
export UI_W

AUTO_FETCH=0
AUTO_ACCEPT=0
TARGET_INTERFACE=""
TARGET_VLAN=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -a|--auto) AUTO_FETCH=1; shift ;;
        -i|--interface) TARGET_INTERFACE="$2"; shift 2 ;;
        -v|--vlan) TARGET_VLAN="$2"; shift 2 ;;
        --accept) AUTO_ACCEPT=1; shift ;;
        *) shift ;;
    esac
done

declare -a INSTALLED_PKGS=()
PKG_MGR=""
PKG_INSTALL=""
PKG_UPDATED=0

if command -v apt-get >/dev/null 2>&1; then PKG_MGR="apt-get"; PKG_INSTALL="DEBIAN_FRONTEND=noninteractive apt-get install -y";
elif command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"; PKG_INSTALL="dnf install -y";
elif command -v yum >/dev/null 2>&1; then PKG_MGR="yum"; PKG_INSTALL="yum install -y";
elif command -v pacman >/dev/null 2>&1; then PKG_MGR="pacman"; PKG_INSTALL="pacman -S --noconfirm";
elif command -v zypper >/dev/null 2>&1; then PKG_MGR="zypper"; PKG_INSTALL="zypper install -y";
elif command -v apk >/dev/null 2>&1; then PKG_MGR="apk"; PKG_INSTALL="apk add --no-interactive";
fi

if [ "$AUTO_FETCH" -eq 1 ]; then
    APP_TITLE="VLAN HUNTER PRO"
else
    APP_TITLE="VLAN HUNTER"
fi
APP_AUTHOR="By Sussyflow (https://github.com/sussyflow)"

PRINT_SEP() {
    local char="$1"
    printf "%${UI_W}s\n" "" | tr ' ' "$char"
}

PRINT_CENTER() {
    local str="$1"
    local pad=$(( (UI_W - ${#str}) / 2 ))
    [ $pad -lt 0 ] && pad=0
    printf "%*s%s\n" $pad "" "$str"
}

DRAW_HEADER() {
    clear
    PRINT_SEP "="
    PRINT_CENTER "$APP_TITLE"
    PRINT_CENTER "$APP_AUTHOR"
    PRINT_SEP "="
    echo ""
}

tprint() {
    local TS="[$(date '+%H:%M:%S')]"
    local TS_LEN=${#TS}
    local MAX_TEXT_W=$(( UI_W - TS_LEN - 1 ))
    local is_first=1
    local padding=$(printf "%$((TS_LEN + 1))s" "")
    
    echo "$1" | fold -w "$MAX_TEXT_W" -s | while IFS= read -r line; do
        if [ "$is_first" -eq 1 ]; then
            echo "$TS $line"
            echo "$TS $line" >> "$LOG_FILE" 2>/dev/null
            is_first=0
        else
            echo "${padding}${line}"
            echo "${padding}${line}" >> "$LOG_FILE" 2>/dev/null
        fi
    done
}

cprint() {
    local is_first=1
    local TS="[$(date '+%H:%M:%S')]"
    local TS_LEN=${#TS}
    local padding=$(printf "%$((TS_LEN + 1))s" "")
    
    echo "$1" | fold -w "$UI_W" -s | while IFS= read -r line; do
        echo "$line"
        if [ "$is_first" -eq 1 ]; then
            echo "$TS $line" >> "$LOG_FILE" 2>/dev/null
            is_first=0
        else
            echo "${padding}${line}" >> "$LOG_FILE" 2>/dev/null
        fi
    done
}

lprint() {
    echo "[$(date '+%H:%M:%S')] $1" >> "$LOG_FILE" 2>/dev/null
}

auto_install_pkg() {
    local pkg="$1"
    if [ "$AUTO_FETCH" -ne 1 ]; then return 1; fi
    if [ -z "$PKG_MGR" ]; then
        tprint "Error: No supported package manager found."
        return 1
    fi

    for installed in "${INSTALLED_PKGS[@]}"; do
        if [ "$installed" == "$pkg" ]; then
            return 0
        fi
    done

    if [ "$PKG_UPDATED" -eq 0 ]; then
        tprint "Updating package manager indices..."
        case "$PKG_MGR" in
            "apt-get") DEBIAN_FRONTEND=noninteractive apt-get update -q -y >/dev/null 2>&1 ;;
            "apk") apk update -q >/dev/null 2>&1 ;;
            "pacman") pacman -Sy --noconfirm >/dev/null 2>&1 ;;
            "zypper") zypper refresh >/dev/null 2>&1 ;;
        esac
        PKG_UPDATED=1
    fi

    tprint "Auto-installing globally: $pkg"
    if eval "$PKG_INSTALL $pkg" >/dev/null 2>&1; then
        INSTALLED_PKGS+=("$pkg")
        return 0
    else
        tprint "Error: Failed to install $pkg"
        return 1
    fi
}

[ "$EUID" -ne 0 ] && tprint "Error: Root privileges required." && exit 1

STATE_MTU_CHANGED=0
STATE_RX_CHANGED=0
ORIGINAL_MTU=""
CLEANED=0

cleanup() {
    if [ "$CLEANED" -eq 1 ]; then return; fi
    CLEANED=1
    tprint "Restoring system state..."

    if [ "$STATE_MTU_CHANGED" -eq 1 ] && [ -n "$TARGET_INTERFACE" ] && [ -n "$ORIGINAL_MTU" ]; then
        ip link set dev "$TARGET_INTERFACE" mtu "$ORIGINAL_MTU" >/dev/null 2>&1
        tprint "Restored MTU to $ORIGINAL_MTU"
    fi
    
    if [ "$STATE_RX_CHANGED" -eq 1 ] && [ -n "$TARGET_INTERFACE" ]; then
        ethtool -K "$TARGET_INTERFACE" rxvlan on >/dev/null 2>&1
        tprint "Restored RX-VLAN offload"
    fi
    
    if [ -n "$_VLAN_WORKSPACE" ] && [ -d "$_VLAN_WORKSPACE" ] && [ "$_VLAN_WORKSPACE" != "/" ]; then
        rm -rf "$_VLAN_WORKSPACE"
    fi

    if [ ${#INSTALLED_PKGS[@]} -gt 0 ]; then
        tprint "Retained dependencies: ${INSTALLED_PKGS[*]}"
    fi
    
    stty echoctl < /dev/tty 2>/dev/null
    
    tprint "Cleanup complete."
    echo "Log: $LOG_FILE"
    echo ""
    exit 0
}

trap cleanup EXIT SIGINT SIGTERM HUP QUIT

DRAW_HEADER
tprint "Starting VLAN Hunter..."
tprint "Running robust preflight checks..."

MISSING_CMDS=()
for cmd in python3 ip ethtool mktemp tput clear fold cat grep stty date getent cut touch; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING_CMDS+=("$cmd")
    fi
done

if [ ${#MISSING_CMDS[@]} -gt 0 ]; then
    if [ "$AUTO_FETCH" -eq 1 ]; then
        for cmd in "${MISSING_CMDS[@]}"; do
            pkg_name="$cmd"
            case "$cmd" in
                ip) pkg_name="iproute2" ;;
                mktemp|fold|cat|stty|date|cut|touch) pkg_name="coreutils" ;;
                tput|clear) 
                    pkg_name="ncurses-bin"
                    [ "$PKG_MGR" = "pacman" ] || [ "$PKG_MGR" = "apk" ] && pkg_name="ncurses"
                    ;;
                getent) pkg_name="libc-bin" ;;
                python3) 
                    pkg_name="python3"
                    [ "$PKG_MGR" = "apk" ] && pkg_name="python3"
                    ;;
            esac
            if ! auto_install_pkg "$pkg_name"; then
                tprint "Critical Error: Failed to auto-install $pkg_name for '$cmd'."
                exit 1
            fi
        done
        
        for cmd in "${MISSING_CMDS[@]}"; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                tprint "Critical Error: '$cmd' is still missing after installation attempt."
                exit 1
            fi
        done
        tprint "All missing command dependencies successfully resolved."
    else
        tprint "Critical Error: Missing required system commands: ${MISSING_CMDS[*]}"
        tprint "Run with -a or --auto to automatically resolve these dependencies."
        exit 1
    fi
fi

PYTHON_EXEC="python3"

if python3 -c "import scapy" >/dev/null 2>&1; then
    tprint "Found dependency: Python Scapy module"
else
    tprint "Missing dependency: Python Scapy module"
    if [ "$AUTO_FETCH" -eq 1 ]; then
        SCAPY_PKG="python3-scapy"
        case "$PKG_MGR" in
            "pacman") SCAPY_PKG="python-scapy" ;;
            "apk") SCAPY_PKG="py3-scapy" ;;
        esac
        
        if auto_install_pkg "$SCAPY_PKG"; then
            if ! python3 -c "import scapy" >/dev/null 2>&1; then
                tprint "Error: Scapy installed natively but not importable."
                exit 1
            fi
        else
            tprint "Error: Failed to install $SCAPY_PKG natively."
            exit 1
        fi
    else
        tprint "Error: Requires Scapy. Use -a to auto-fetch."
        exit 1
    fi
fi
sleep 3

if [ "$AUTO_ACCEPT" -eq 0 ]; then
    DRAW_HEADER
    cprint "TERMS OF USE"
    echo ""
    cprint "VLAN Hunter probes network segments to identify active 802.1Q VLANs and map service delivery such as Internet, IPTV, or VoIP without permanently altering host configurations."
    echo ""
    cprint "The utility temporarily modifies network hardware and MTU settings for deep packet inspection. While the script is designed to revert all changes and purge artifacts upon exit, users acknowledge this activity is visible to upstream monitors and may be recorded."
    echo ""
    cprint "By proceeding, you assume full responsibility for any resulting network consequences. The author is held harmless from all liability regarding operational disruptions, and you acknowledge that improper termination may necessitate manual restoration of your network interface."
    PRINT_SEP "-"
    printf "Enter 'ACCEPT' to acknowledge and proceed: "
    
    if ! read -t 45 -r TERMS_ACCEPT < /dev/tty; then
        echo -e "\n"
        tprint "Input timeout (45s). Aborting."
        exit 1
    fi

    if [ "${TERMS_ACCEPT^^}" != "ACCEPT" ]; then 
        echo ""
        tprint "Authorization declined. Aborting."
        exit 1
    fi
    echo ""
fi
lprint "Terms accepted."

if [ -z "$TARGET_INTERFACE" ]; then
    DRAW_HEADER
    cprint "Available Network Interfaces"
    echo ""
    declare -a IFACE_LIST
    idx=1
    for iface in /sys/class/net/*; do
        ifname=$(basename "$iface")
        if [[ "$ifname" == "lo" || "$ifname" == veth* || "$ifname" == docker* || "$ifname" == br-* ]]; then continue; fi
        mac=$(cat "$iface/address" 2>/dev/null)
        if [ -n "$mac" ] && [ "$mac" != "00:00:00:00:00:00" ]; then
            printf " %2d. %-15s [%s]\n" "$idx" "$ifname" "$mac"
            IFACE_LIST[$idx]="$ifname"
            idx=$((idx+1))
        fi
    done
    PRINT_SEP "-"
    printf "Select interface index: "
    
    if ! read -t 45 -r IFACE_SEL < /dev/tty; then
        echo -e "\n"
        tprint "Input timeout (45s). Aborting."
        exit 1
    fi
    
    TARGET_INTERFACE="${IFACE_LIST[$IFACE_SEL]}"
    echo ""
    if [ -z "$TARGET_INTERFACE" ]; then
        tprint "Error: Invalid selection."
        exit 1
    fi
fi

TARGET_MAC=$(cat "/sys/class/net/$TARGET_INTERFACE/address" 2>/dev/null)
if [ -z "$TARGET_MAC" ] || [ "${#TARGET_MAC}" -ne 17 ]; then
    tprint "Error: Valid MAC address not found on $TARGET_INTERFACE."
    exit 1
fi
lprint "Selected interface: $TARGET_INTERFACE ($TARGET_MAC)"

DRAW_HEADER
tprint "Optimizing network interface..."

CURRENT_MTU=$(cat "/sys/class/net/$TARGET_INTERFACE/mtu" 2>/dev/null || echo "1500")
if [ "$CURRENT_MTU" -lt 1512 ]; then
    ORIGINAL_MTU="$CURRENT_MTU"
    ip link set dev "$TARGET_INTERFACE" mtu 1512 >/dev/null 2>&1
    STATE_MTU_CHANGED=1
    tprint "MTU temporarily increased to 1512"
else
    tprint "MTU optimization skipped (already $CURRENT_MTU)"
fi

if ethtool -k "$TARGET_INTERFACE" 2>/dev/null | grep -q "rx-vlan-offload: on"; then
    ethtool -K "$TARGET_INTERFACE" rxvlan off >/dev/null 2>&1
    STATE_RX_CHANGED=1
    tprint "Hardware RX-VLAN offload temporarily disabled"
else
    tprint "RX-VLAN offload already disabled"
fi

PYTHON_PAYLOAD="$_VLAN_WORKSPACE/probe.py"

cat << 'EOF' > "$PYTHON_PAYLOAD"
import os, threading, queue, time, sys, binascii, signal, textwrap, random
from scapy.all import Ether, Dot1Q, PPPoED, IP, UDP, BOOTP, DHCP, sendp, AsyncSniffer, conf

PDLY = 0.125
UI_W = int(os.getenv('UI_W', 64))
BLEN = max(10, UI_W - 35)

conf.verb = 0
REQQ = queue.Queue()
VLAN_Q = queue.Queue()
STOP = threading.Event()
PLCK = threading.Lock()
CPLT = 0

def tstamp(): return f"[{time.strftime('%H:%M:%S')}]"

def tprint(msg): 
    prefix = tstamp() + " "
    wrapper = textwrap.TextWrapper(width=UI_W, initial_indent=prefix, subsequent_indent=" " * len(prefix))
    sys.stdout.write(wrapper.fill(msg) + "\n")
    sys.stdout.flush()

def rprint(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()

def handle_interrupt(sig, frame):
    if not STOP.is_set():
        STOP.set()

signal.signal(signal.SIGINT, handle_interrupt)
signal.signal(signal.SIGTERM, handle_interrupt)

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

def PROG(TOTL):
    sys.stdout.write("\n")
    sys.stdout.flush()
    
    try:
        tty = open('/dev/tty', 'w')
    except:
        tty = sys.stdout

    while not STOP.is_set() and CPLT < TOTL:
        CURR = CPLT
        ratio = (CURR / TOTL) if TOTL else 0
        PCTT = int(ratio * 100)
        FILL = int(ratio * BLEN)
        BARR = '#' * FILL + '-' * (BLEN - FILL)
        tty.write(f"\rVLAN {CURR}/{TOTL} [{BARR}] {PCTT}% Completed")
        tty.flush()
        time.sleep(0.125)

    tty.write(f"\r{' ' * UI_W}\r")
    tty.flush()
    
    if tty is not sys.stdout:
        tty.close()

    MSG = "VLAN Probing Successful" if CPLT >= TOTL else "VLAN Probing Terminated"
    sys.stdout.write(f"{tstamp()} {MSG}\n")
    sys.stdout.flush()
    
def WRKR(IFCE, HMAC):
    global CPLT
    
    while not STOP.is_set():
        try:
            VVVV = VLAN_Q.get_nowait()
        except queue.Empty:
            break
            
        BASE = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff")
        BPPP = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff", type=0x8863)
        PPPP = PPPoED(version=1, type=1, code=0x09, sessionid=0)
        
        if VVVV > 0:
            PKTS = [BASE/Dot1Q(vlan=VVVV, type=0x8863)/PPPP]
        else:
            PKTS = [BPPP/PPPP]
        
        sendp(PKTS, iface=IFCE, verbose=0)
        with PLCK:
            CPLT += 1
            
        VLAN_Q.task_done()
        
        if PDLY > 0:
            target = time.time() + PDLY
            while time.time() < target:
                if STOP.is_set(): return
                time.sleep(0.0125)

def MAIN():
    IFCE = sys.argv[1]
    HMAC = sys.argv[2]
    VLAN_ARG = sys.argv[3] if len(sys.argv) > 3 else ""

    if VLAN_ARG:
        if '-' in VLAN_ARG:
            try:
                parts = VLAN_ARG.split('-')
                x, y = int(parts[0]), int(parts[1])
                VRGG = list(range(min(x, y), max(x, y) + 1))
            except:
                VRGG = list(range(0, 4096))
        else:
            try:
                VRGG = [int(VLAN_ARG)]
            except:
                VRGG = list(range(0, 4096))
    else:
        VRGG = list(range(0, 4096))

    TVLN = len(VRGG)
    for v in VRGG: VLAN_Q.put(v)
    
    cpu_cores = os.cpu_count() or 1
    CFTR = max(8, cpu_cores * 8)

    tprint(f"Starting packet sniffer on {IFCE}...")
    SNFF = AsyncSniffer(iface=IFCE, prn=CBBK, store=0)
    SNFF.start()
    time.sleep(0.0125)

    # Send a single untagged DHCP Discover Broadcast before starting the VLAN loop
    tprint("Sending initial untagged DHCP broadcast...")
    MAC_B = binascii.unhexlify(HMAC.replace(':', ''))
    XID = random.randint(1, 0xFFFFFFFF)
    BASE_ETH = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff")
    BDHCP = IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=MAC_B, xid=XID)/DHCP(options=[("message-type", "discover"), "end"])
    sendp(BASE_ETH/BDHCP, iface=IFCE, verbose=0)

    tprint(f"Spawning {CFTR} concurrent threads...")
    
    THDS = []
    for _ in range(CFTR):
        THRD = threading.Thread(target=WRKR, args=(IFCE, HMAC))
        THRD.daemon = True
        THRD.start()
        THDS.append(THRD)
        
    TMON = threading.Thread(target=PROG, args=(TVLN,))
    TMON.daemon = True
    TMON.start()
    
    while any(t.is_alive() for t in THDS):
        if STOP.is_set(): break
        time.sleep(0.125)
    
    if not STOP.is_set():
        global CPLT
        CPLT = TVLN
        time.sleep(0.125)
        tprint("Awaiting network responses...")
        for _ in range(30):
            if STOP.is_set(): break
            time.sleep(0.125)

    STOP.set()
    if TMON.is_alive():
        TMON.join()
    SNFF.stop()

    DATA = {}
    while not REQQ.empty():
        ITEM = REQQ.get()
        DATA[f"{ITEM['vvvv']}-{ITEM['pppp']}-{ITEM['nnnn']}"] = ITEM

    # --- DYNAMIC PADDING & LAYOUT CALCULATION ---
    max_v = max([4] + [len(str(v['vvvv'])) for v in DATA.values()])
    max_p = max([5] + [len(v['pppp']) for v in DATA.values()])
    max_t = max([4] + [len(v['tttt']) for v in DATA.values()])
    max_m = 17 # Fixed length for MAC addresses, header is 11.
    max_i = max([8] + [len(v['nnnn']) for v in DATA.values()])

    total_fixed = max_v + max_p + max_t + max_m
    min_gaps = 4

    # Enforce constraints if Identity width pushes past UI bounds
    if total_fixed + max_i + min_gaps > UI_W:
        max_i = max(8, UI_W - total_fixed - min_gaps)

    # Calculate remaining space and evenly distribute among 4 gaps
    rem_space = UI_W - (total_fixed + max_i)
    b_gap = rem_space // 4
    rem_gap = rem_space % 4

    g1 = " " * (b_gap + (1 if rem_gap > 0 else 0))
    g2 = " " * (b_gap + (1 if rem_gap > 1 else 0))
    g3 = " " * (b_gap + (1 if rem_gap > 2 else 0))
    g4 = " " * b_gap

    H_FMT = f"{{:<{max_v}}}{g1}{{:<{max_p}}}{g2}{{:<{max_t}}}{g3}{{:<{max_i}}}{g4}{{:>{max_m}}}"

    sys.stdout.write("\n\n")
    rprint("DISCOVERY RESULTS")
    rprint("-" * UI_W)
    rprint(H_FMT.format('VLAN', 'PROTO', 'TYPE', 'IDENTITY', 'MAC ADDRESS'))
    rprint("-" * UI_W)
    
    if not DATA: 
        rprint("No services detected.")
    else:
        SKKK = sorted(DATA.keys(), key=lambda XXXX: (int(XXXX.split('-')[0]), XXXX.split('-')[1]))
        for KKKK in SKKK:
            DDDD = DATA[KKKK]
            IDEN_STR = DDDD['nnnn'][:max_i]
            rprint(H_FMT.format(str(DDDD['vvvv']), DDDD['pppp'], DDDD['tttt'], IDEN_STR, DDDD['mmmm']))
            
    rprint("-" * UI_W + "\n")

if __name__ == "__main__":
    MAIN()
EOF

trap '' SIGINT

echo ""
PYTHONUNBUFFERED=1 "$PYTHON_EXEC" "$PYTHON_PAYLOAD" "$TARGET_INTERFACE" "$TARGET_MAC" "$TARGET_VLAN" 2>&1 | tee -a "$LOG_FILE"
