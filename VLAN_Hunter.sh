#!/usr/bin/env bash

# Title:        VLAN Hunter
# Author:       sussyflow
# Copyright:    (c) 2025-2026 sussyflow
# License:      GNU General Public License v3.0
# Description:  Reliable VLAN Discovery Tool for Linux

export PYTHONDONTWRITEBYTECODE=1

set -o pipefail
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
PPS_RATE=250

L=1
M=3
H=5

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -a|--auto) AUTO_FETCH=1; shift ;;
        -i|--interface) TARGET_INTERFACE="$2"; shift 2 ;;
        -v|--vlan) 
            if [[ "$2" == *","* ]]; then
                echo "Error: Comma separated values not allowed for VLAN."
                sleep $M
                exit 1
            fi
            TARGET_VLAN="$2"; shift 2 ;;
        --accept) AUTO_ACCEPT=1; shift ;;
        *) shift ;;
    esac
done
export PPS_RATE

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

    if [ "$SHOW_DETAILS" = "1" ]; then
        echo ""
        echo "INTERFACE: $TARGET_INTERFACE"
        echo "MAC ADDRESS: $TARGET_MAC"
        echo "TARGET VLAN(s): ${TARGET_VLAN:-ALL}"
        echo ""
    else
        echo ""
    fi
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
    echo ""
    tprint "Restoring system state..."

    local RESTORE_FAIL=0
    if [ "$STATE_MTU_CHANGED" -eq 1 ] && [ -n "$TARGET_INTERFACE" ] && [ -n "$ORIGINAL_MTU" ]; then
        if ! ip link set dev "$TARGET_INTERFACE" mtu "$ORIGINAL_MTU" >/dev/null 2>&1; then
            RESTORE_FAIL=1
        fi
    fi
    
    if [ "$STATE_RX_CHANGED" -eq 1 ] && [ -n "$TARGET_INTERFACE" ]; then
        if ! ethtool -K "$TARGET_INTERFACE" rxvlan on >/dev/null 2>&1; then
            RESTORE_FAIL=1
        fi
    fi

    if [ "$RESTORE_FAIL" -eq 0 ]; then
        tprint "System state restored."
    else
        tprint "System state restoration failed."
    fi

    tprint "Cleanup started."
    if [ -n "$_VLAN_WORKSPACE" ] && [ -d "$_VLAN_WORKSPACE" ] && [ "$_VLAN_WORKSPACE" != "/" ]; then
        rm -rf "$_VLAN_WORKSPACE"
    fi
    
    stty echoctl < /dev/tty 2>/dev/null
    tprint "Cleanup complete."
    
    echo ""
    echo "Log: $LOG_FILE"
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
                sleep $M
                exit 1
            fi
        done
        
        for cmd in "${MISSING_CMDS[@]}"; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                tprint "Critical Error: '$cmd' is still missing after installation attempt."
                sleep $M
                exit 1
            fi
        done
        tprint "All missing command dependencies successfully resolved."
    else
        tprint "Critical Error: Missing required system commands: ${MISSING_CMDS[*]}"
        tprint "Run with -a or --auto to automatically resolve these dependencies."
        sleep $M
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
sleep $M

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
    
    if ! read -t 30 -r TERMS_ACCEPT < /dev/tty; then
        echo -e "\n"
        tprint "Input timeout (30s). Aborting."
        exit 1
    fi

    if [ "${TERMS_ACCEPT^^}" != "ACCEPT" ]; then 
        echo ""
        tprint "Authorization declined. Aborting."
        sleep $M
        exit 1
    fi
    echo ""
fi
clear
lprint "Terms accepted."

CLI_INT_PASSED=0; [ -n "$TARGET_INTERFACE" ] && CLI_INT_PASSED=1
CLI_VLAN_PASSED=0; [ -n "$TARGET_VLAN" ] && CLI_VLAN_PASSED=1

# ==============================================================================
# UPDATED INTERACTIVE SELECTION LOOP (CLEANED)
# ==============================================================================
INVALID_COUNT=0
MAX_STRIKES=3

while true; do
    DRAW_HEADER

    [ "$CLI_INT_PASSED" -eq 0 ] && TARGET_INTERFACE=""
    [ "$CLI_VLAN_PASSED" -eq 0 ] && TARGET_VLAN=""
    
    if [ $INVALID_COUNT -ge $MAX_STRIKES ]; then
        echo ""
        tprint "Too many consecutive invalid inputs. Exiting script."
        sleep $M
        exit 1
    fi

    # ---------------------------------------------
    # STAGE 1: Interface Selection (Only run if not passed via CLI)
    # ---------------------------------------------
    if [ -z "$TARGET_INTERFACE" ]; then
        cprint "--- [Stage 1] Available Network Interfaces ---"
        declare -a IFACE_LIST
        idx=1
        for iface in /sys/class/net/*; do
            ifname=$(basename "$iface")
            [[ "$ifname" == "lo" || "$ifname" == veth* || "$ifname" == docker* || "$ifname" == br-* ]] && continue
            mac=$(cat "$iface/address" 2>/dev/null)
            if [ -n "$mac" ] && [ "$mac" != "00:00:00:00:00:00" ]; then
                printf "  %2d. %-15s [%s]\n" "$idx" "$ifname" "$mac"
                IFACE_LIST[$idx]="$ifname"
                idx=$((idx+1))
            fi
        done
        echo ""
        printf "Select interface index: "
        if ! read -t 30 -r IFACE_SEL < /dev/tty || [ -z "${IFACE_LIST[$IFACE_SEL]}" ]; then
            echo ""
            tprint "Invalid interface choice (or input timeout)."
            ((INVALID_COUNT++))
            sleep $L
            clear
            continue
        fi
        TARGET_INTERFACE="${IFACE_LIST[$IFACE_SEL]}"
        sleep $L
    fi

    TARGET_MAC_ACTUAL=$(cat "/sys/class/net/$TARGET_INTERFACE/address" 2>/dev/null)

    # ---------------------------------------------
    # STAGE 2: MAC Selection
    # ---------------------------------------------
    DRAW_HEADER
    cprint "--- [Stage 2] Select MAC Address Type ---"
    printf "  1. Use Hardware Interface MAC\n"
    printf "  2. Randomly Generated MAC [Default]\n"
    printf "  3. Custom MAC\n"
    echo ""
    printf "Select option [1-3]: "
    
    if ! read -t 30 -r MAC_SEL < /dev/tty; then
        echo ""
        tprint "Input timeout."
        ((INVALID_COUNT++))
        sleep $L
        clear
        continue
    fi
    
    [ -z "$MAC_SEL" ] && MAC_SEL=2

    if [ "$MAC_SEL" -eq 1 ]; then
        TARGET_MAC="$TARGET_MAC_ACTUAL"
    elif [ "$MAC_SEL" -eq 2 ]; then
        TARGET_MAC="02:$(printf '%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
    elif [ "$MAC_SEL" -eq 3 ]; then
        printf "Enter custom MAC address: "
        read -r USER_MAC < /dev/tty
        CLEAN_MAC=$(echo "$USER_MAC" | sed 's/[: -]//g' | tr '[:upper:]' '[:lower:]')
        if [[ ! "$CLEAN_MAC" =~ ^[0-9a-f]{12}$ ]]; then
            echo ""
            tprint "Invalid MAC layout formatting."
            ((INVALID_COUNT++))
            sleep $L
            clear
            continue
        fi
        TARGET_MAC=$(echo "$CLEAN_MAC" | sed 's/\(..\)/\1:/g;s/.$//')
    else
        echo ""
        tprint "Invalid selection."
        ((INVALID_COUNT++))
        sleep $L
        clear
        continue
    fi
    sleep $L
    clear

    # ---------------------------------------------
    # STAGE 3: VLAN Selection (Only run if not passed via CLI)
    # ---------------------------------------------
    STAGE3_READY=1
    if [ -z "$TARGET_VLAN" ]; then
        DRAW_HEADER        
        cprint "--- [Stage 3] VLAN Scope Config ---"
        echo ""
        printf "Enter target VLAN string (e.g., '5', '10-500', or leave blank for ALL): "
        if ! read -t 30 -r USER_VLAN < /dev/tty; then
            echo ""
            tprint "Input timeout."
            ((INVALID_COUNT++))
            sleep $L
            clear
            continue
        fi
        if [[ "$USER_VLAN" == *","* ]]; then
            echo ""
            tprint "Error: Comma notation is restricted. Use range or specific ID."
            ((INVALID_COUNT++))
            sleep $L
            clear
            continue
        fi
        TARGET_VLAN="$USER_VLAN"
        clear
    fi

    break
done
sleep $L

SHOW_DETAILS=1

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
    tprint "Hardware RX/TX-VLAN offload temporarily disabled"
else
    tprint "Hardware RX/TX-VLAN offload already disabled"
fi

tprint "Network interface optimization complete"
echo ""

PYTHON_PAYLOAD="$_VLAN_WORKSPACE/probe.py"

cat << 'EOF' > "$PYTHON_PAYLOAD"
import os, threading, queue, time, sys, binascii, signal, textwrap, random
from scapy.all import Ether, Dot1Q, PPPoED, IP, UDP, BOOTP, DHCP, sendp, AsyncSniffer, conf
from scapy.arch.linux import L2Socket

IFCE = sys.argv[1] if len(sys.argv) > 1 else ""
HMAC = sys.argv[2] if len(sys.argv) > 2 else ""

PPS = int(os.getenv('PPS_RATE', '125'))
PDLY = 1.0 / (PPS + 1)

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
        if PKTT.haslayer(Ether) and PKTT[Ether].src.lower() == HMAC.lower():
            return
            
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
        try:
            BARR = '█' * FILL + '░' * (BLEN - FILL)
        except UnicodeEncodeError:
            BARR = '#' * FILL + '-' * (BLEN - FILL)
        tty.write(f"\rVLAN {CURR}/{TOTL} [{BARR}] {PCTT}% Completed")
        tty.flush()
        time.sleep(0.125)

    tty.write(f"\r{' ' * UI_W}\r")
    tty.flush()
    
    if tty is not sys.stdout:
        tty.close()

    MSG = "VLAN Probing Completed" if CPLT >= TOTL else "VLAN Probing Terminated"
    sys.stdout.write(f"{tstamp()} {MSG}\n")
    sys.stdout.flush()

def RUN_SCAN(IFCE, HMAC):
    global CPLT
    try:
        L2_sock = L2Socket(iface=IFCE)
    except Exception as e:
        tprint(f"Socket Error: {e}")
        return

    BASE = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff")
    BPPP = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff", type=0x8863)
    PPPP = PPPoED(version=1, type=1, code=0x09, sessionid=0)
    
    MAC_B = binascii.unhexlify(HMAC.replace(':', ''))
    XID = random.randint(1, 0xFFFFFFFF)
    BDHCP_BASE = IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=MAC_B, xid=XID)/DHCP(options=[("message-type", "discover"), "end"])

    K = 500
    tx_buffer = []

    def bake_batch(buf, limit, q, b_ether, b_ppp, p_ppp, b_dhcp):
        baked = 0
        while baked < limit and not q.empty():
            try:
                VVVV = q.get_nowait()
                if VVVV > 0:
                    buf.append((bytes(b_ether/Dot1Q(vlan=VVVV, type=0x8863)/p_ppp), 0))
                    buf.append((bytes(b_ether/Dot1Q(vlan=VVVV, type=0x0800)/b_dhcp), 1))
                else:
                    buf.append((bytes(b_ppp/p_ppp), 1))
                baked += 1
            except queue.Empty:
                break

    bake_batch(tx_buffer, K, VLAN_Q, BASE, BPPP, PPPP, BDHCP_BASE)

    while not STOP.is_set() and (tx_buffer or not VLAN_Q.empty()):
        if len(tx_buffer) <= int(K * 0.5):
            bake_batch(tx_buffer, K, VLAN_Q, BASE, BPPP, PPPP, BDHCP_BASE)

        if not tx_buffer:
            break

        pkt, is_complete = tx_buffer.pop(0)

        try:
            L2_sock.send(pkt)
        except:
            pass

        if is_complete:
            CPLT += 1
            VLAN_Q.task_done()

        if PDLY > 0:
            time.sleep(PDLY)
            
    L2_sock.close()
    
def MAIN():
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
    
    KFILT = "ether proto 0x8863 or (udp and port 68)"
    SNFF = AsyncSniffer(iface=IFCE, filter=KFILT, prn=CBBK, store=0)
    SNFF.start()
    time.sleep(0.0125)
    tprint("VLAN Probing Started")

    MAC_B = binascii.unhexlify(HMAC.replace(':', ''))
    XID = random.randint(1, 0xFFFFFFFF)
    BASE_ETH = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff")
    BDHCP = IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=MAC_B, xid=XID)/DHCP(options=[("message-type", "discover"), "end"])
    sendp(BASE_ETH/BDHCP, iface=IFCE, verbose=0)

    TMON = threading.Thread(target=PROG, args=(TVLN,))
    TMON.daemon = True
    TMON.start()

    RUN_SCAN(IFCE, HMAC)
    
    while TMON.is_alive():
        if STOP.is_set(): break
        time.sleep(0.125)
    
    if not STOP.is_set():
        global CPLT
        CPLT = TVLN
        time.sleep(0.125)
        tprint("Awaiting responses...")
        time.sleep(5.0)

    STOP.set()
    if TMON.is_alive():
        TMON.join()
    SNFF.stop()

    DATA = {}
    while not REQQ.empty():
        ITEM = REQQ.get()
        DATA[f"{ITEM['vvvv']}-{ITEM['pppp']}-{ITEM['nnnn']}"] = ITEM

    if not DATA:
        max_v, max_p, max_t, max_m, max_i = 4, 5, 4, 17, 8
    else:
        max_v = max([4] + [len(str(v['vvvv'])) for v in DATA.values()])
        max_p = max([5] + [len(v['pppp']) for v in DATA.values()])
        max_t = max([4] + [len(v['tttt']) for v in DATA.values()])
        max_m = 17 
        max_i = max([8] + [len(v['nnnn']) for v in DATA.values()])

    total_fixed = max_v + max_p + max_t + max_m
    min_gaps = 4

    if total_fixed + max_i + min_gaps > UI_W:
        max_i = max(8, UI_W - total_fixed - min_gaps)

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
