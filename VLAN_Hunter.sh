#!/usr/bin/env bash

# Title:        VLAN Hunter
# Author:       sussyflow
# Copyright:    (c) 2025-2026 sussyflow
# License:      GNU General Public License v3.0
# Description:  Reliable VLAN Discovery Tool for Linux

# Configuration
export MAX_STRIKES=3
export BURST_RATE=10
export BURST_PER_SEC=10
export PASSIVE_TIMEOUT_SEC=900
export MENU_TIMEOUT_SEC=45
export TARGET_MTU=1512
export LATE_RESPONSE_WAIT=3
export PYTHONDONTWRITEBYTECODE=1

WDTH=64
export UI_W=$WDTH
SHOW_DETAILS=0
PYTHON_EXEC="python3"

set -o pipefail
stty -echoctl < /dev/tty 2>/dev/null

BASE_DIR=""
for d in "/run" "/tmp" "/home"; do
    if [[ -d "$d" && -w "$d" ]]; then
        BASE_DIR="$d"
        break
    fi
done

[[ -z "$BASE_DIR" ]] && { echo "Error: No writable directory found."; sleep 1; exit 1; }

export _VLAN_WORKSPACE=$(mktemp -d "$BASE_DIR/VLAN-XXXXXX" 2>/dev/null)
USER_HOME=$(eval echo "~${SUDO_USER:-$USER}")
[[ -z "$USER_HOME" ]] && USER_HOME="/root"

LOG_FILE="$USER_HOME/VLAN_Hunter_Execution.log"
[[ -d "$USER_HOME/Desktop" && -w "$USER_HOME/Desktop" ]] && LOG_FILE="$USER_HOME/Desktop/VLAN_Hunter_Execution.log"
touch "$LOG_FILE" 2>/dev/null

T_COLS=$(tput cols 2>/dev/null || echo "$WDTH")
UI_W=$(( T_COLS > WDTH ? WDTH : T_COLS ))

AUTO_FETCH=0
ACCEPT_TNC=0
TARGET_INTERFACE=""
TARGET_MAC=""
TARGET_VLAN=""
PROBE_MODE=""
PROTO_PPPOE=0
PROTO_DHCP=0
PROTO_IGMP=0
CLI_INT_PASSED=0
CLI_MAC_PASSED=0
CLI_PROTO_PASSED=0
CLI_MODE_PASSED=0
CLI_VLAN_PASSED=0

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -i|--interface) TARGET_INTERFACE="$2"; CLI_INT_PASSED=1; shift 2 ;;
        -m|--mac)
            CMAC=$(echo "$2" | sed 's/[: -]//g' | tr '[:upper:]' '[:lower:]')
            [[ ! "$CMAC" =~ ^[0-9a-f]{12}$ ]] && echo "Error: Invalid MAC format." && exit 1
            TARGET_MAC=$(echo "$CMAC" | sed 's/\(..\)/\1:/g;s/.$//')
            CLI_MAC_PASSED=1; shift 2 ;;
        -v|--vlan) 
            [[ "$2" == *","* ]] && echo "Error: Commas not allowed for VLAN." && exit 1
            TARGET_VLAN="$2"; CLI_VLAN_PASSED=1; shift 2 ;;
        --auto) AUTO_FETCH=1; shift ;;
        --pppoe) PROTO_PPPOE=1; CLI_PROTO_PASSED=1; shift ;;
        --dhcp) PROTO_DHCP=1; CLI_PROTO_PASSED=1; shift ;;
        --igmp) PROTO_IGMP=1; CLI_PROTO_PASSED=1; shift ;;
        --active) PROBE_MODE=1; CLI_MODE_PASSED=1; shift ;;
        --passive) PROBE_MODE=2; TARGET_VLAN="ALL"; CLI_MODE_PASSED=1; shift ;;
        --accept) ACCEPT_TNC=1; shift ;;
        *) shift ;;
    esac
done

[[ "$CLI_PROTO_PASSED" -eq 0 ]] && PROTO_PPPOE=1

declare -a INSTALLED_PKGS=()
PKG_UPDATED=0
declare -A PKGMGRS=(
    ["apt-get"]="DEBIAN_FRONTEND=noninteractive apt-get install -y"
    ["dnf"]="dnf install -y"
    ["yum"]="yum install -y"
    ["pacman"]="pacman -S --noconfirm"
    ["zypper"]="zypper install -y"
    ["apk"]="apk add --no-interactive"
)

for mgr in "${!PKGMGRS[@]}"; do
    if command -v "$mgr" >/dev/null 2>&1; then
        PKG_MGR="$mgr"
        PKG_INSTALL="${PKGMGRS[$mgr]}"
        break
    fi
done

APP_TITLE=$([[ "$AUTO_FETCH" -eq 1 ]] && echo "VLAN HUNTER PRO" || echo "VLAN HUNTER")
APP_AUTHOR="By Sussyflow (https://github.com/sussyflow)"

PRINT_SEP() { printf "%${UI_W}s\n" "" | tr ' ' "$1"; }
PRINT_CENTER() {
    local pad=$(( (UI_W - ${#1}) / 2 ))
    printf "%*s%s\n" $((pad < 0 ? 0 : pad)) "" "$1"
}

DRAW_HEADER() {
    clear
    PRINT_SEP "="
    PRINT_CENTER "$APP_TITLE"
    PRINT_CENTER "$APP_AUTHOR"
    PRINT_SEP "="
    echo ""
}

tprint() { echo "[$(date +%H:%M:%S)] $1" | tee -a "$LOG_FILE"; }
cprint() { echo "$1" | tee -a "$LOG_FILE"; }

auto_install_pkg() {
    [[ "$AUTO_FETCH" -ne 1 || -z "$PKG_MGR" ]] && return 1
    [[ " ${INSTALLED_PKGS[*]} " =~ " $1 " ]] && return 0
    if [[ "$PKG_UPDATED" -eq 0 ]]; then
        tprint "Updating package manager indices..."
        case "$PKG_MGR" in
            apt-get) apt-get update -q -y >/dev/null 2>&1 ;;
            apk) apk update -q >/dev/null 2>&1 ;;
            pacman) pacman -Sy --noconfirm >/dev/null 2>&1 ;;
            zypper) zypper refresh >/dev/null 2>&1 ;;
        esac
        PKG_UPDATED=1
    fi
    tprint "Auto-installing globally: $1"
    eval "$PKG_INSTALL $1" >/dev/null 2>&1 && INSTALLED_PKGS+=("$1") || return 1
}

STATE_MTU_CHANGED=0
STATE_RX_CHANGED=0
CLEANED=0
ORIGINAL_MTU=""

cleanup() {
    local exit_code=$?
    [[ "$CLEANED" -eq 1 ]] && return
    CLEANED=1
    echo ""
    tprint "Restoring system state..."
    local R_FAIL=0
    
    [[ "$STATE_MTU_CHANGED" -eq 1 ]] && ! ip link set dev "$TARGET_INTERFACE" mtu "$ORIGINAL_MTU" >/dev/null 2>&1 && R_FAIL=1
    [[ "$STATE_RX_CHANGED" -eq 1 ]] && ! ethtool -K "$TARGET_INTERFACE" rxvlan on >/dev/null 2>&1 && R_FAIL=1
    
    [[ "$R_FAIL" -eq 0 ]] && tprint "System state restored." || tprint "System state restoration failed."
    tprint "Cleanup started."
    [[ -n "$_VLAN_WORKSPACE" && "$_VLAN_WORKSPACE" != "/" ]] && rm -rf "$_VLAN_WORKSPACE"
    stty echoctl < /dev/tty 2>/dev/null
    tprint "Cleanup complete."
    echo -e "\nLog: $LOG_FILE"
    sleep 1
    exit "$exit_code"
}
trap cleanup EXIT SIGINT SIGTERM HUP QUIT

INVALID_COUNT=0

handle_invalid() {
    tprint "$1"
    ((INVALID_COUNT++))
    [[ "$INVALID_COUNT" -ge "$MAX_STRIKES" ]] && { tprint "Too many invalid inputs. Exiting."; exit 1; }
    sleep 1
}

[[ "$EUID" -ne 0 ]] && { tprint "Error: Root privileges required."; sleep 1; exit 1; }

if [[ "$ACCEPT_TNC" -eq 0 ]]; then
    DRAW_HEADER
    PRINT_CENTER "TERMS OF USE"
    echo ""
    
    justify_print() {
        local text="$1"
        echo "$text" | nroff -W"$UI_W" -Tascii 2>/dev/null | grep -v '^[[:space:]]*$' | while read -r line; do
            cprint "$line"
        done
    }

    justify_print "VLAN Hunter probes network segments to identify active 802.1Q VLANs and map service delivery such as Internet, IPTV, or VoIP without permanently altering host configurations."
    echo ""
    justify_print "The utility temporarily modifies network hardware and MTU settings for deep packet inspection. While the script is designed to revert all changes and purge artifacts upon exit, users acknowledge this activity is visible to upstream monitors and may be recorded."
    echo ""
    justify_print "By proceeding, you assume full responsibility for any resulting network consequences. The author is held harmless from all liability regarding operational disruptions, and you acknowledge that improper termination may necessitate manual restoration of your network interface."
    
    PRINT_SEP "-"
    printf "Enter 'ACCEPT' to acknowledge and proceed: "
    
    if ! read -t 30 -r TERMS_ACCEPT < /dev/tty; then
        echo -e "\n"
        tprint "Input timeout (30s). Aborting."
        exit 1
    fi

    if [[ "${TERMS_ACCEPT^^}" != "ACCEPT" ]]; then
        echo ""
        tprint "Terms not accepted. Aborting."
        exit 1
    fi
fi

DRAW_HEADER
tprint "Starting VLAN Hunter..."
tprint "Running robust preflight checks..."

MISSING_CMDS=()
for cmd in python3 ip ethtool mktemp tput clear cat grep stty date touch; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING_CMDS+=("$cmd")
done

if [[ ${#MISSING_CMDS[@]} -gt 0 ]]; then
    [[ "$AUTO_FETCH" -ne 1 ]] && { tprint "Critical Error: Missing ${MISSING_CMDS[*]}. Run with --auto to resolve."; exit 1; }
    for cmd in "${MISSING_CMDS[@]}"; do
        pkg="$cmd"
        case "$cmd" in
            ip) pkg="iproute2" ;;
            mktemp|cat|stty|date|touch) pkg="coreutils" ;;
            tput|clear) 
                pkg="ncurses-bin"
                [[ "$PKG_MGR" =~ (pacman|apk) ]] && pkg="ncurses"
                ;;
            python3) [[ "$PKG_MGR" == "apk" ]] && pkg="python3" ;;
        esac
        auto_install_pkg "$pkg" || { tprint "Error: Failed to auto-install $pkg."; exit 1; }
    done
    for cmd in "${MISSING_CMDS[@]}"; do 
        command -v "$cmd" >/dev/null 2>&1 || { tprint "Error: '$cmd' still missing."; exit 1; }
    done
    tprint "Dependencies resolved."
fi

if ! "$PYTHON_EXEC" -c "import scapy" >/dev/null 2>&1; then
    tprint "Missing Scapy."
    [[ "$AUTO_FETCH" -ne 1 ]] && { tprint "Requires Scapy. Use --auto to auto-fetch."; exit 1; }
    SCAPY_PKG="python3-scapy"
    [[ "$PKG_MGR" == "pacman" ]] && SCAPY_PKG="python-scapy"
    [[ "$PKG_MGR" == "apk" ]] && SCAPY_PKG="py3-scapy"
    
    auto_install_pkg "$SCAPY_PKG" && "$PYTHON_EXEC" -c "import scapy" >/dev/null 2>&1 || { tprint "Error: Failed to install Scapy."; exit 1; }
else
    tprint "Found Scapy."
fi
sleep 1

if [[ "$CLI_INT_PASSED" -eq 0 ]]; then
    while true; do
        DRAW_HEADER
        cprint "--- [Stage 1] Network Interfaces ---"
        echo ""
        declare -a IFACE_LIST
        idx=1
        for iface in /sys/class/net/*; do
            ifname=$(basename "$iface")
            [[ "$ifname" =~ ^(lo|veth|docker|br-) ]] && continue
            mac=$(cat "$iface/address" 2>/dev/null)
            if [[ -n "$mac" && "$mac" != "00:00:00:00:00:00" ]]; then
                printf "  %2d. %-15s [%s]\n" "$idx" "$ifname" "$mac"
                IFACE_LIST[$idx]="$ifname"
                ((idx++))
            fi
        done
        echo ""
        printf "Select interface index: "
        read -t "$MENU_TIMEOUT_SEC" -r IFACE_SEL < /dev/tty || { echo -e "\nTimeout reached. Exiting."; exit 1; }
        if [[ -n "${IFACE_LIST[$IFACE_SEL]}" ]]; then
            TARGET_INTERFACE="${IFACE_LIST[$IFACE_SEL]}"
            break
        else
            handle_invalid "Invalid choice."
        fi
    done
fi

TARGET_MAC_ACTUAL=$(cat "/sys/class/net/$TARGET_INTERFACE/address" 2>/dev/null)

if [[ "$CLI_MODE_PASSED" -eq 0 ]]; then
    while true; do
        DRAW_HEADER
        cprint "--- [Stage 2] Probe Mode ---"
        echo ""
        printf "  1. Active (Inject and Sniff) [Default]\n  2. Passive (Sniff Only)\n\nSelect option [1-2]: "
        read -t "$MENU_TIMEOUT_SEC" -r MODE_SEL < /dev/tty || { echo -e "\nTimeout reached. Exiting."; exit 1; }
        case "${MODE_SEL:-1}" in
            1) PROBE_MODE=1; break ;;
            2) PROBE_MODE=2; TARGET_VLAN="ALL"; break ;;
            *) handle_invalid "Invalid selection." ;;
        esac
    done
else
    [[ "$PROBE_MODE" == "active" ]] && PROBE_MODE=1
    [[ "$PROBE_MODE" == "passive" ]] && PROBE_MODE=2
fi

if [[ "$PROBE_MODE" -eq 1 || "$PROBE_MODE" == "active" ]]; then
    if [[ "$CLI_PROTO_PASSED" -eq 0 ]]; then
        while true; do
            DRAW_HEADER
            cprint "--- [Stage 3] Protocols ---"
            echo ""
            printf "  1. PPPoE  [%s]\n" "$([[ "$PROTO_PPPOE" -eq 1 ]] && echo ENABLED || echo SKIP)"
            printf "  2. DHCP   [%s]\n" "$([[ "$PROTO_DHCP" -eq 1 ]] && echo ENABLED || echo SKIP)"
            printf "  3. IGMP   [%s]\n\n" "$([[ "$PROTO_IGMP" -eq 1 ]] && echo ENABLED || echo SKIP)"
            printf "Toggle [1-3] or press ENTER to proceed: "
            read -t "$MENU_TIMEOUT_SEC" -r P_SEL < /dev/tty || { echo -e "\nTimeout reached. Exiting."; exit 1; }
            case "$P_SEL" in
                1) PROTO_PPPOE=$((1 - PROTO_PPPOE)) ;;
                2) PROTO_DHCP=$((1 - PROTO_DHCP)) ;;
                3) PROTO_IGMP=$((1 - PROTO_IGMP)) ;;
                "") 
                    if [[ "$PROTO_PPPOE" -eq 0 && "$PROTO_DHCP" -eq 0 && "$PROTO_IGMP" -eq 0 ]]; then
                        handle_invalid "Error: You must enable at least one protocol!"
                    else
                        break
                    fi
                    ;;
                *) handle_invalid "Invalid selection." ;;
            esac
        done
    fi

    if [[ "$CLI_VLAN_PASSED" -eq 0 ]]; then
        while true; do
            DRAW_HEADER
            cprint "--- [Stage 4] VLAN Scope ---"
            echo ""
            printf "Enter VLAN string (e.g., '5', '10-500', or blank for ALL): "
            read -t "$MENU_TIMEOUT_SEC" -r USER_VLAN < /dev/tty || { echo -e "\nTimeout reached. Exiting."; exit 1; }
            if [[ "$USER_VLAN" == *","* ]]; then
                handle_invalid "Commas restricted. Use dashes."
            else
                TARGET_VLAN="$USER_VLAN"
                break
            fi
        done
    fi

    if [[ "$CLI_MAC_PASSED" -eq 0 ]]; then
        while true; do
            DRAW_HEADER
            cprint "--- [Stage 5] MAC Address ---"
            echo ""
            printf "  1. Hardware MAC\n  2. Random MAC [Default]\n  3. Custom MAC\n\nSelect option [1-3]: "
            read -t "$MENU_TIMEOUT_SEC" -r MAC_SEL < /dev/tty || { echo -e "\nTimeout reached. Exiting."; exit 1; }
            case "${MAC_SEL:-2}" in
                1) TARGET_MAC="$TARGET_MAC_ACTUAL"; break ;;
                2) TARGET_MAC=$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))); break ;;
                3) 
                    printf "Enter custom MAC: "
                    read -r USER_MAC < /dev/tty
                    CMAC=$(echo "$USER_MAC" | sed 's/[: -]//g' | tr '[:upper:]' '[:lower:]')
                    if [[ "$CMAC" =~ ^[0-9a-f]{12}$ ]]; then
                        TARGET_MAC=$(echo "$CMAC" | sed 's/\(..\)/\1:/g;s/.$//')
                        break
                    else
                        handle_invalid "Invalid format."
                    fi
                    ;;
                *) handle_invalid "Invalid selection." ;;
            esac
        done
    fi
else
    TARGET_MAC="$TARGET_MAC_ACTUAL"
fi

DRAW_HEADER
tprint "Optimizing network interface..."

CURRENT_MTU=$(cat "/sys/class/net/$TARGET_INTERFACE/mtu" 2>/dev/null || echo "1500")
if [[ "$CURRENT_MTU" -lt "$TARGET_MTU" ]]; then
    ORIGINAL_MTU="$CURRENT_MTU"
    ip link set dev "$TARGET_INTERFACE" mtu "$TARGET_MTU" >/dev/null 2>&1
    STATE_MTU_CHANGED=1
    tprint "MTU temporarily increased to $TARGET_MTU"
else
    tprint "MTU optimization skipped (already $CURRENT_MTU)"
fi

if ethtool -k "$TARGET_INTERFACE" 2>/dev/null | grep -q "rx-vlan-offload: on"; then
    ethtool -K "$TARGET_INTERFACE" rxvlan off >/dev/null 2>&1
    STATE_RX_CHANGED=1
    tprint "Hardware VLAN offload disabled"
else
    tprint "Hardware VLAN offload already disabled"
fi
tprint "Network interface optimization complete"

PYTHON_PAYLOAD="$_VLAN_WORKSPACE/probe.py"

cat << 'EOF' > "$PYTHON_PAYLOAD"
import os, threading, queue, time, sys, select, termios, tty
from scapy.all import Ether, Dot1Q, PPPoED, IP, UDP, BOOTP, DHCP, sendp, AsyncSniffer, conf, RandMAC
from scapy.arch.linux import L2Socket
from scapy.contrib.igmp import IGMP
from scapy.layers.ppp import PPPoETag
from scapy.layers.inet import IPOption

IFCE, HMAC = sys.argv[1:3]
VLAN_ARG = sys.argv[3] if len(sys.argv) > 3 else ""
P_PPPOE, P_DHCP, P_IGMP = map(int, sys.argv[4:7])
PROBE_MODE = int(sys.argv[7]) if len(sys.argv) > 7 else 1

BRT = int(os.environ.get('BURST_RATE', 10))
BPS = int(os.environ.get('BURST_PER_SEC', 10))
PASSIVE_TIMEOUT_SEC = int(os.environ.get('PASSIVE_TIMEOUT_SEC', 900))
LATE_RESPONSE_WAIT = int(os.environ.get('LATE_RESPONSE_WAIT', 3))
BBI = 1.0 / (BPS + 1)

conf.verb = 0
REQQ = queue.Queue()

def TYPP(VLAN, NAME):
    N = NAME.upper()
    if any(X in N for X in ["IPTV", "TV", "VIDEO", "VOD"]): return "IPTV"
    if any(X in N for X in ["VOIP", "VOICE", "SIP", "PHONE"]): return "VOIP"
    if any(X in N for X in ["MGMT", "CWMP", "TR069", "ACS", "MANAGEMENT"]): return "MGMT"
    return "INTERNET" if VLAN > 0 else "UNTAGGED"

SEEN_PASV = set()

def CBBK(PKTT):
    global SEEN_PASV
    try:
        if not PKTT.haslayer(Ether): return
        SMAC = PKTT[Ether].src
        if not SMAC or SMAC.strip() == "" or SMAC.lower() == HMAC.lower(): return
        
        VLAN = PKTT[Dot1Q].vlan if Dot1Q in PKTT else 0
        if VLAN == 0: return

        if PKTT.haslayer(PPPoED) and PKTT[PPPoED].code in [0x07, 0x65]:
            RAWW, NAME, INDX = bytes(PKTT[PPPoED].payload), 'UNKNOWN', 0
            while INDX + 4 <= len(RAWW):
                T, L = (RAWW[INDX]<<8)+RAWW[INDX+1], (RAWW[INDX+2]<<8)+RAWW[INDX+3]
                if T == 0x0102: NAME = RAWW[INDX+4:INDX+4+L].decode(errors='ignore'); break
                INDX += 4 + L
            ITEM = {'v':VLAN, 'm':SMAC, 'n':NAME, 't':TYPP(VLAN,NAME), 'p':'PPPoE'}
        elif PKTT.haslayer(BOOTP) and PKTT[BOOTP].op == 2:
            NAME = next((f"VCI: {O[1].decode(errors='ignore')}" for O in PKTT[DHCP].options if isinstance(O, tuple) and O[0]=='vendor_class_id'), "DHCP Server") if PKTT.haslayer(DHCP) else "DHCP Server"
            if NAME == "DHCP Server" and PKTT.haslayer(IP): NAME = f"IPoE: {PKTT[IP].src}"
            ITEM = {'v':VLAN, 'm':SMAC, 'n':NAME, 't':TYPP(VLAN,NAME), 'p':'DHCP'}
        else:
            ITEM = {'v':VLAN, 'm':SMAC, 'n': 'UNKNOWN', 't': 'UNKNOWN', 'p': 'UNKNOWN'}

        REQQ.put(ITEM)
        if PROBE_MODE == 2:
            UID = f"{VLAN}-{ITEM['p']}"
            if UID not in SEEN_PASV:
                SEEN_PASV.add(UID)
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                sys.stdout.write(f"{time.strftime('[%H:%M:%S]')} VLAN Detected: {VLAN} | Proto: {ITEM['p']} | Identity: {ITEM['n'][:20]}\n")
                sys.stdout.flush()
    except: pass

def DRAW_PROG_ACTIVE(CPLT, TOTL):
    R = CPLT / TOTL if TOTL else 1.0
    FILL = int(R * 20)
    BARR = '#' * FILL + '-' * (20 - FILL)
    sys.stdout.write(f"\rScan progress [{BARR}] ({CPLT}/{TOTL}) {int(R*100)}% Completed")
    sys.stdout.flush()

def DRAW_PROG_PASSIVE(ELAP, TOTL, found_count=0):
    R = ELAP / TOTL if TOTL else 1.0
    FILL = int(R * 20)
    BARR = '#' * FILL + '-' * (20 - FILL)
    sys.stdout.write(f"\rScan progress [{BARR}] ({int(ELAP)}/{TOTL}s) | Found: {found_count} VLAN(s)")
    sys.stdout.flush()

if __name__ == "__main__":
    SNFF = AsyncSniffer(iface=IFCE, prn=CBBK, store=0)
    SNFF.start()
    time.sleep(0.1)

    try:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        is_tty = True
    except:
        is_tty = False

    INTERRUPTED = False

    try:
        if PROBE_MODE == 1:
            sys.stdout.write(f"{time.strftime('[%H:%M:%S]')} VLAN probing started (ACTIVE)\n")
            sys.stdout.flush()
            
            if VLAN_ARG:
                if '-' in VLAN_ARG:
                    try: x, y = map(int, VLAN_ARG.split('-')); VRGG = list(range(min(x,y), max(x,y)+1))
                    except: VRGG = list(range(4096))
                else:
                    try: VRGG = [int(VLAN_ARG)]
                    except: VRGG = list(range(4096))
            else: VRGG = list(range(4096))

            B_ETH = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff")
            M_ETH = Ether(src=HMAC, dst="01:00:5e:00:00:16")
            B_PPP = Ether(src=HMAC, dst="ff:ff:ff:ff:ff:ff", type=0x8863)
            P_PPP = PPPoED(version=1, type=1, code=0x09, sessionid=0) / PPPoETag(tag_type=0x0101, tag_len=0) / PPPoETag(tag_type=0x0103, tag_len=4, tag_value=b"\x00\x00\x00\x01")
            B_DHC = IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=RandMAC())/DHCP(options=[("message-type", "discover"), "end"])
            B_IGM = IP(src="0.0.0.0", dst="224.0.0.22", ttl=1, options=[IPOption(b"\x94\x04\x00\x00")])/IGMP(type=0x16, gaddr="239.1.1.1")

            chunks_vlan = [VRGG[i:i + BRT] for i in range(0, len(VRGG), BRT)]
            pkts_to_send = []

            for chunk in chunks_vlan:
                if P_PPPOE:
                    for v in chunk:
                        if v > 0: pkts_to_send.append(bytes(B_ETH/Dot1Q(vlan=v, type=0x8863)/P_PPP))
                        else: pkts_to_send.append(bytes(B_PPP/P_PPP))
                if P_DHCP:
                    for v in chunk:
                        if v > 0: pkts_to_send.append(bytes(B_ETH/Dot1Q(vlan=v, type=0x0800)/B_DHC))
                if P_IGMP:
                    for v in chunk:
                        if v > 0: pkts_to_send.append(bytes(M_ETH/Dot1Q(vlan=v, type=0x0800)/B_IGM))

            try: L2 = L2Socket(iface=IFCE)
            except Exception as e: SNFF.stop(); sys.exit(1)

            TOTL = len(pkts_to_send)
            CPLT = 0

            INDIVIDUAL_DELAY = 1.0 / float(BPS * BRT) if BPS > 0 else 0.01

            for idx, pkt in enumerate(pkts_to_send):
                if is_tty and idx % BRT == 0 and select.select([sys.stdin], [], [], 0)[0]:
                    sys.stdin.read(1)
                    INTERRUPTED = True
                    break

                try: L2.send(pkt)
                except: pass
                CPLT += 1
                
                if idx % max(1, int(BRT/2)) == 0 or CPLT == TOTL:
                    DRAW_PROG_ACTIVE(CPLT, TOTL)
                
                time.sleep(INDIVIDUAL_DELAY)

            L2.close()
            sys.stdout.write("\r\033[K")
            status = "completed" if not INTERRUPTED else "terminated"
            sys.stdout.write(f"{time.strftime('[%H:%M:%S]')} Active probing {status}. Awaiting late responses...\n")
            sys.stdout.flush()
            time.sleep(LATE_RESPONSE_WAIT)

        else:
            sys.stdout.write(f"{time.strftime('[%H:%M:%S]')} VLAN sniffing started (PASSIVE).\n")
            sys.stdout.write(f"{time.strftime('[%H:%M:%S]')} Sniffing for {PASSIVE_TIMEOUT_SEC} sec. (Press ANY key to STOP)\n")
            sys.stdout.flush()
            
            start_time = time.time()
            while time.time() - start_time < PASSIVE_TIMEOUT_SEC:
                elapsed = time.time() - start_time
                DRAW_PROG_PASSIVE(elapsed, PASSIVE_TIMEOUT_SEC, REQQ.qsize())
                
                if is_tty and select.select([sys.stdin], [], [], 0.1)[0]:
                    sys.stdin.read(1)
                    INTERRUPTED = True
                    break
                    
            sys.stdout.write("\r\033[K")
            sys.stdout.write("\033[1A")
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            
            status = "completed" if not INTERRUPTED else "terminated"
            sys.stdout.write(f"{time.strftime('[%H:%M:%S]')} Passive sniffing {status}. Preparing results...\n")
            sys.stdout.flush()
            time.sleep (3)

    except (KeyboardInterrupt, SystemExit):
        INTERRUPTED = True
    finally:
        if is_tty:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    SNFF.stop()

    DATA = {}
    while not REQQ.empty():
        ITEM = REQQ.get()
        DATA[f"{ITEM['v']}-{ITEM['p']}-{ITEM['n']}"] = ITEM

    H_FMT = "{:<6} {:<8} {:<10} {:<24} {:<18}"
    sys.stdout.write("\nDISCOVERY RESULTS\n" + "-"*70 + "\n")
    sys.stdout.write(H_FMT.format('VLAN', 'PROTO', 'TYPE', 'IDENTITY', 'MAC ADDRESS') + "\n" + "-"*70 + "\n")
    
    if not DATA: 
        sys.stdout.write("No services detected.\n")
    else:
        for K in sorted(DATA.keys(), key=lambda x: (int(x.split('-')[0]), x.split('-')[1])):
            D = DATA[K]
            sys.stdout.write(H_FMT.format(str(D['v']), D['p'], D['t'], D['n'][:23], D['m']) + "\n")
            
    sys.stdout.write("-" * 70 + "\n")
EOF

echo ""

trap '' SIGINT SIGTERM

PYTHONUNBUFFERED=1 "$PYTHON_EXEC" "$PYTHON_PAYLOAD" \
    "$TARGET_INTERFACE" "$TARGET_MAC" "$TARGET_VLAN" \
    "$PROTO_PPPOE" "$PROTO_DHCP" "$PROTO_IGMP" "$PROBE_MODE" 2>&1 \
    | tee >(sed -r "s/\x1B\[[0-9;]*[a-zA-Z]//g" >> "$LOG_FILE")

trap - SIGINT SIGTERM
cleanup
