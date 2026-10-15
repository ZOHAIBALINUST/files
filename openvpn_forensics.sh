#!/usr/bin/env bash
#
# openvpn_forensics.sh - Evidence collection for an OpenVPN server (CentOS/RHEL 7/8/9)
#
# Collects volatile state first, then configuration, logs, PKI records,
# firewall/network state, and system artifacts. Read-only against the system.
# Produces a hashed manifest and a compressed, checksummed archive.
#
# Usage: sudo ./openvpn_forensics.sh [-c CASE_ID] [-o OUTPUT_DIR]

set -uo pipefail

CASE_ID="CASE-$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="/var/forensics"
while getopts "c:o:h" opt; do
    case $opt in
        c) CASE_ID="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        h) echo "Usage: $0 [-c CASE_ID] [-o OUTPUT_DIR]"; exit 0 ;;
        *) echo "Usage: $0 [-c CASE_ID] [-o OUTPUT_DIR]"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
fi

HOSTNAME_SHORT=$(hostname -s)
TS=$(date -u +%Y%m%dT%H%M%SZ)
BASE="${OUTDIR}/${CASE_ID}_${HOSTNAME_SHORT}_${TS}"
COLLECT="${BASE}/collection"
LOG="${BASE}/collector.log"
MANIFEST="${BASE}/manifest.sha256"
META="${BASE}/file_metadata.txt"
ERRORS="${BASE}/errors.txt"

umask 077
mkdir -p "$COLLECT"/{volatile,system,openvpn,pki,logs,network,firewall,auth,packages,misc}
touch "$LOG" "$META" "$ERRORS"

log() {
    printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "$1" "$2" | tee -a "$LOG"
}

# Copy a file or directory, preserving attributes and recording its metadata.
collect_path() {
    local src="$1" dest_dir="$2"
    if [[ -e "$src" ]]; then
        mkdir -p "$dest_dir"
        if cp -a --parents "$src" "$dest_dir" 2>>"$ERRORS"; then
            log INFO "Collected $src"
            stat -c '%n|%s|%U:%G|%a|mtime=%y|ctime=%z|atime=%x' "$src" >> "$META" 2>/dev/null
        else
            log WARN "Failed to copy $src (see errors.txt)"
        fi
    else
        log SKIP "Not present: $src"
    fi
}

# Run a command and save its stdout/stderr to a file.
collect_cmd() {
    local name="$1"; shift
    local out="$COLLECT/$name.txt"
    {
        echo "### COMMAND: $*"
        echo "### TIME: $(date -u +%FT%TZ)"
        echo "----------------------------------------"
        "$@" 2>&1
        echo "----------------------------------------"
        echo "### EXIT: $?"
    } > "$out" 2>>"$ERRORS"
    log INFO "Ran: $*"
}

log INFO "Starting collection. Case=$CASE_ID Host=$HOSTNAME_SHORT"

# ---------------------------------------------------------------------------
# 1. VOLATILE DATA (capture first, it changes quickly)
# ---------------------------------------------------------------------------
log INFO "=== Phase 1: volatile state ==="
V="$COLLECT/volatile"

collect_cmd "v01_date_uptime"        bash -c 'date -u; echo; uptime; echo; cat /proc/uptime'
collect_cmd "v02_processes"          ps auxfww
collect_cmd "v03_process_tree"       ps -eo pid,ppid,user,lstart,cmd --forest
collect_cmd "v04_openvpn_procs"      bash -c 'pgrep -a openvpn; echo; for p in $(pgrep openvpn); do echo "--- PID $p ---"; ls -l /proc/$p/exe /proc/$p/cwd 2>/dev/null; cat /proc/$p/cmdline | tr "\0" " "; echo; ls -l /proc/$p/fd 2>/dev/null; done'
collect_cmd "v05_sockets_all"        ss -tupanoe
collect_cmd "v06_listening"          ss -tulpn
collect_cmd "v07_netstat"            bash -c 'command -v netstat >/dev/null && netstat -anp || echo "netstat not installed"'
collect_cmd "v08_lsof_network"       bash -c 'command -v lsof >/dev/null && lsof -nP -i || echo "lsof not installed"'
collect_cmd "v09_ip_addr"            ip -d addr show
collect_cmd "v10_ip_link"            ip -d link show
collect_cmd "v11_ip_route"           bash -c 'ip route show table all; echo; ip -6 route show table all'
collect_cmd "v12_ip_rules"           ip rule show
collect_cmd "v13_arp_neigh"          ip neigh show
collect_cmd "v14_logged_in_users"    bash -c 'who -a; echo; w'
collect_cmd "v15_loaded_modules"     lsmod
collect_cmd "v16_mounts"             cat /proc/mounts
collect_cmd "v17_open_files"         bash -c 'command -v lsof >/dev/null && lsof -nP +L1 || true'
collect_cmd "v18_sysctl_network"     sysctl -a --pattern 'net\.ipv4\.ip_forward|net\.ipv4\.conf\..*\.forwarding|net\.ipv6\.conf\.all\.forwarding'
collect_cmd "v19_tun_devices"        bash -c 'ls -la /dev/net/tun 2>/dev/null; ip -o link show type tun 2>/dev/null'
collect_cmd "v20_dmesg"              dmesg -T

# ---------------------------------------------------------------------------
# 2. SYSTEM STATE
# ---------------------------------------------------------------------------
log INFO "=== Phase 2: system state ==="
collect_cmd "s01_os_release"         bash -c 'cat /etc/redhat-release; echo; cat /etc/os-release; echo; uname -a'
collect_cmd "s02_hostname_time"      bash -c 'hostnamectl 2>/dev/null; echo; timedatectl 2>/dev/null; echo; chronyc tracking 2>/dev/null || true'
collect_cmd "s03_disk_usage"         bash -c 'df -hT; echo; lsblk -f'
collect_cmd "s04_systemd_units"      systemctl list-units --type=service --all --no-pager
collect_cmd "s05_systemd_enabled"    systemctl list-unit-files --no-pager
collect_cmd "s06_openvpn_status"     bash -c 'systemctl status "openvpn*" --no-pager -l 2>&1; echo; systemctl is-enabled "openvpn*" 2>&1'
collect_cmd "s07_failed_units"       systemctl --failed --no-pager
collect_cmd "s08_timers"             systemctl list-timers --all --no-pager
collect_cmd "s09_sysctl_all"         sysctl -a
collect_cmd "s10_kernel_cmdline"     cat /proc/cmdline
collect_path "/etc/systemd/system"   "$COLLECT/system"
collect_path "/usr/lib/systemd/system/openvpn-server@.service" "$COLLECT/system"
collect_path "/usr/lib/systemd/system/openvpn-client@.service" "$COLLECT/system"
collect_path "/etc/sysctl.conf"      "$COLLECT/system"
collect_path "/etc/sysctl.d"         "$COLLECT/system"
collect_path "/etc/hosts"            "$COLLECT/system"
collect_path "/etc/resolv.conf"      "$COLLECT/system"
collect_path "/etc/fstab"            "$COLLECT/system"
collect_path "/etc/crontab"          "$COLLECT/system"
collect_path "/etc/cron.d"           "$COLLECT/system"
collect_path "/etc/cron.daily"       "$COLLECT/system"
collect_path "/etc/cron.hourly"      "$COLLECT/system"
collect_path "/var/spool/cron"       "$COLLECT/system"
collect_path "/etc/rc.d/rc.local"    "$COLLECT/system"
collect_path "/etc/profile"          "$COLLECT/system"
collect_path "/etc/profile.d"        "$COLLECT/system"
collect_path "/etc/bashrc"           "$COLLECT/system"
collect_path "/etc/ld.so.preload"    "$COLLECT/system"
collect_path "/etc/security"         "$COLLECT/system"
collect_path "/etc/pam.d"            "$COLLECT/system"

# ---------------------------------------------------------------------------
# 3. OPENVPN CONFIGURATION, KEYS AND CLIENT MAPPINGS
# ---------------------------------------------------------------------------
log INFO "=== Phase 3: OpenVPN configuration ==="
O="$COLLECT/openvpn"
collect_path "/etc/openvpn"          "$O"
collect_path "/usr/lib/systemd/system/openvpn-server@.service" "$O"
collect_path "/var/lib/openvpn"      "$O"
collect_path "/var/log/openvpn"      "$O"
collect_path "/var/log/openvpn.log"  "$O"
collect_path "/var/log/openvpn-status.log" "$O"
collect_path "/var/run/openvpn"      "$O"
collect_path "/run/openvpn-server"   "$O"
collect_path "/run/openvpn"          "$O"

# Locate every server config and any status/log directives it references.
collect_cmd "o01_openvpn_binary"     bash -c 'command -v openvpn && openvpn --version'
collect_cmd "o02_openvpn_packages"   bash -c 'rpm -qa | grep -iE "openvpn|easy-rsa|openssl|iptables|firewalld|nftables"'
collect_cmd "o03_server_configs"     bash -c 'find /etc/openvpn -type f \( -name "*.conf" -o -name "*.ovpn" \) -exec ls -la {} \;'
collect_cmd "o04_status_directives"  bash -c 'grep -rHiE "^[[:space:]]*(status|log|log-append|management|client-config-dir|ca|cert|key|crl-verify|tls-auth|tls-crypt|auth-user-pass-verify|script-security|up|down|client-connect|client-disconnect|learn-address|route|push|plugin)[[:space:]]" /etc/openvpn 2>/dev/null'
collect_cmd "o05_ccd_listing"        bash -c 'for d in $(grep -rhiE "^[[:space:]]*client-config-dir" /etc/openvpn 2>/dev/null | awk "{print \$2}" | sort -u); do echo "== $d =="; ls -la "$d" 2>/dev/null; done'
collect_cmd "o06_ccd_contents"       bash -c 'for d in $(grep -rhiE "^[[:space:]]*client-config-dir" /etc/openvpn 2>/dev/null | awk "{print \$2}" | sort -u); do [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }; done; done'
collect_cmd "o07_ovpn_sha256"        bash -c 'find /etc/openvpn /var/lib/openvpn /var/log/openvpn -type f -exec sha256sum {} + 2>/dev/null'

# ---------------------------------------------------------------------------
# 4. PKI / EASY-RSA RECORDS (issuance, revocation, CRL)
# ---------------------------------------------------------------------------
log INFO "=== Phase 4: PKI records ==="
P="$COLLECT/pki"
PKI_DIRS=(/etc/openvpn/easy-rsa /etc/easy-rsa /usr/share/easy-rsa /root/easy-rsa /home/*/easy-rsa /opt/easy-rsa)
for d in "${PKI_DIRS[@]}"; do
    for pdir in $d/pki $d; do
        [[ -d "$pdir" ]] || continue
        log INFO "Found PKI directory: $pdir"
        collect_path "$pdir/index.txt"        "$P"
        collect_path "$pdir/index.txt.attr"   "$P"
        collect_path "$pdir/serial"           "$P"
        collect_path "$pdir/crl.pem"          "$P"
        collect_path "$pdir/issued"           "$P"
        collect_path "$pdir/revoked"          "$P"
        collect_path "$pdir/reqs"             "$P"
        collect_path "$pdir/private/ca.key"   "$P"   # Presence and metadata only; see note below
        collect_path "$pdir/ca.crt"           "$P"
        collect_path "$pdir/vars"             "$P"
        collect_path "$pdir/pki.conf"         "$P"
    done
done
# Certificates present in server config dirs
collect_cmd "p01_cert_inventory" bash -c '
for c in $(find /etc/openvpn /etc/easy-rsa /usr/share/easy-rsa /root /home /opt -maxdepth 6 -type f \( -name "*.crt" -o -name "*.pem" \) 2>/dev/null); do
    subj=$(openssl x509 -in "$c" -noout -subject 2>/dev/null)
    [[ -z "$subj" ]] && continue
    echo "FILE: $c"
    echo "  $subj"
    openssl x509 -in "$c" -noout -issuer -serial -dates -fingerprint -sha256 2>/dev/null | sed "s/^/  /"
    echo
done'
collect_cmd "p02_crl_details"        bash -c 'for f in $(find /etc/openvpn /usr/share/easy-rsa /etc/easy-rsa -name crl.pem 2>/dev/null); do echo "== $f =="; openssl crl -in "$f" -noout -text 2>/dev/null | head -n 400; done'
collect_cmd "p03_index_summary"      bash -c 'for f in $(find /etc/openvpn /usr/share/easy-rsa /etc/easy-rsa -name index.txt 2>/dev/null); do echo "== $f =="; echo "Total entries: $(wc -l < "$f")"; echo "Valid (V):   $(awk "\$1==\"V\"" "$f" | wc -l)"; echo "Revoked (R): $(awk "\$1==\"R\"" "$f" | wc -l)"; echo; awk -F"\t" "{print \$1 \"|\" \$2 \"|\" \$3 \"|\" \$4 \"|\" \$6}" "$f"; done'

# ---------------------------------------------------------------------------
# 5. LOGS
# ---------------------------------------------------------------------------
log INFO "=== Phase 5: logs ==="
L="$COLLECT/logs"
for f in /var/log/messages /var/log/messages-* /var/log/secure /var/log/secure-* \
         /var/log/audit /var/log/cron /var/log/maillog /var/log/boot.log \
         /var/log/dmesg /var/log/yum.log /var/log/dnf.log /var/log/dnf.rpm.log \
         /var/log/firewalld /var/log/btmp /var/log/wtmp /var/log/lastlog \
         /var/log/tuned /var/log/chrony /var/log/sa /var/log/pki; do
    collect_path "$f" "$L"
done

collect_cmd "l01_journal_openvpn"    bash -c 'journalctl -u "openvpn*" --no-pager -o short-iso-precise --since "-90 days" 2>&1'
collect_cmd "l02_journal_kernel"     journalctl -k --no-pager -o short-iso-precise --since "-90 days"
collect_cmd "l03_journal_auth"       bash -c 'journalctl _COMM=sshd _COMM=sudo _COMM=su _COMM=passwd _COMM=useradd _COMM=usermod _COMM=userdel --no-pager -o short-iso-precise --since "-90 days" 2>&1'
collect_cmd "l04_journal_boots"      journalctl --list-boots --no-pager
collect_cmd "l05_journal_full_90d"   bash -c 'journalctl --no-pager -o short-iso-precise --since "-90 days" 2>&1 | gzip -c' 

# Login history
collect_cmd "l06_last"               bash -c 'last -aiFw; echo; last -aiFw -f /var/log/btmp.1 2>/dev/null'
collect_cmd "l07_lastb"              bash -c 'lastb -aiFw 2>/dev/null'
collect_cmd "l08_lastlog"            lastlog
collect_cmd "l09_sa_history"         bash -c 'ls -la /var/log/sa/ 2>/dev/null'

# OpenVPN-specific quick extracts (high-value summaries; raw logs are already collected)
collect_cmd "l10_ovpn_connections"   bash -c '
LOGS=$(ls /var/log/openvpn* /var/log/messages* 2>/dev/null)
echo "### Client connection events (CLIENT_CONNECT / peer connection lines)"
grep -hiE "peer connection initiated|Peer Connection Initiated|MULTI: Learn|Initialization Sequence Completed" $LOGS 2>/dev/null
echo
echo "### Disconnects"
grep -hiE "SIGTERM|SIGUSR1|connection reset|Client-instance restarting|client-instance exiting|Connection reset|TLS Error" $LOGS 2>/dev/null
echo
echo "### Authentication failures"
grep -hiE "AUTH_FAILED|VERIFY ERROR|TLS Error: TLS key negotiation failed|auth-user-pass-verify|Failed to verify|certificate.*(revoked|expired|unknown)|TLS handshake failed|bad certificate|tls-crypt|replay" $LOGS 2>/dev/null
echo
echo "### Revoked or rejected certificates"
grep -hiE "revoked|CRL" $LOGS 2>/dev/null'

collect_cmd "l11_ovpn_journal_summary" bash -c '
journalctl -u "openvpn*" --no-pager -o cat --since "-90 days" 2>/dev/null |
  grep -oE "MULTI: primary virtual IP for [^:]+|peer connection initiated from [0-9a-fA-F:.]+[^ ]*|CN=[^/, ]+" |
  sort | uniq -c | sort -rn'

# ---------------------------------------------------------------------------
# 6. ACCOUNTS, AUTHENTICATION AND USER ARTIFACTS
# ---------------------------------------------------------------------------
log INFO "=== Phase 6: accounts and user artifacts ==="
A="$COLLECT/auth"
collect_path "/etc/passwd"           "$A"
collect_path "/etc/group"            "$A"
collect_path "/etc/shadow"           "$A"    # Contains password hashes. Handle as sensitive.
collect_path "/etc/gshadow"          "$A"
collect_path "/etc/sudoers"          "$A"
collect_path "/etc/sudoers.d"        "$A"
collect_path "/etc/ssh/sshd_config"  "$A"
collect_path "/etc/ssh/sshd_config.d" "$A"
collect_path "/etc/login.defs"       "$A"
collect_path "/etc/ssh"              "$A"
collect_cmd  "a01_user_list"         bash -c 'awk -F: "\$3>=1000 || \$3==0 {print}" /etc/passwd; echo; echo "Users with login shells:"; grep -vE "(nologin|false)$" /etc/passwd'
collect_cmd  "a02_sudo_users"        bash -c 'grep -rE "^[^#].*ALL" /etc/sudoers /etc/sudoers.d 2>/dev/null; echo; getent group wheel sudo 2>/dev/null'
collect_cmd  "a03_recently_changed"  bash -c 'find /etc /root /home /var/spool/cron -xdev -newermt "-30 days" -type f 2>/dev/null | head -n 5000'
collect_cmd  "a04_setuid_setgid"     bash -c 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null'
collect_cmd  "a05_world_writable"    bash -c 'find / -xdev -type f -perm -0002 -ls 2>/dev/null | head -n 2000'

# Per-user artifacts (root and every home directory)
for home in /root /home/*; do
    [[ -d "$home" ]] || continue
    user=$(basename "$home")
    dest="$A/users/$user"
    collect_path "$home/.bash_history"       "$dest"
    collect_path "$home/.zsh_history"        "$dest"
    collect_path "$home/.lesshst"            "$dest"
    collect_path "$home/.viminfo"            "$dest"
    collect_path "$home/.ssh"                "$dest"
    collect_path "$home/.bashrc"             "$dest"
    collect_path "$home/.bash_profile"       "$dest"
    collect_path "$home/.profile"            "$dest"
    collect_path "$home/.wget-hsts"          "$dest"
    collect_path "$home/.gnupg"              "$dest"
    collect_path "$home/easy-rsa"            "$dest"
    collect_path "$home/client-configs"      "$dest"
    collect_path "$home/.config/openvpn"     "$dest"
done

# ---------------------------------------------------------------------------
# 7. NETWORK AND FIREWALL CONFIGURATION
# ---------------------------------------------------------------------------
log INFO "=== Phase 7: network and firewall ==="
N="$COLLECT/network"
F="$COLLECT/firewall"

collect_cmd "n01_nm_connections"     bash -c 'nmcli -t con show 2>/dev/null; echo; nmcli dev status 2>/dev/null'
collect_path "/etc/sysconfig/network-scripts" "$N"
collect_path "/etc/sysconfig/network"         "$N"
collect_path "/etc/NetworkManager"            "$N"
collect_path "/etc/hosts.allow"               "$N"
collect_path "/etc/hosts.deny"                "$N"
collect_path "/etc/nsswitch.conf"             "$N"

collect_cmd "f01_firewalld_state"    bash -c 'firewall-cmd --state 2>&1; echo; firewall-cmd --list-all-zones 2>&1; echo; firewall-cmd --get-active-zones 2>&1'
collect_cmd "f02_firewalld_runtime"  bash -c 'firewall-cmd --list-all 2>&1; echo; firewall-cmd --direct --get-all-rules 2>&1; echo; firewall-cmd --list-rich-rules 2>&1; echo; firewall-cmd --list-forward-ports 2>&1'
collect_cmd "f03_firewalld_perm"     bash -c 'firewall-cmd --permanent --list-all-zones 2>&1; echo; firewall-cmd --permanent --direct --get-all-rules 2>&1; echo; firewall-cmd --permanent --list-rich-rules 2>&1'
collect_path "/etc/firewalld"        "$F"
collect_path "/usr/lib/firewalld"    "$F"
collect_cmd "f04_iptables_save"      bash -c 'iptables-save -c 2>&1; echo; ip6tables-save -c 2>&1'
collect_cmd "f05_iptables_nat"       bash -c 'iptables -t nat -L -nv --line-numbers 2>&1; echo; iptables -t mangle -L -nv 2>&1'
collect_cmd "f06_nft_ruleset"        bash -c 'nft list ruleset 2>&1'
collect_path "/etc/sysconfig/iptables"  "$F"
collect_path "/etc/sysconfig/ip6tables" "$F"
collect_path "/etc/nftables.conf"       "$F"

# ---------------------------------------------------------------------------
# 8. PACKAGE AND UPDATE HISTORY
# ---------------------------------------------------------------------------
log INFO "=== Phase 8: packages ==="
K="$COLLECT/packages"
collect_cmd "k01_rpm_all"            bash -c 'rpm -qa --last | head -n 2000'
collect_cmd "k02_rpm_verify_openvpn" bash -c 'rpm -V openvpn easy-rsa openssl openssh-server firewalld iptables 2>&1'
collect_cmd "k03_yum_history"        bash -c 'dnf history 2>/dev/null || yum history 2>/dev/null'
collect_cmd "k04_yum_history_detail" bash -c 'for id in $(dnf history list 2>/dev/null | awk "NR>2 {print \$1}" | head -n 50); do echo "=== Transaction $id ==="; dnf history info "$id" 2>/dev/null; done'
collect_path "/var/lib/dnf/history.sqlite" "$K"
collect_path "/var/lib/rpm"                 "$K"

# ---------------------------------------------------------------------------
# 9. MISCELLANEOUS
# ---------------------------------------------------------------------------
log INFO "=== Phase 9: misc ==="
M="$COLLECT/misc"
collect_cmd "m01_selinux"            bash -c 'getenforce; sestatus; echo; ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | tail -n 500'
collect_cmd "m02_audit_rules"        bash -c 'auditctl -l 2>&1; echo; auditctl -s 2>&1'
collect_cmd "m03_tmp_listing"        bash -c 'ls -laR /tmp /var/tmp /dev/shm 2>/dev/null | head -n 5000'
collect_cmd "m04_hidden_files_tmp"   bash -c 'find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null'
collect_cmd "m05_executables_tmp"    bash -c 'find /tmp /var/tmp /dev/shm -type f -perm -u+x -ls 2>/dev/null'
collect_cmd "m06_deleted_running"    bash -c 'ls -l /proc/*/exe 2>/dev/null | grep "(deleted)"'
collect_cmd "m07_crontabs"           bash -c 'for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null); [[ -n "$c" ]] && { echo "== $u =="; echo "$c"; }; done'
collect_cmd "m08_at_jobs"            bash -c 'atq 2>/dev/null; ls -la /var/spool/at 2>/dev/null'
collect_cmd "m09_rc_local_status"    bash -c 'ls -la /etc/rc.d/rc.local 2>/dev/null; systemctl status rc-local 2>&1 | head -n 20'
collect_cmd "m10_recent_files"       bash -c 'find / -xdev -type f -newermt "-7 days" 2>/dev/null | grep -vE "^/(proc|sys|dev|run)/" | head -n 10000'

# ---------------------------------------------------------------------------
# 10. METADATA, MANIFEST, PACKAGING
# ---------------------------------------------------------------------------
log INFO "=== Phase 10: manifest and packaging ==="

cat > "${BASE}/README.txt" <<EOF
Evidence collection record
==========================
Case ID:            $CASE_ID
Hostname:           $(hostname -f 2>/dev/null || hostname)
Collection start:   $TS (UTC)
Collection end:     $(date -u +%Y%m%dT%H%M%SZ) (UTC)
Collected by:       $(logname 2>/dev/null || echo "${SUDO_USER:-root}")
Script version:     1.0
Kernel:             $(uname -r)
OS:                 $(cat /etc/redhat-release 2>/dev/null)

Contents:
  collection/volatile/   Live state (processes, sockets, routes, sessions)
  collection/system/     Services, cron, system configuration
  collection/openvpn/    OpenVPN configs, keys, logs, status files
  collection/pki/        Easy-RSA index, CRL, issued/revoked certificates
  collection/logs/       System, auth, audit and journal logs
  collection/auth/       Accounts, sudoers, SSH config, user histories
  collection/network/    Interface and network manager configuration
  collection/firewall/   firewalld, iptables and nftables state
  collection/packages/   Package inventory and update history
  collection/misc/       SELinux, audit, tmp directories, deleted-but-running binaries
  manifest.sha256        SHA-256 of every collected file
  file_metadata.txt      stat() output (owner, mode, times) for copied files
  collector.log          Timestamped collection log
  errors.txt             Non-fatal errors encountered

Notes:
  - /etc/shadow and CA private keys were collected for completeness. Restrict access.
  - The live system was not modified except for reading state.
EOF

log INFO "Generating SHA-256 manifest"
(cd "$COLLECT" && find . -type f -exec sha256sum {} +) > "$MANIFEST" 2>>"$ERRORS"

log INFO "Writing quick summary"
{
    echo "OpenVPN forensic quick summary - $CASE_ID"
    echo "Generated: $(date -u +%FT%TZ)"
    echo
    echo "Files collected:  $(find "$COLLECT" -type f | wc -l)"
    echo "Total size:       $(du -sh "$COLLECT" | cut -f1)"
    echo "Errors logged:    $(wc -l < "$ERRORS")"
    echo
    echo "OpenVPN services:"
    systemctl list-units "openvpn*" --no-pager 2>/dev/null
    echo
    echo "Listening OpenVPN sockets:"
    ss -ulpn 2>/dev/null | grep -i openvpn
    ss -tlpn 2>/dev/null | grep -i openvpn
} > "${BASE}/SUMMARY.txt"

# Create the archive and hash it
ARCHIVE="${BASE}.tar.gz"
tar -czf "$ARCHIVE" -C "$OUTDIR" "$(basename "$BASE")" 2>>"$ERRORS"
sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"
chmod 600 "$ARCHIVE" "${ARCHIVE}.sha256"

log INFO "Collection complete"
echo
echo "======================================================="
echo " Evidence archive: $ARCHIVE"
echo " SHA-256 file:     ${ARCHIVE}.sha256"
echo " Working dir:      $BASE"
echo " Manifest:         $MANIFEST"
echo "======================================================="