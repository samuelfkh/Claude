#!/usr/bin/env bash
#
# Invoke-VbrLinuxComponentAudit.sh
# -------------------------------------------------------------------------------------
# Companion to Invoke-VbrCyberSecureAudit.ps1 (the Windows VBR audit).
#
# Audits the LINUX-hosted Veeam components (hardened repository / managed Linux server)
# against the checklist items the Windows script cannot verify:
#
#   5.14  Do Linux/Unix systems use SSH Private/Public Key with Passphrase credentials?
#   5.15  Does SSH use strong password enforcement where applicable? (min 15 characters)
#   5.16  Is a dedicated, audited account used for repository access?
#   5.17  Is the account for repository access NOT root, or a member of Sudoers?
#   5.18  Where required, is the Linux service account NOT root but leverages SUDOER,
#         Firewall and PAM security?
#
# Run this script ON the Linux component (as root / via sudo) so it can read sshd_config,
# PAM, sudoers, firewall state and account details. It prints a color-coded table and
# writes a CSV whose columns match the Windows report:
#
#   Item #,Compliance,Topic,Rule Name,Status,Current Value,Recommendation
#
# Usage:
#   sudo ./Invoke-VbrLinuxComponentAudit.sh [-a REPO_ACCOUNT] [-o /path/report.csv] [-h]
#
#   -a REPO_ACCOUNT   Linux account used by Veeam for repository/service access. Enables
#                     the account-specific checks (5.16-5.18). If omitted those items
#                     degrade to WARNING and list candidate non-system accounts.
#   -o FILE           Output CSV path (default: ./VBR_Linux_Audit_<host>_<timestamp>.csv)
#   -h                Show this help.
# -------------------------------------------------------------------------------------

set -u

REPO_ACCOUNT=""
OUT_CSV=""

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while getopts ":a:o:h" opt; do
    case "$opt" in
        a) REPO_ACCOUNT="$OPTARG" ;;
        o) OUT_CSV="$OPTARG" ;;
        h) usage ;;
        \?) echo "Invalid option: -$OPTARG" >&2; exit 2 ;;
        :) echo "Option -$OPTARG requires an argument." >&2; exit 2 ;;
    esac
done

HOSTN="$(hostname 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d_%H%M%S)"
[ -z "$OUT_CSV" ] && OUT_CSV="./VBR_Linux_Audit_${HOSTN}_${TS}.csv"
TOPIC="Accounts and Permissions"

# --- colors (disabled if not a TTY) ---
if [ -t 1 ]; then
    C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_CYAN=$'\033[36m'; C_GRY=$'\033[90m'; C_RST=$'\033[0m'
else
    C_GREEN=""; C_RED=""; C_YEL=""; C_CYAN=""; C_GRY=""; C_RST=""
fi

# CSV header
printf '"Item #","Compliance","Topic","Rule Name","Status","Current Value","Recommendation"\n' > "$OUT_CSV"

PASS=0; FAIL=0; WARN=0

# csv_escape: double any embedded quotes.
csv_escape() { printf '%s' "$1" | sed 's/"/""/g'; }

# emit NUM COMPLIANCE NAME STATUS VALUE RECOMMENDATION
emit() {
    local num="$1" comp="$2" name="$3" status="$4" value="$5" rec="$6" color
    case "$status" in
        Passed)  color="$C_GREEN"; PASS=$((PASS+1)) ;;
        Failed)  color="$C_RED";   FAIL=$((FAIL+1)) ;;
        Warning) color="$C_YEL";   WARN=$((WARN+1)) ;;
        *)       color="$C_CYAN" ;;
    esac
    printf '  %-5s %s[%-7s]%s (%s) %s\n' "$num" "$color" "$status" "$C_RST" "$comp" "$name"
    [ -n "$value" ] && printf '        %s-> %s%s\n' "$C_GRY" "$value" "$C_RST"
    printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
        "$(csv_escape "$num")" "$(csv_escape "$comp")" "$(csv_escape "$TOPIC")" \
        "$(csv_escape "$name")" "$(csv_escape "$status")" "$(csv_escape "$value")" \
        "$(csv_escape "$rec")" >> "$OUT_CSV"
}

# sshd_config effective value (last matching directive wins); case-insensitive key.
sshd_val() {
    local key="$1" f="/etc/ssh/sshd_config"
    [ -r "$f" ] || { echo ""; return; }
    grep -iE "^[[:space:]]*${key}[[:space:]]+" "$f" 2>/dev/null | tail -n1 | awk '{print $2}'
}

echo ""
echo "${C_CYAN}===============================================================${C_RST}"
echo "${C_CYAN}  Veeam Linux Component Audit (checklist 5.14 - 5.18)${C_RST}"
echo "${C_CYAN}  Host: ${HOSTN}   Date: $(date '+%Y-%m-%d %H:%M')${C_RST}"
echo "${C_CYAN}===============================================================${C_RST}"
[ "$(id -u)" -ne 0 ] && echo "${C_YEL}[!] Not running as root - some files (sshd_config, sudoers, shadow) may be unreadable; results may degrade to WARNING.${C_RST}"

# ------------------------------------------------------------------ 5.14 SSH key + passphrase
pubkey="$(sshd_val 'PubkeyAuthentication')"; pubkey="${pubkey:-yes}"    # default is yes
passwd_auth="$(sshd_val 'PasswordAuthentication')"; passwd_auth="${passwd_auth:-yes}"  # default yes
if [ ! -r /etc/ssh/sshd_config ]; then
    emit "5.14" "Required" "Do Linux/Unix Systems use SSH Private/Public Key with Passphrase credentials?" \
        "Warning" "/etc/ssh/sshd_config not readable" \
        "Verify PubkeyAuthentication=yes and PasswordAuthentication=no; key passphrase must be confirmed manually."
elif printf '%s' "$pubkey" | grep -qi '^yes' && printf '%s' "$passwd_auth" | grep -qi '^no'; then
    emit "5.14" "Required" "Do Linux/Unix Systems use SSH Private/Public Key with Passphrase credentials?" \
        "Passed" "PubkeyAuthentication=$pubkey; PasswordAuthentication=$passwd_auth" \
        "Key-based auth enforced. NOTE: SSH key *passphrase* cannot be verified server-side - confirm manually."
else
    emit "5.14" "Required" "Do Linux/Unix Systems use SSH Private/Public Key with Passphrase credentials?" \
        "Failed" "PubkeyAuthentication=$pubkey; PasswordAuthentication=$passwd_auth" \
        "Set PubkeyAuthentication yes and PasswordAuthentication no in sshd_config; use SSH keys with a passphrase."
fi

# ------------------------------------------------------------------ 5.15 SSH strong password (min 15)
minlen=""
if [ -r /etc/security/pwquality.conf ]; then
    minlen="$(grep -iE '^[[:space:]]*minlen[[:space:]]*=' /etc/security/pwquality.conf 2>/dev/null | tail -n1 | tr -d ' ' | cut -d= -f2)"
fi
if [ -z "$minlen" ] && [ -r /etc/pam.d/common-password ]; then
    minlen="$(grep -iE 'pam_(pwquality|cracklib)\.so' /etc/pam.d/common-password 2>/dev/null | grep -oE 'minlen=[0-9]+' | head -n1 | cut -d= -f2)"
fi
if [ -z "$minlen" ] && [ -r /etc/login.defs ]; then
    minlen="$(grep -iE '^[[:space:]]*PASS_MIN_LEN' /etc/login.defs 2>/dev/null | tail -n1 | awk '{print $2}')"
fi
if [ -z "$minlen" ]; then
    emit "5.15" "Required" "Does SSH use strong password enforcement where applicable? (min of 15 characters)" \
        "Warning" "No minlen/PASS_MIN_LEN policy found" \
        "Set minlen>=15 in /etc/security/pwquality.conf (or PAM) to enforce strong passwords."
elif [ "$minlen" -ge 15 ] 2>/dev/null; then
    emit "5.15" "Required" "Does SSH use strong password enforcement where applicable? (min of 15 characters)" \
        "Passed" "Minimum password length = $minlen" \
        "Password minimum length meets the 15-character requirement."
else
    emit "5.15" "Required" "Does SSH use strong password enforcement where applicable? (min of 15 characters)" \
        "Failed" "Minimum password length = $minlen" \
        "Increase minimum password length to >=15 characters."
fi

# ------------------------------------------------------------------ auditd state (used by 5.16)
auditd_active="unknown"
if command -v systemctl >/dev/null 2>&1; then
    auditd_active="$(systemctl is-active auditd 2>/dev/null || echo inactive)"
elif command -v service >/dev/null 2>&1; then
    service auditd status >/dev/null 2>&1 && auditd_active="active" || auditd_active="inactive"
fi

# ------------------------------------------------------------------ 5.16 dedicated audited account
if [ -z "$REPO_ACCOUNT" ]; then
    candidates="$(awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd 2>/dev/null | paste -sd',' -)"
    emit "5.16" "Advised if applicable" "Is a dedicated, audited account used for repository access" \
        "Warning" "No -a REPO_ACCOUNT supplied. auditd=$auditd_active. Candidate accounts: ${candidates:-none}" \
        "Re-run with -a <repo_account>. Ensure a dedicated account exists and auditd is active for auditing."
elif ! id "$REPO_ACCOUNT" >/dev/null 2>&1; then
    emit "5.16" "Advised if applicable" "Is a dedicated, audited account used for repository access" \
        "Failed" "Account '$REPO_ACCOUNT' does not exist" \
        "Create a dedicated repository account and enable auditd."
elif [ "$auditd_active" = "active" ]; then
    emit "5.16" "Advised if applicable" "Is a dedicated, audited account used for repository access" \
        "Passed" "Account '$REPO_ACCOUNT' exists; auditd=active" \
        "Dedicated account present and auditing is active."
else
    emit "5.16" "Advised if applicable" "Is a dedicated, audited account used for repository access" \
        "Warning" "Account '$REPO_ACCOUNT' exists; auditd=$auditd_active" \
        "Enable and start auditd so repository-account activity is audited."
fi

# ------------------------------------------------------------------ 5.17 repo account NOT root / not sudoer
if [ -z "$REPO_ACCOUNT" ]; then
    emit "5.17" "Required" "Is the account for repository access NOT root, or a member of Sudoers" \
        "Warning" "No -a REPO_ACCOUNT supplied" \
        "Re-run with -a <repo_account> to verify it is non-root and not in sudoers (KB2676)."
elif ! id "$REPO_ACCOUNT" >/dev/null 2>&1; then
    emit "5.17" "Required" "Is the account for repository access NOT root, or a member of Sudoers" \
        "Failed" "Account '$REPO_ACCOUNT' does not exist" \
        "Create a non-root repository account that is not in sudoers."
else
    uid="$(id -u "$REPO_ACCOUNT" 2>/dev/null)"
    grps="$(id -nG "$REPO_ACCOUNT" 2>/dev/null)"
    in_sudo_grp="no"
    printf '%s' " $grps " | grep -qE ' (sudo|wheel|root) ' && in_sudo_grp="yes"
    in_sudoers="no"
    if [ -r /etc/sudoers ]; then
        { grep -REl "^[[:space:]]*${REPO_ACCOUNT}[[:space:]]" /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -q . ; } && in_sudoers="yes"
    else
        in_sudoers="unknown(not readable)"
    fi
    if [ "$uid" = "0" ]; then
        emit "5.17" "Required" "Is the account for repository access NOT root, or a member of Sudoers" \
            "Failed" "Account '$REPO_ACCOUNT' is root (uid=0)" \
            "Use a non-root account for repository access (KB2676)."
    elif [ "$in_sudo_grp" = "yes" ] || [ "$in_sudoers" = "yes" ]; then
        emit "5.17" "Required" "Is the account for repository access NOT root, or a member of Sudoers" \
            "Failed" "uid=$uid; groups=$grps; in sudoers=$in_sudoers" \
            "Remove '$REPO_ACCOUNT' from sudo/wheel groups and sudoers (KB2676)."
    else
        emit "5.17" "Required" "Is the account for repository access NOT root, or a member of Sudoers" \
            "Passed" "uid=$uid; groups=$grps; in sudoers=$in_sudoers" \
            "Account is non-root and not a sudoer."
    fi
fi

# ------------------------------------------------------------------ 5.18 service account: non-root + SUDOER/Firewall/PAM
# Firewall state.
fw="none"
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    fw="firewalld(running)"
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then
    fw="ufw(active)"
elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
    fw="nftables(rules present)"
elif command -v iptables >/dev/null 2>&1 && iptables -S 2>/dev/null | grep -qvE '^-P|^$'; then
    fw="iptables(rules present)"
fi
# PAM present.
pam="no"; { [ -d /etc/pam.d ] && [ -n "$(ls -A /etc/pam.d 2>/dev/null)" ]; } && pam="yes"

if [ -z "$REPO_ACCOUNT" ]; then
    emit "5.18" "Required" "Where required, is LINUX service account \"NOT\" root but leverages SUDOER, Firewall and PAM security?" \
        "Warning" "No -a account supplied. Firewall=$fw; PAM=$pam" \
        "Re-run with -a <service_account>. Ensure non-root account + firewall + PAM are in place."
else
    uid="$(id -u "$REPO_ACCOUNT" 2>/dev/null || echo NA)"
    if [ "$uid" != "0" ] && [ "$uid" != "NA" ] && [ "$fw" != "none" ] && [ "$pam" = "yes" ]; then
        emit "5.18" "Required" "Where required, is LINUX service account \"NOT\" root but leverages SUDOER, Firewall and PAM security?" \
            "Passed" "account '$REPO_ACCOUNT' uid=$uid; Firewall=$fw; PAM=$pam" \
            "Non-root service account with firewall and PAM in place."
    else
        emit "5.18" "Required" "Where required, is LINUX service account \"NOT\" root but leverages SUDOER, Firewall and PAM security?" \
            "Failed" "account '$REPO_ACCOUNT' uid=$uid; Firewall=$fw; PAM=$pam" \
            "Ensure the service account is non-root and that firewall + PAM protections are enabled."
    fi
fi

echo ""
echo "${C_CYAN}===============================================================${C_RST}"
echo "  Linux audit summary - Passed: ${PASS}  Failed: ${FAIL}  Warning: ${WARN}"
echo "  CSV report: ${OUT_CSV}"
echo "${C_CYAN}===============================================================${C_RST}"
