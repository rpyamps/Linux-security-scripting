#!/usr/bin/env bash
# ==============================================================================
# Script Name: security_monitor.sh
# Description: Linux security audit script for Ubuntu and CentOS Stream 10.
#              Audits failed SSH logins, UID 0 accounts, empty passwords,
#              and listening ports.
# ==============================================================================

# Ensure a secure and predictable PATH for cron execution
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Configuration
REPORT_DIR="/var/log/security_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/security_report_${TIMESTAMP}.txt"

# Ensure the report directory exists with secure permissions
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

# Exit status tracker (0 = OK, 1 = Security Issue Detected)
exit_code=0

# Begin logging to stdout and the timestamped report file simultaneously
{
    echo "=== Linux Security Monitoring Report ==="
    echo "Hostname: $(hostname)"
    echo "Timestamp: $(date)"
    echo "----------------------------------------"
    
    # --------------------------------------------------------------------------
    # 1. Report failed SSH logins from the last 24 hours
    # --------------------------------------------------------------------------
    echo -e "\n[1] Failed SSH Logins (Last 24 Hours):"
    if command -v journalctl >/dev/null 2>&1; then
        # Query systemd journal for ssh/sshd failed attempts in the last 24h
        FAILED_SSH=$(journalctl _COMM=sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -i "failed" || true)
    else
        # Fallback to standard log files if journalctl is unavailable
        if [ -f /var/log/auth.log ]; then
            FAILED_SSH=$(grep -i "failed" /var/log/auth.log 2>/dev/null || true)
        elif [ -f /var/log/secure ]; then
            FAILED_SSH=$(grep -i "failed" /var/log/secure 2>/dev/null || true)
        else
            FAILED_SSH="Log file not accessible."
        fi
    fi

    if [ -n "$FAILED_SSH" ]; then
        echo "$FAILED_SSH"
        FAILED_COUNT=$(echo "$FAILED_SSH" | wc -l)
        echo "Total failed login log entries: $FAILED_COUNT"
    else
        echo "No failed SSH logins found in the last 24 hours."
    fi

    # --------------------------------------------------------------------------
    # 2. List accounts with UID 0
    # --------------------------------------------------------------------------
    echo -e "\n[2] Accounts with UID 0:"
    UID0_ACCOUNTS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
    echo "$UID0_ACCOUNTS"
    
    # Check if any account other than 'root' has UID 0 (a severe security risk)
    NON_ROOT_UID0=$(echo "$UID0_ACCOUNTS" | grep -v "^root$")
    if [ -n "$NON_ROOT_UID0" ]; then
        echo "[!] WARNING: Non-root accounts with UID 0 detected: $NON_ROOT_UID0"
        exit_code=1
    fi

    # --------------------------------------------------------------------------
    # 3. Identify accounts with empty passwords
    # --------------------------------------------------------------------------
    echo -e "\n[3] Accounts with Empty Passwords:"
    if [ -r /etc/shadow ]; then
        # An empty second field in /etc/shadow indicates an unencrypted/empty password
        EMPTY_PASS_ACCOUNTS=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
    else
        echo "[!] ERROR: Unable to read /etc/shadow (requires root privileges)."
        EMPTY_PASS_ACCOUNTS=""
        exit_code=1
    fi

    if [ -n "$EMPTY_PASS_ACCOUNTS" ]; then
        echo "[!] CRITICAL: Accounts with empty passwords found: $EMPTY_PASS_ACCOUNTS"
        exit_code=1
    else
        echo "No accounts with empty passwords found."
    fi

    # --------------------------------------------------------------------------
    # 4. List listening ports using ss
    # --------------------------------------------------------------------------
    echo -e "\n[4] Listening Ports (ss -tuln):"
    if command -v ss >/dev/null 2>&1; then
        ss -tuln
    else
        echo "[!] ERROR: 'ss' command not found."
        exit_code=1
    fi

    echo "----------------------------------------"
    echo "Audit completed with exit status: $exit_code"
} | tee "$REPORT_FILE"

# Exit with non-zero status if a security violation was flagged
exit "$exit_code"
