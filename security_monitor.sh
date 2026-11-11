#!/usr/bin/env bash
#https://www.man7.org/linux/man-pages/man1/env.1.html   
# ==============================================================================
# Script Name: security_monitor.sh
# Description: Linux security audit script for Ubuntu and CentOS Stream 10.
#              Audits failed SSH logins, UID 0 accounts, empty passwords,
#              and listening ports.
# ==============================================================================

# Ensure a secure and predictable PATH for cron execution
#https://www.gnu.org/software/bash/manual/bash.html#Bourne-Shell-Variables
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Configuration
#https://www.gnu.org/software/bash/manual/bash.html#Shell-Parameters 
REPORT_DIR="/var/log/security_reports"
#https://www.gnu.org/software/coreutils/manual/html_node/date-invocation.html 
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
#https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html
REPORT_FILE="${REPORT_DIR}/security_report_${TIMESTAMP}.txt"

# Ensure the report directory exists with secure permissions
#https://man7.org/linux/man-pages/man1/mkdir.1.html 
#https://medium.com/@laxman.pokhrel.101/chmod-360b47cccc82  
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

# Exit status tracker (0 = OK, 1 = Security Issue Detected)
https://www.gnu.org/software/bash/manual/html_node/Exit-Status.html
exit_code=0

# Begin logging to stdout and the timestamped report file simultaneously
#https://www.gnu.org/software/bash/manual/html_node/Command-Grouping.html
{
#https://man7.org/linux/man-pages/man1/echo.1.html
    echo "=== Linux Security Monitoring Report ==="
#https://man7.org/linux/man-pages/man1/echo.1.html
    echo "Hostname: $(hostname)" 
#https://www.gnu.org/software/coreutils/manual/html_node/date-invocation.html 
    echo "Timestamp: $(date)"
#https://man7.org/linux/man-pages/man1/echo.1.html 
    echo "----------------------------------------"
    
    # --------------------------------------------------------------------------
    # 1. Report failed SSH logins from the last 24 hours
    # --------------------------------------------------------------------------
    #https://man7.org/linux/man-pages/man1/echo.1.html 
    echo -e "\n[1] Failed SSH Logins (Last 24 Hours):"
    #https://www.gnu.org/software/bash/manual/html_node/Redirections.html
    #https://www.gnu.org/software/bash/manual/html_node/Redirections.html
    if command -v journalctl >/dev/null 2>&1; then
        # Query systemd journal for ssh/sshd failed attempts in the last 24h
        #https://www.geeksforgeeks.org/linux-unix/grep-command-in-unixlinux/  
        #https://man7.org/linux/man-pages/man1/journalctl.1.html 
        FAILED_SSH=$(journalctl _COMM=sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -i "failed" || true)
    #https://www.gnu.org/software/bash/manual/html_node/Bash-Conditional-Expressions.html 
    else
        # Fallback to standard log files if journalctl is unavailable
        #https://www.gnu.org/software/bash/manual/bash.html 
        if [ -f /var/log/auth.log ]; then
            #https://www.gnu.org/software/bash/manual/bash.html 
            FAILED_SSH=$(grep -i "failed" /var/log/auth.log 2>/dev/null || true)
        #https://www.gnu.org/software/bash/manual/bash.html    
        elif [ -f /var/log/secure ]; then
            #https://www.geeksforgeeks.org/linux-unix/grep-command-in-unixlinux/
            FAILED_SSH=$(grep -i "failed" /var/log/secure 2>/dev/null || true)
        #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs 
        else
            #https://www.gnu.org/software/bash/manual/bash.html#Shell-Parameters 
            FAILED_SSH="Log file not accessible."
        #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs 
        fi
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs      
    fi
    
    #https://www.gnu.org/software/bash/manual/bash.html#Bash-Conditional-Expressions 
    if [ -n "$FAILED_SSH" ]; then
        #https://man7.org/linux/man-pages/man1/echo.1.html  
        echo "$FAILED_SSH"
        #https://man7.org/linux/man-pages/man1/wc.1.html 
        FAILED_COUNT=$(echo "$FAILED_SSH" | wc -l)
        #https://man7.org/linux/man-pages/man1/echo.1.html  
        echo "Total failed login log entries: $FAILED_COUNT"
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs     
    else
        #https://man7.org/linux/man-pages/man1/echo.1.html  
        echo "No failed SSH logins found in the last 24 hours."
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs      
    fi

    # --------------------------------------------------------------------------
    # 2. List accounts with UID 0
    # --------------------------------------------------------------------------
    #https://man7.org/linux/man-pages/man1/echo.1.html  
    echo -e "\n[2] Accounts with UID 0:"
    #https://www.geeksforgeeks.org/linux-unix/awk-command-unixlinux-examples/
    UID0_ACCOUNTS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
    #https://man7.org/linux/man-pages/man1/echo.1.html  
    #https://www.gnu.org/software/bash/manual/bash.html#Bash-Conditional-Expressions 
    echo "$UID0_ACCOUNTS"
    
    # Check if any account other than 'root' has UID 0 (a severe security risk)
    #https://www.geeksforgeeks.org/linux-unix/grep-command-in-unixlinux/  
    NON_ROOT_UID0=$(echo "$UID0_ACCOUNTS" | grep -v "^root$")
    #https://www.gnu.org/software/bash/manual/bash.html#Bash-Conditional-Expressions 
    if [ -n "$NON_ROOT_UID0" ]; then
        #https://man7.org/linux/man-pages/man1/echo.1.html  
        echo "[!] WARNING: Non-root accounts with UID 0 detected: $NON_ROOT_UID0"
        #https://www.gnu.org/software/bash/manual/bash.html#Exit-Status 
        exit_code=1
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs      
    fi

    # --------------------------------------------------------------------------
    # 3. Identify accounts with empty passwords
    # --------------------------------------------------------------------------
    #https://man7.org/linux/man-pages/man1/echo.1.html  
    echo -e "\n[3] Accounts with Empty Passwords:"
    #https://www.gnu.org/software/bash/manual/bash.html#Bash-Conditional-Expressions 
    if [ -r /etc/shadow ]; then
        # An empty second field in /etc/shadow indicates an unencrypted/empty password
        #https://www.geeksforgeeks.org/linux-unix/awk-command-unixlinux-examples/
        EMPTY_PASS_ACCOUNTS=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs  
    else
        #https://man7.org/linux/man-pages/man1/echo.1.html   
        echo "[!] ERROR: Unable to read /etc/shadow (requires root privileges)."
        #https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html
        EMPTY_PASS_ACCOUNTS=""
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs  
    fi

    #https://www.gnu.org/software/bash/manual/bash.html#Bash-Conditional-Expressions
    if [ -n "$EMPTY_PASS_ACCOUNTS" ]; then
        echo "[!] CRITICAL: Accounts with empty passwords found: $EMPTY_PASS_ACCOUNTS"
        exit_code=1
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs      
    else
        echo "No accounts with empty passwords found."
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs  
    fi

    # --------------------------------------------------------------------------
    # 4. List listening ports using ss
    # --------------------------------------------------------------------------
    #https://man7.org/linux/man-pages/man1/echo.1.html  
    echo -e "\n[4] Listening Ports (ss -tuln):"
    #https://www.gnu.org/software/bash/manual/bash.html  
    if command -v ss >/dev/null 2>&1; then
        #https://man7.org/linux/man-pages/man8/ss.8.html 
        ss -tuln
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs
    else
        #https://man7.org/linux/man-pages/man1/echo.1.html 
        echo "[!] ERROR: 'ss' command not found."
        #https://www.gnu.org/software/bash/manual/bash.html#Exit-Status 
        exit_code=1
    #https://www.gnu.org/software/bash/manual/bash.html#Conditional-Constructs  
    fi

    #https://man7.org/linux/man-pages/man1/echo.1.html 
    echo "----------------------------------------"
    #https://man7.org/linux/man-pages/man1/echo.1.html 
    echo "Audit completed with exit status: $exit_code"
#https://man7.org/linux/man-pages/man1/tee.1.html     
} | tee "$REPORT_FILE"

# Exit with non-zero status if a security violation was flagged
#https://man7.org/linux/man-pages/man3/exit.3.html  
exit "$exit_code"
