#https://www.gnu.org/software/bash/manual/html_node/Shell-Scripts.html  
#!/bin/bash

#Security Monitoring scipt for Ubuntu and CentOS
#https://www.gnu.org/software/coreutils/manual/html_node/date-invocation.html 
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S") #Gets the current date and time for the report Source https://www.gnu.org/software/coreutils/manual/html_node/date-invocation.html

#https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html 
REPORT_DIR="$HOME/security-reports" #Set the directory where the security report will be saved

#https://man7.org/linux/man-pages/man1/mkdir.1.html 
mkdir -p "$REPORT_DIR" #Creates the report directory if it does not exist #source https://www.gnu.org/software/coreutils/manual/html_node/mkdir-invocation.html

#creates timestamp filename for the security report
#https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html
REPORT_FILE="$REPORT_DIR/security_report_$TIMESTAMP.txt"

#Write a title at the beginning of the security report
#SOURCE: https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html
echo "Ubuntu Security Report" > "$REPORT_FILE"

#Writes the date and time the report was generated 
#SOURCE: https://www.gnu.org/software/bash/manual/html_node/Redirections.html
echo "Report Generated: $(date)" >> "$REPORT_FILE"

#Add a heading for failed SSH login attemps
#https://www.gnu.org/software/bash/manual/html_node/Redirections.html
echo "Failed SSH Logins (Last 24 hours):" >> "$REPORT_FILE"

#Find failed ssh password attempts from the last 24 hours
#SOURCE https://www.freedesktop.org/software/systemd/man/latest/journalctl.html
journalctl -u ssh --since "24 hours ago" --no-pager | grep "Failed Password" >> "$REPORT_FILE"

#Add a heading for accounts with root privileges
#https://www.gnu.org/software/bash/manual/html_node/Redirections.html
echo "Accounts with UID o:" >> "$REPORT_FILE"

#Find and report accounts with UID 0
#SOURCE https://www.gnu.org/software/gawk/manual/gawk.html
awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$REPORT_FILE"

#Add a heading for accounts with empty passwords
#SOURCE https://www.gnu.org/software/gawk/manual/gawk.html
echo "Accounts woth Empty Password:" >> "$REPORT_FILE"



#Check for accounts with empty passwords
#SOURCE https://www.gnu.org/software/gawk/manual/gawk.html
#https://man7.org/linux/man-pages/man5/shadow.5.html 
#https://www.geeksforgeeks.org/linux-unix/awk-command-unixlinux-examples/
if awk -F: '$2 == "" {found=1} END {exit !found}' /etc/shadow; then
	#https://www.gnu.org/software/bash/manual/html_node/Redirections.html
	echo "WARNING: Empty Password detected!" >> "$REPORT_FILE"
	#https://www.gnu.org/software/bash/manual/html_node/Exit-Status.html
	exit 1 
#https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html 
fi

#ADD a heading for listening network ports
#SOURCE https://man7.org/linux/man-pages/man8/ss.8.html
echo "Listening TCP and UDP Port:" >> "$REPORT_FILE"

#List listening TCP and UDP ports 
#SOURCE https: https://man7.org/linux/man-pages/man8/ss.8.html
ss -tuln >> "$REPORT_FILE"

