#!/bin/bash

# Output file
output_file="linux_enum_$(date +%Y%m%d_%H%M%S).txt"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print and log output
log() {
  echo -e "$1" | tee -a $output_file
}

# Header
log "${CYAN}===== Linux Enumeration Script =====${NC}\n"

# 1. Basic System Information
log "${GREEN}[+] Basic System Information${NC}"
log "${YELLOW}Kernel Information:${NC}"
uname -a | tee -a $output_file
log "${YELLOW}OS Version:${NC}"
cat /etc/*release | tee -a $output_file
log "${YELLOW}System Architecture:${NC}"
arch | tee -a $output_file
log "${YELLOW}Hostname:${NC}"
hostname | tee -a $output_file
log "${YELLOW}System Uptime:${NC}"
uptime | tee -a $output_file
log "${YELLOW}System Date and Time:${NC}"
date | tee -a $output_file
log "${YELLOW}List of Running Processes:${NC}"
ps aux | tee -a $output_file
log ""

# 2. User and Group Information
log "${GREEN}[+] User and Group Information${NC}"
log "${YELLOW}Current User:${NC}"
whoami | tee -a $output_file
log "${YELLOW}User ID and Group ID:${NC}"
id | tee -a $output_file
log "${YELLOW}List All Users:${NC}"
cat /etc/passwd | tee -a $output_file
log "${YELLOW}List All Groups:${NC}"
cat /etc/group | tee -a $output_file
log "${YELLOW}List Logged In Users:${NC}"
who | tee -a $output_file
log "${YELLOW}Check Last Logins:${NC}"
last | tee -a $output_file
log "${YELLOW}Find Users with UID 0 (Root Accounts):${NC}"
awk -F: '($3 == 0) {print}' /etc/passwd | tee -a $output_file
log "${YELLOW}Check Sudo Permissions:${NC}"
sudo -l | tee -a $output_file
log ""

# 3. Network Configuration
log "${GREEN}[+] Network Configuration${NC}"
log "${YELLOW}Display Network Interfaces:${NC}"
ifconfig -a | tee -a $output_file
log "${YELLOW}View Routing Table:${NC}"
route -n | tee -a $output_file
log "${YELLOW}Check Open Ports:${NC}"
netstat -tuln | tee -a $output_file
log "${YELLOW}Show Active Network Connections:${NC}"
netstat -antp | tee -a $output_file
log "${YELLOW}Check Firewall Rules (iptables):${NC}"
iptables -L | tee -a $output_file
log "${YELLOW}DNS Resolution:${NC}"
cat /etc/resolv.conf | tee -a $output_file
log "${YELLOW}Display ARP Cache:${NC}"
arp -a | tee -a $output_file
log "${YELLOW}List Active Network Connections with Process Information:${NC}"
lsof -i | tee -a $output_file
log ""

# 4. Filesystem Enumeration
log "${GREEN}[+] Filesystem Enumeration${NC}"
log "${YELLOW}Current Directory:${NC}"
pwd | tee -a $output_file
log "${YELLOW}List Files in Directory:${NC}"
ls -alh | tee -a $output_file
log "${YELLOW}List Files with Full Paths:${NC}"
find $(pwd) -type f | tee -a $output_file
log "${YELLOW}Find World-Writable Files:${NC}"
find / -perm -2 -type f 2>/dev/null | tee -a $output_file
log "${YELLOW}Find SUID and SGID Files:${NC}"
find / -perm /4000 2>/dev/null | tee -a $output_file
log "${YELLOW}List Recently Modified Files:${NC}"
find / -type f -mtime -10 2>/dev/null | tee -a $output_file
log "${YELLOW}Check Disk Usage:${NC}"
df -h | tee -a $output_file
log "${YELLOW}List Mounted Filesystems:${NC}"
mount | tee -a $output_file
log "${YELLOW}Check for Hidden Files:${NC}"
find / -name ".*" 2>/dev/null | tee -a $output_file
log ""

# 5. Installed Software and Services
log "${GREEN}[+] Installed Software and Services${NC}"
log "${YELLOW}List Installed Packages (Debian/Ubuntu):${NC}"
dpkg -l | tee -a $output_file
log "${YELLOW}List Installed Packages (RedHat/CentOS):${NC}"
rpm -qa | tee -a $output_file
log "${YELLOW}List Running Services (Systemd):${NC}"
systemctl list-units --type=service --state=running | tee -a $output_file
log "${YELLOW}List Running Services (SysVinit):${NC}"
service --status-all | tee -a $output_file
log "${YELLOW}Check for Installed Compilers:${NC}"
gcc --version | tee -a $output_file
log "${YELLOW}List Installed Languages and Tools:${NC}"
which perl python ruby gcc | tee -a $output_file
log ""

# 6. Scheduled Tasks and Jobs
log "${GREEN}[+] Scheduled Tasks and Jobs${NC}"
log "${YELLOW}List Cron Jobs:${NC}"
crontab -l | tee -a $output_file
log "${YELLOW}List System-Wide Cron Jobs:${NC}"
ls -la /etc/cron* | tee -a $output_file
log "${YELLOW}Check At Jobs:${NC}"
atq | tee -a $output_file
log ""

# 7. Environment Variables
log "${GREEN}[+] Environment Variables${NC}"
log "${YELLOW}View Environment Variables:${NC}"
env | tee -a $output_file
log "${YELLOW}List Path Directories:${NC}"
echo $PATH | tee -a $output_file
log ""

# 8. Logs and Auditing
log "${GREEN}[+] Logs and Auditing${NC}"
log "${YELLOW}Check Syslog:${NC}"
cat /var/log/syslog | tee -a $output_file
log "${YELLOW}Check Authentication Logs:${NC}"
cat /var/log/auth.log | tee -a $output_file
log "${YELLOW}Check for Command History:${NC}"
cat ~/.bash_history | tee -a $output_file
log "${YELLOW}Check Audit Logs:${NC}"
ausearch -m avc | tee -a $output_file
log ""

# 9. Processes and Privilege Escalation
log "${GREEN}[+] Processes and Privilege Escalation${NC}"
log "${YELLOW}List Processes Running as Root:${NC}"
ps -U root -u root u | tee -a $output_file
log "${YELLOW}Check for Running Docker Containers:${NC}"
docker ps | tee -a $output_file
log "${YELLOW}Enumerate Capabilities:${NC}"
getcap -r / 2>/dev/null | tee -a $output_file
log "${YELLOW}Find Processes with Specific Capability:${NC}"
pscap | tee -a $output_file
log "${YELLOW}Check for Writable Directories in PATH:${NC}"
for x in $(echo $PATH | tr ':' ' '); do ls -ld $x; done | tee -a $output_file
log ""

log "${CYAN}===== Enumeration Complete =====${NC}\n"
log "Results saved to ${output_file}"


