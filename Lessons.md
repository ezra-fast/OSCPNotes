root in the default username for mysql connections; ALWAYS try root as the username    --> define('DB_SERVER_USERNAME', ''); means the username is root

Always check the web root for .git folder

Always try the username as the password

search for other database usernames passwords using grep
    
        grep -r "dbname=" / 2>/dev/null

        define('DB_SERVER_USERNAME'

Port scans may not properly pick up UDP ports; manually try to detect tftp running on port 69 with:

        nmap -n -Pn -sU -p69 -sV --script tftp-enum 192.168.228.222

        admin/tftp/tftp_transfer_util

Enumerate all services, not just running services

Use PowerUp.ps1 to enumerate DLL hijacking, service binary replacement, and unquoted service paths

sniff all network interfaces for secrets; port 514 is syslog; if tcpdump is on the system, use it            --> tcpdump -vv -i ens192 | grep -E 'ass|oot|ser'

VNC runs on port 5900 and 5901 --> ALWAYS check port 5901 for VNC

/usr/share/wordlists/fasttrack.txt can be used to crack if rockyou.txt is exhausted

Always add any kind of virtual routing/name resolution to /etc/hosts, even if it is not needed

loot literally every single user/home/config/program folder that is not native to Windows/Linux. look for .ini, .conf, .config, .txt, etc.

Umbraco alternative webroot can be found at: umbraco/bin/Debug/net6.0/publish/wwwroot/

feroxbuster often misses files; use gobuster to find directories and once you're out of directories, use gobuster with -x

use masscan to discover all TCP/UDP ports

always spray null credentials on SMB/Windows hosts

Privesc often involves compromising web/www/database users first 

nmap doesn't version non-standard ports correctly

always enumerate 127.0.0.1:XX services and forward them out

no more directories to bust? look for files with -x or feroxbuster

always try default credentials (admin : admin, user : password, admin : password, etc.)

try  relaying NetNTLMv2 if you cannot crack it

always look for .kdbx files

doas is the same as sudo; enumerate for the contents of doas.conf

enumerate all user home folders

enumerate for AlwaysInstallElevated

