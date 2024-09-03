root in the default username for mysql connections; ALWAYS try root as the username    --> define('DB_SERVER_USERNAME', ''); means the username is root

search for other database usernames passwords using grep
    
        grep -r "dbname=" / 2>/dev/null

        define('DB_SERVER_USERNAME'

Enumerate all services, not just running services

Use PowerUp.ps1 to enumerate DLL hijacking, service binary replacement, and unquoted service paths

Always add any kind of virtual routing/name resolution to /etc/hosts, even if it is not needed

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

