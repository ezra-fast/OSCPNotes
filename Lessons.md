root in the default username for mysql connections; ALWAYS try root as the username    --> define('DB_SERVER_USERNAME', ''); means the username is root

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

