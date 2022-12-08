<# 
.NOTES 
    File Name  : ESXi_7.0_VCF_Prep.ps1 
    Author     : coslush
    Version    : 0.1
    License    : Apache-2.0
    
	.PARAMETER disableCEIP
	Set this flag to disable CEIP on the ESXi host
	.PARAMETER esxicred
    Enter the pscredential variable name to use for authentication to the ESXi host. This can be run before the script for example: $cred = get-pscredential 
	.PARAMETER hostnames
    Enter the FQDN/IP or list of FQDN/IPs of the ESXi Server(s) to prep for VCF
	.PARAMETER matchVMNetwork
	Set this flag to match the vlan set on the VM Network portgroup to the vlan defined on the Management Network portgroup
	.PARAMETER ntpServers
	Set this to configure the NTP servers
	.PARAMETER restartHost
	Set this to restart the host at the end of the configuration process. If set, this is the very last action performed before disconnecting from the host
	.PARAMETER restartServices
	Set this to restart only the services at the end of the configuration process
	.PARAMETER rollCerts
	Set this to regenerate the host certificate using the built-in utility. This sets the CN of the certificate to the FQDN
	.PARAMETER rollvmk0
	Set this to replace the current vmk0 with a new one of the same IP address. This needs to leverage a temporary IP address on the same network as the existing vmk0
	.PARAMETER updateHost
	Set this to update the host to the specified profile using the address of the offline repo provided

.SYNOPSIS 
    Configures the required settings on an ESXi host for a VCF deployment
	
.DESCRIPTION
    Configures a number of the required settings on an ESXi host for a VCF deployment. 

	The settings that can be adjusted are:
	- CEIP Settings (Disable Only)
	- VM Network VLAN (Match Management Network)
	- NTP Servers (List of servers by FQDN/IP)
	- Host Certificate (Only CN set to FQDN)
	- VM Kernel Adapter vmk0 (MAC set to new virtual address)
	- Host Software Profile (Profile available on offline repo only)
	- Service state (Restart only)
	- Power State (Restart only)
		
	The settings that CANNOT be adjusted are:
	- NTP Service State (Running)
	- NTP Service Policy (Start and stop with host)
	- SSH Service State (Running)
	- SSH Service Policy (Start and stop with host)
	- ESXCLI Service State (Stopped)
	- ESXCLI Service Policy (Start and stop manually)

.EXAMPLE
	.\ESXi_7.0_VCF_Prep.ps1 -hostname esxihost.example.lab
	
	Single hostname example where the user is prompted for login credentials at runtime
.EXAMPLE
	$myesxilogin = Get-Credential
	PS > .\ESXi_7.0_VCF_Prep.ps1 -hostname esxihostname.example.lab -esxicred $myesxilogin
	
	Single hostname example where the user has already run Get-Credential and stored the result in a variable
.EXAMPLE
	$myesxilogin = Get-Credential
	PS > .\ESXi_7.0_VCF_Prep.ps1 -hostname "esxi01.example.lab","esxi02.example.lab" -esxicred $myesxilogin
	
	Multiple hostname example where the user has already run Get-Credential and stored the result in a variable
.EXAMPLE
	$myesxilogin = Get-Credential
	PS > .\ESXi_7.0_VCF_Prep.ps1 -hostname "esxi01.example.lab","esxi02.example.lab" -esxicred $myesxilogin -disableCEIP -matchVMNetwork -ntpServers "ntp01.example.lab","ntp02.example.lab" -rollvmk0 192.168.1.2 -rollCerts -restartServices
	
	Multiple hostname example where the user has already run Get-Credential and stored the result in a variable
.EXAMPLE
	$myesxilogin = Get-Credential
	PS > .\ESXi_7.0_VCF_Prep.ps1 -hostname "esxi01.example.lab","esxi02.example.lab" -esxicred $myesxilogin -rollvmk0 192.168.1.2 -rollCerts -updateHost "ESXi-7.0U1d-17551050-standard","https://webserver/VMware-ESXi-7.0U1d-17551050-depot/index.xml" -restartHost
	
	Multiple hostname example where the user has already run Get-Credential and stored the result in a variable
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,ParameterSetName="hostnames")]
    [string[]]$hostnames,

    [Parameter(Mandatory=$true)]
    [pscredential]$esxicred,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to disable VMware's CEIP on the host.")]
    [switch]$disableCEIP,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to match the 'VM Network' portgroup VLAN configuration with the 'Management Network' portrgoup VLAN configuration.")]
    [switch]$matchVMNetwork,

	[Parameter(Mandatory=$false,
    HelpMessage="Enter a comma-separated list of hostnames/IPs to use for NTP servers. Ex: `"192.168.1.1`",`"ntp.local`"")]
    [string[]]$ntpServers,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to roll the host certificates.")]
    [switch]$rollCerts,

    [Parameter(Mandatory=$false,
    HelpMessage="Enter the IP of the temporary vmkernel adapter. Ex: `"192.168.1.1`"")]
    [string]$rollvmk0,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to restart host services.")]
    [switch]$restartServices,

	[Parameter(Mandatory=$false,
    HelpMessage="Enter a comma-separated list for the profile and update depot URL. Ex: `"ESXi-7.0U1d-17551050-standard`",`"https://webserver/VMware-ESXi-7.0U1d-17551050-depot/index.xml`"")]
    [string[]]$updateHost,
	
    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to restart the host after all other configuration changes have been made.")]
    [switch]$restartHost
)

#Modules needed to run script and load
$modules = @("Posh-SSH")

#Check for correct modules
Function checkModule ($m){
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        Write-Host "Module $m is already imported."
    }
    else{
        Write-Host "Trying to import module $m"
        Import-Module $m -Verbose
    }
}

#Load Modules
Try
{
    ForEach($module in $modules){
        checkModule $module
    }
}
Catch
{
    Write-Error "Failed to load modules"
    Write-Error $_.Exception
    Exit
}

foreach($hostname in $hostnames){
	# Identify host being worked on
	Write-Host
	Write-Host "Current host is $hostname" -ForegroundColor Blue
	
	# Connect to the host
	Write-Host
	Write-Host "Connecting to the ESXi host $hostname via HTTPS"
	Try {
		Connect-VIServer $hostname -Credential $esxicred -Protocol https -ErrorAction Stop | Out-Null
		$vmhost = Get-VMHost -Name $hostname
		
	}
	Catch {
		Write-Error "Failed to connect to $hostname via HTTPS"
		Write-Error $_.Exception
		Exit -1
	}
	Write-Host "...Connected to $hostname via HTTPS" -ForegroundColor Green
	Write-Host

	# Disable CEIP
	Write-Host "Adjusting CEIP configuration"
	Try {
		if($disableCEIP){
			Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.HostClientCEIPOptIn | Set-AdvancedSetting -Value 2 -Confirm:$false | Out-Null
			Write-Host "...CEIP Disabled!" -ForegroundColor Green
			Write-Host
		}
		else {
			Write-Host "...Leaving CEIP configuration alone" -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to disable CEIP"
		Write-Error $_.Exception
		Exit -1
	}

	# Match VM Network
	Write-Host "Adjusting 'VM Network' portgroup configuration"
	Try {
		if($matchVMNetwork){
			$mgmtPG = Get-VirtualPortGroup -VMHost $vmhost -Name "Management Network"
			Get-VirtualPortGroup -VMHost $vmhost -Name "VM Network" | Set-VirtualPortGroup -VLanId $mgmtPG.VLanId | Out-Null
			Write-Host "...'VM Network' VLAN set!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...Leaving 'VM Network' configuration alone" -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to adjust 'VM Network' settings"
		Write-Error $_.Exception
		Exit -1
	}

	# Set NTP Servers
	Write-Host "Setting NTP Server configuration"
	Try {
		if($ntpServers.Count -gt 0){
			$currNTP = Get-VMHostNtpServer -VMHost $vmhost 
			if ($currNTP -ne $null){
				Remove-VMHostNtpServer -VMHost $vmhost $currNTP -Confirm:$false | Out-Null
			}
			foreach($ntpServer in $ntpServers){
				Get-VMHost -Name $hostname | Add-VMHostNtpServer $ntpServer | Out-Null
			}
			Write-Host "...NTP server(s) set!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...Leaving NTP server configuration alone." -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to set NTP server(s)"
		Write-Error $_.Exception
		Exit -1
	}

	# Set NTP Service Policy
	Write-Host "Setting NTP Service Policy"
	Try {
		Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On | Out-Null
		Write-Host "...NTP service policy set!" -ForegroundColor Green
		Write-Host
	}
	Catch {
		Write-Error "Failed to set NTP policy"
		Write-Error $_.Exception
		Exit -1
	}

	# Start NTP Service
	Write-Host "Starting NTP Service"
	Try {
		Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService | Out-Null
		Write-Host "...NTP service started!" -ForegroundColor Green
		Write-Host
	}
	Catch {
		Write-Error "Failed to start NTP service"
		Write-Error $_.Exception
		Exit -1
	}

	# Set SSH Service Policy
	Write-Host "Setting SSH Service Policy"
	Try {
		Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Set-VMHostService -Policy On | Out-Null
		Write-Host "...SSH service policy set!" -ForegroundColor Green
		Write-Host
	}
	Catch {
		Write-Error "Failed to set SSH policy"
		Write-Error $_.Exception
		Exit -1
	}

	# Start SSH Service
	Write-Host "Starting SSH Service"
	Try {
		Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Start-VMHostService | Out-Null
		Write-Host "...SSH service started!" -ForegroundColor Green
		Write-Host
	}
	Catch {
		Write-Error "Failed to start SSH service"
		Write-Error $_.Exception
		Exit -1
	}

	# Set ESXi Shell Service Policy
	Write-Host "Setting SSH Service Policy"
	Try {
		Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Set-VMHostService -Policy Off | Out-Null
		Write-Host "...ESXi shell service policy set!" -ForegroundColor Green
		Write-Host
	}
	Catch {
		Write-Error "Failed to set ESXi Shell policy"
		Write-Error $_.Exception
		Exit -1
	}

	# Stop ESXi Shell Service
	Write-Host "Stopping ESXi Shell service"
	Try {
		Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Stop-VMHostService -Confirm:$false | Out-Null
		Write-Host "...ESXi shell service stopped!" -ForegroundColor Green
		Write-Host
	}
	Catch {
		Write-Error "Failed to stop ESXi Shell service"
		Write-Error $_.Exception
		Exit -1
	}

	# Generate new vmk0
	Write-Host "Updating vmk0"
	Try {
		if($rollvmk0){
			# Get the current info for restoring later
			$currSettings = Get-VMHostNetworkAdapter -VMHost $vmhost -name vmk0
		
			# Add a temporary vmkernel adapter to the "VM Network" portgroup
			$vsw0 = Get-VirtualSwitch -VMHost $vmhost -Name "vSwitch0"
			New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vsw0 -PortGroup "VM Network" -IP $rollvmk0 -SubnetMask $currSettings.SubnetMask -ManagementTrafficEnabled $true | Out-Null
			Disconnect-VIServer -Server $hostname -Confirm:$false | Out-Null

			# Delete the original vmk0
			Connect-VIServer $rollvmk0 -Credential $esxicred -Protocol https -ErrorAction Stop | Out-Null
			$vmk0host = Get-VMHost -Name $rollvmk0
			$vmk0 = Get-VMHostNetworkAdapter -VMHost $vmk0host -Name "vmk0"
			Remove-VMHostNetworkAdapter $vmk0 -Confirm:$false | Out-Null

			# Create a new vmk0
			$vsw1 = Get-VirtualSwitch -VMHost $vmk0host -Name "vSwitch0"
			New-VMHostNetworkAdapter -VMHost $vmk0host -VirtualSwitch $vsw1 -PortGroup "Management Network" -IP $currSettings.IP -SubnetMask $currSettings.SubnetMask -ManagementTrafficEnabled $true | Out-Null
			Disconnect-VIServer -Server $rollvmk0 -Confirm:$false | Out-Null

			# Delete the temporary vmkernel adapter
			Connect-VIServer $hostname -Credential $esxicred -Protocol https -ErrorAction Stop | Out-Null
			$vmhost = Get-VMHost -Name $hostname
			$vmk1 = Get-VMHostNetworkAdapter -VMHost $vmhost -Name "vmk1"
			Remove-VMHostNetworkAdapter $vmk1 -Confirm:$false | Out-Null
			
			Write-Host "...vmk0 updated!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...vmk0 untouched!" -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to roll vmk0"
		Write-Error $_.Exception
		Exit -1
	}

	# Patch host from repo 
	Write-Host "Updating host version"
	Try {
		if($updateHost.Count -gt 0){
			if($updateHost.Count -eq 2){
				$hostEsxCli = Get-VMHost -Name $hostname | Get-EsxCli -V2
				$updateArgs = $hostEsxCli.software.profile.install.CreateArgs()
				$updateArgs.profile = $updateHost[0]
				$updateArgs.depot = $updateHost[1]
				$updateArgs.nohardwarewarning = $true
				$updateArgs.oktoremove = $true
				$hostEsxCli.software.profile.install.Invoke($updateArgs)
				Write-Host "...ESXi host update applied!" -ForegroundColor Green
				Write-Host
			}
			else{
				Write-Host "...Incorrect number of values given!" -ForegroundColor Yellow
				Write-Host "...Correct usage: -updateHost `"<profile name>`",`"<repo url>`"" -ForegroundColor Yellow
				Write-Host "...Example: -updateHost `"ESXi-7.0U1d-17551050-standard`",`"https://172.16.33.120/update-repos/esxi/VMware-ESXi-7.0U1d-17551050-depot/index.xml`"" -ForegroundColor Yellow
				Write-Host
			}
		}
		else{
			Write-Host "...Leaving host version alone." -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to update host"
		Write-Error $_.Exception
		Exit -1
	}

	if($rollCerts -or $restartServices -or $restartHost){
		# Connect via SSHCommand
		Write-Host "Connecting to $hostname via SSH"
		Try {
			$esxihostssh = New-SSHSession -ComputerName $hostname -Credential $esxicred -Force -KeepAliveInterval 5
		}
		Catch {
			Write-Error "Failed to connect to $hostname via SSH"
			Write-Error $_.Exception
			Exit -1
		}
		Write-Host "...Connected to $hostname via SSH" -ForegroundColor Green
		Write-Host
	}

	# Roll Certs
	Write-Host "Checking cert preference"
	Try {
		if($rollCerts){
			Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command '/sbin/generate-certificates' -TimeOut 30 | Out-Null
			Write-Host "...Certificates rolled!" -ForegroundColor Green
			Write-Host
		}
		else {
			Write-Host "...Leaving certificates alone" -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to roll certificates"
		Write-Error $_.Exception
		Exit -1
	}

	# Restarting Services
	Write-Host "Checking service preference"
	Try {
		if($restartServices){
			Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command 'services.sh restart' -TimeOut 60 | Out-Null
			Write-Host "...Services restarted!" -ForegroundColor Green
			Write-Host
		}
		else {
			Write-Host "...Leaving services alone" -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to restart services"
		Write-Error $_.Exception
		Exit -1
	}

	# Restart Host
	Write-Host "Checking if host should be restarted"
	Try {
		if($restartHost){
			Restart-VMHost -VMHost $vmhost -Force -Confirm:$false
			Write-Host "...Host restarted!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...Leaving host power state alone." -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "Failed to restart host"
		Write-Error $_.Exception
		Exit -1
	}
	
	if($esxihostssh){
		# Disconnect from the host
		Write-Host "Disconnecting SSH from the ESXi host $hostname"o
		Try {
			# Close SSH connection to the ESXi host
			$sshdc = Remove-SSHSession -SessionId $esxihostssh.SessionId
		}
		Catch {
			Write-Error "Failed to disconnect from $hostname"
			Write-Error $_.Exception
			Exit -1
		}
		Write-Host "...Disconnected SSH from $hostname" -ForegroundColor Green
		Write-Host
	}

	# Disconnect from the host
	Write-Host "Disconnecting HTTPS from the ESXi host $hostname"
	Try {
		# Close PowerCLI connection to the ESXi host
		Disconnect-VIServer $hostname -Confirm:$false
	}
	Catch {
		Write-Error "Failed to disconnect from $hostname"
		Write-Error $_.Exception
		Exit -1
	}
	Write-Host "...Disconnected HTTPS from $hostname" -ForegroundColor Green
	Write-Host
}