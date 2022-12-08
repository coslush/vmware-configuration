<# 
.NOTES 
File Name  : esxi-host-prep.ps1 
Author     : coslush
Version    : 1.0
License    : Apache-2.0
    
.PARAMETER disableCEIP
Disables CEIP
.PARAMETER esxicred
    Enter the pscredential variable name to use for authentication to the ESXi host. This can be run before the script for example: $cred = get-pscredential 
.PARAMETER hostnames
    Enter the FQDN/IP or list of FQDN/IPs of the ESXi Server(s) to prep for VCF
.PARAMETER matchVMNetwork
Matches the vlan set on the VM Network portgroup to the vlan defined on the Management Network portgroup
.PARAMETER startSSH
Starts the SSH service
.PARAMETER disableESXCLI
Disables the ESXCLI service
.PARAMETER rollCerts
Rolls the default certificates to match the current FQDN (Requires reboot or services restart to take effect)
.PARAMETER rollvmk0
Changes the vmk0 MAC address to a dynamic one
.PARAMETER disableIPv6
Disables IPv6 (Requires reboot to take effect)
.PARAMETER restartServices
Restarts all the services
.PARAMETER restartHost
Restarts the host
.PARAMETER createAdmin
Creates an admin user with the given username and password
.PARAMETER updateHost
Updates the host software profile to the given profile name at the specified URL
.PARAMETER stigFile
Applies the enabled STIGs in the specified file

.EXAMPLE
.\esxi-host-prep.ps1

.EXAMPLE
$esxicreds = Get-Credential
.\esxi-host-prep.ps1 -hostnames "172.16.98.31","esxi32.mydomain.local" -esxicred $esxicreds -startSSH

.EXAMPLE
$esxicreds = Get-Credential
.\esxi-host-prep.ps1 -hostnames "172.16.98.31" -esxicred $esxicreds -disableCEIP -matchVMNetwork -disableIPv6 -rollCerts -rollvmk0 -stigFile preDeploy-stig-controls.json -restartHost -createAdmin "ladmin","12qwaszx!@QWASZX"

.EXAMPLE
$esxicreds = Get-Credential
.\esxi-host-prep.ps1 -hostnames "esxi01.mydomain.local" -esxicred $esxicreds -restartHost -updateHost "ESXi-7.0U3g-20328353-standard","https://updaterepo/VMware-ESXi-7.0U3g-20328353-depot/index.xml"

.SYNOPSIS 
    Configures the required settings on an ESXi host for a VCF deployment
	
.DESCRIPTION
    Configures a number of settings on an ESXi host for a VCF deployment. 
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
    HelpMessage="Enable this option if you want to start SSH on the host.")]
    [switch]$startSSH,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to enable esxcli on host startup.")]
    [switch]$disableESXCLI,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to roll the host certificates.")]
    [switch]$rollCerts,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to roll the MAC on vmk0.")]
    [switch]$rollvmk0,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to disable IPv6.")]
    [switch]$disableIPv6,

    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to restart host services.")]
    [switch]$restartServices,

	[Parameter(Mandatory=$false,
    HelpMessage="Enter a comma-separated list for the profile and update depot URL. Ex: `"ESXi-7.0U1d-17551050-standard`",`"https://webserver/VMware-ESXi-7.0U1d-17551050-depot/index.xml`"")]
    [string[]]$updateHost,
	
    [Parameter(Mandatory=$false,
    HelpMessage="Enable this option if you want to restart the host after all other configuration changes have been made.")]
    [switch]$restartHost,

	[Parameter(Mandatory=$false,
    HelpMessage="Enter the filename used for addressing STIGs")]
    [string]$stigFile,

	[Parameter(Mandatory=$false,
    HelpMessage="Enter the username and password to add as an administrator. Ex: ""ladmin"",""12qwaszx!@QWASZX""")]
    [string[]]$createAdmin
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
        Import-Module $m
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
    Write-Error "...Failed to load modules"
    Write-Error $_.Exception
    Exit
}

# Iterate through all the specified hosts
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
		Write-Error "...Failed to connect to $hostname via HTTPS"
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
		Write-Error "...Failed to disable CEIP"
		Write-Error $_.Exception
		#Exit -1
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
		Write-Error "...Failed to adjust 'VM Network' settings"
		Write-Error $_.Exception
		#Exit -1
	}

	# Set SSH Service status
	Write-Host "Setting SSH Service status"
	Try {
		if($startSSH){
			Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Start-VMHostService | Out-Null
			Write-Host "...SSH service started!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...Leaving SSH service status alone." -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "...Failed to start SSH service"
		Write-Error $_.Exception
		#Exit -1
	}

	# Set IPv6 support
	Write-Host "Setting IPv6 support"
	Try {
		if($disableIPv6){
			$theVMHost = Get-VMHost -Name $hostname
			$hostcli = Get-EsxCli -VMHost $theVMHost -V2
			$argument = $hostcli.system.module.parameters.set.CreateArgs()
			$argument.module = "tcpip4"
			$argument.parameterstring = "ipv6=0"
			$hostcli.system.module.parameters.set.Invoke($argument) | Out-Null
			Write-Host "...IPv6 support disabled!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...Leaving IPv6 support alone." -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "...Failed to disable IPv6 support"
		Write-Error $_.Exception
		#Exit -1
	}
	
	# Create administrator account
	Write-Host "Setting Admin account"
	Try {
		if($createAdmin){
			New-VMHostAccount -Id $createAdmin[0] -Password $createAdmin[1] -Confirm:$false | Out-Null
			New-VIPermission -Entity (Get-Folder root) -Principal ladmin -Role Admin -Confirm:$false | Out-Null
			Write-Host "...Additional administrator account created!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...Leaving administrator accounts alone." -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "...Failed to create administrator account."
		Write-Error $_.Exception
		#Exit -1
	}

	if($rollCerts -or $restartServices -or $rollvmk0 -or $stigFile -or $updateHost){
		# Connect via SSHCommand
		Write-Host "Connecting to $hostname via SSH"
		Try {
			$sshStatus = (Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"}).Running
			if(!$sshStatus){
				Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Start-VMHostService -Confirm:$false | Out-Null
			}
			$esxihostssh = New-SSHSession -ComputerName $hostname -Credential $esxicred -Force -KeepAliveInterval 5
		}
		Catch {
			Write-Error "...Failed to connect to $hostname via SSH"
			Write-Error $_.Exception
			Exit -1
		}
		Write-Host "...Connected to $hostname via SSH" -ForegroundColor Green
		Write-Host
	}
	
	# Update host from repo 
	Write-Host "Updating host version"
	Try {
		if($updateHost.Count -gt 0){
			if($updateHost.Count -eq 2){
				Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command 'esxcli software profile update -p $updateHost[0] -d $updateHost[1]' -TimeOut 120 #| Out-Null
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
		Write-Error "...Failed to update host"
		Write-Error $_.Exception
		#Exit -1
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
		Write-Error "...Failed to roll certificates"
		Write-Error $_.Exception
		Exit -1
	}

	# Generate new vmk0 MAC
	Write-Host "Checking vmk0 option"
	Try {
		if($rollvmk0){
			$hostVnicSpec = (Get-VMHost -Name $hostname | Get-View).Config.Network.Vnic[0].Spec
			$hostIP = $hostVnicSpec.Ip.IpAddress
			$hostnetmask = $hostVnicSpec.Ip.SubnetMask
			$hostGW = $hostVnicSpec.IPRouteSpec.IPRouteConfig.DefaultGateway
			if(!$hostGW){
				$hostGW = (Get-VMHost -Name $hostname | Get-View).Config.Network.IpRouteConfig.DefaultGateway
			}
			$vmk0ResetScript = "echo ""esxcli network ip interface remove --interface-name vmk0"" > /tmp/vmk0Reset.sh; echo ""esxcli network ip interface add --interface-name vmk0 --portgroup-name 'Management Network'"" >> /tmp/vmk0Reset.sh; echo ""esxcli network ip interface ipv4 set -i vmk0 -I $hostIP -N $hostnetmask -g $hostGW -t static"" >> /tmp/vmk0Reset.sh; echo ""esxcli network ip route ipv4 add -n default -g $hostGW"" >> /tmp/vmk0Reset.sh"
			Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "$vmk0ResetScript" -TimeOut 60 | Out-Null
			Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "/bin/sh /tmp/vmk0Reset.sh" -TimeOut 60 | Out-Null
			Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "rm -rf /tmp/vmk0Reset.sh" -TimeOut 60 | Out-Null

			Write-Host "...vmk0 updated!" -ForegroundColor Green
			Write-Host
		}
		else{
			Write-Host "...vmk0 untouched!" -ForegroundColor Green
			Write-Host
		}
	}
	Catch {
		Write-Error "...Failed to roll vmk0"
		Write-Error $_.Exception
		#Exit -1
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
		Write-Error "...Failed to restart services"
		Write-Error $_.Exception
		#Exit -1
	}
	
	if($stigFile){
		Write-Host "Addressing STIGs in the file provided."
		Try{
			$stigList = Get-Content -Raw -Path $stigfile | ConvertFrom-Json
			foreach($stigItem in $stigList.STIG_Items){
				if($stigItem.Enabled){
					switch($stigItem.Control_ID)
					{
						"ESXI-70-000001" { 
							Write-Host "   ESXI-70-000001" -NoNewLine
							$vmhost = Get-VMHost -Name $hostname | Get-View
							$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
							$lockdown.ChangeLockdownMode($stigItem.Control_Input)
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000002" { 
							Write-Host "   ESXI-70-000002" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break
						}
						"ESXI-70-000003" { 
							Write-Host "   ESXI-70-000003" -NoNewLine
							$vmhost = Get-VMHost -Name $hostname | Get-View
							$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
							$lockdown.UpdateLockdownExceptions($stigItem.Control_Input)
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000004" { 
							Write-Host "   ESXI-70-000004" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000005" { 
							Write-Host "   ESXI-70-000005" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000006" { 
							Write-Host "   ESXI-70-000006" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000007" { 
							Write-Host "   ESXI-70-000007" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000008" { 
							Write-Host "   ESXI-70-000008" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.Etc.issue | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000009" { 
							Write-Host "   ESXI-70-000009" -NoNewLine
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#Banner/d' /etc/ssh/sshd_config" -TimeOut 60 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^Banner/#Banner/' /etc/ssh/sshd_config" -TimeOut 60 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'Banner /etc/issue' >> /etc/ssh/sshd_config" -TimeOut 60 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000010" { 
							Write-Host "   ESXI-70-000010" -NoNewLine
							$esxiHost = Get-VMHost -Name $hostname
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
							$arguments.enable = $true
							$esxcli.system.security.fips140.ssh.set.Invoke($arguments) | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000012" { 
							Write-Host "   ESXI-70-000012" -NoNewLine
							# make sure /etc/ssh/sshd_config has "IgnoreRhosts" set to "yes"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#IgnoreRhosts/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^IgnoreRhosts/#IgnoreRhosts/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000013" { 
							Write-Host "   ESXI-70-000013" -NoNewLine
							# make sure /etc/ssh/sshd_config has "HostbasedAuthentication" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#HostbasedAuthentication/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^HostbasedAuthentication/#HostbasedAuthentication/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'HostbasedAuthentication no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000014" { 
							Write-Host "   ESXI-70-000014" -NoNewLine
							# make sure /etc/ssh/sshd_config has "PermitRootLogin" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#PermitRootLogin/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^PermitRootLogin/#PermitRootLogin/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000015" { 
							Write-Host "   ESXI-70-000015" -NoNewLine
							# make sure /etc/ssh/sshd_config has "PermitEmptyPasswords" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#PermitEmptyPasswords/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^PermitEmptyPasswords/#PermitEmptyPasswords/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000016" { 
							Write-Host "   ESXI-70-000016" -NoNewLine
							# make sure /etc/ssh/sshd_config has "PermitUserEnvironment" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#PermitUserEnvironment/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^PermitUserEnvironment/#PermitUserEnvironment/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000020" { 
							Write-Host "   ESXI-70-000020" -NoNewLine
							# make sure /etc/ssh/sshd_config has "StrictModes" set to "yes"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#StrictModes/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^StrictModes/#StrictModes/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'StrictModes yes' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000021" { 
							Write-Host "   ESXI-70-000021" -NoNewLine
							# make sure /etc/ssh/sshd_config has "Compression" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#Compression/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^Compression/#Compression/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'Compression no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000022" { 
							Write-Host "   ESXI-70-000022" -NoNewLine
							# make sure /etc/ssh/sshd_config has "GatewayPorts" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#GatewayPorts/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^GatewayPorts/#GatewayPorts/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'GatewayPorts no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000023" { 
							Write-Host "   ESXI-70-000023" -NoNewLine
							# make sure /etc/ssh/sshd_config has "X11Forwarding" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#X11Forwarding/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^X11Forwarding/#X11Forwarding/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'X11Forwarding no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000025" { 
							Write-Host "   ESXI-70-000025" -NoNewLine
							# make sure /etc/ssh/sshd_config has "PermitTunnel" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#PermitTunnel/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^PermitTunnel/#PermitTunnel/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'PermitTunnel no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000026" { 
							Write-Host "   ESXI-70-000026" -NoNewLine
							# make sure /etc/ssh/sshd_config has "ClientAliveCountMax" set to "3"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#ClientAliveCountMax/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^ClientAliveCountMax/#ClientAliveCountMax/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'ClientAliveCountMax 3' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000027" { 
							Write-Host "   ESXI-70-000027" -NoNewLine
							# make sure /etc/ssh/sshd_config has "ClientAliveInterval" set to "200"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#ClientAliveInterval/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^ClientAliveInterval/#ClientAliveCountMax/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'ClientAliveInterval 200' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000030" { 
							Write-Host "   ESXI-70-000030" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000031" { 
							Write-Host "   ESXI-70-000031" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000032" { 
							Write-Host "   ESXI-70-000032" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000034" { 
							Write-Host "   ESXI-70-000034" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value $false -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000035" { 
							Write-Host "   ESXI-70-000035" -NoNewLine
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Stop-VMHostService -Confirm:$false | Out-Null
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Set-VMHostService -Policy Off | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000036" { 
							Write-Host "   ESXI-70-000036" -NoNewLine
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Stop-VMHostService -Confirm:$false | Out-Null
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Set-VMHostService -Policy Off | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000037" { 
							Write-Host "   ESXI-70-000037" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000038" { 
							Write-Host "   ESXI-70-000038" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000039" { 
							Write-Host "   ESXI-70-000039" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000041" { 
							Write-Host "   ESXI-70-000041" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000042" { 
							Write-Host "   ESXI-70-000042" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000043" { 
							Write-Host "   ESXI-70-000043" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000045" { 
							Write-Host "   ESXI-70-000045" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Syslog.global.logDirUnique | Set-AdvancedSetting -Value $true -Confirm:$false | Out-Null
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000046" { 
							Write-Host "   ESXI-70-000046" -NoNewLine
							
							# Set the NTP servers
							if($stigItem.Control_Input.Count -gt 0){
								$currNTP = Get-VMHostNtpServer -VMHost $vmhost 
								if ($currNTP -ne $null){
									Remove-VMHostNtpServer -VMHost $vmhost $currNTP -Confirm:$false | Out-Null
								}
								foreach($ntpServer in $stigItem.Control_Input){
									Get-VMHost -Name $hostname | Add-VMHostNtpServer $ntpServer | Out-Null
								}
							}
							
							# Set the NTP service policy to start on boot
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On | Out-Null
							
							# Start the NTP service
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000047" { 
							Write-Host "   ESXI-70-000047" -NoNewLine
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.software.acceptance.set.CreateArgs()
							$arguments.level = $stigItem.Control_Input
							$esxcli.software.acceptance.set.Invoke($arguments) | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000048" { 
							Write-Host "   ESXI-70-000048" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000049" { 
							Write-Host "   ESXI-70-000049" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000050" { 
							Write-Host "   ESXI-70-000050" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000053" { 
							Write-Host "   ESXI-70-000053" -NoNewLine
							Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000054" { 
							Write-Host "   ESXI-70-000054" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000055" { 
							Write-Host "   ESXI-70-000055" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2 -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000056" { 
							Write-Host "   ESXI-70-000056" -NoNewLine
							$esxiHost = Get-VMHost -Name $hostname
							$fwservices = Get-VMHostFirewallException -VMHost $esxiHost | Where-Object {($_.Enabled -eq $True) -and ($_.extensiondata.allowedhosts.allip -eq "enabled") -and ($_.Name -ne "vSphere Web Client") -and ($_.Name -ne "dellptagenttcp") -and ($_.Name -ne "dellsshServer") -and ($_.Name -ne "VMware vCenter Agent")}
							$esxcli = Get-EsxCli -VMHost $esxiHost -V2
							ForEach($fwservice in $fwservices){
								$fwsvcname = $fwservice.extensiondata.key
								## Disables All IPs allowed policy
								$fwargs = $esxcli.network.firewall.ruleset.set.CreateArgs()
								$fwargs.allowedall = $false
								$fwargs.rulesetid = $fwsvcname
								$esxcli.network.firewall.ruleset.set.Invoke($fwargs) | Out-Null
								#Add IP ranges to each service
								ForEach($allowedip in $stigItem.Control_Input){
									$fwallowedargs = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
									$fwallowedargs.ipaddress = $allowedip
									$fwallowedargs.rulesetid = $fwsvcname
									$esxcli.network.firewall.ruleset.allowedip.add.Invoke($fwallowedargs) | Out-Null
								}
								#Add 169.254.0.0/16 range to hyperbus service if NSX-T is in use for internal communication
								If($fwsvcname -eq "hyperbus"){
									$fwallowedargs = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
									$fwallowedargs.ipaddress = "169.254.0.0/16"
									$fwallowedargs.rulesetid = $fwsvcname
									$esxcli.network.firewall.ruleset.allowedip.add.Invoke($fwallowedargs) | Out-Null
								}
								#Add 255.255.255.255 to dhcp service 
								If($fwsvcname -eq "dhcp"){
									$fwallowedargs = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
									$fwallowedargs.ipaddress = "255.255.255.255"
									$fwallowedargs.rulesetid = $fwsvcname
									$esxcli.network.firewall.ruleset.allowedip.add.Invoke($fwallowedargs) | Out-Null
								}
							}
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000057" { 
							Write-Host "   ESXI-70-000057" -NoNewLine
							Get-VMHostFirewallDefaultPolicy -VMHost $esxiHost | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000058" { 
							Write-Host "   ESXI-70-000058" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000059" { 
							Write-Host "   ESXI-70-000059" -NoNewLine
							$esxiHost = Get-VMHost -Name $hostname
							Get-VirtualSwitch -VMHost $esxiHost | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits $false -Confirm:$false | Out-Null
							Get-VirtualPortGroup -VMHost $esxiHost | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmitsInherited $true -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000060" { 
							Write-Host "   ESXI-70-000060" -NoNewLine
							$esxiHost = Get-VMHost -Name $hostname
							Get-VirtualSwitch -VMHost $esxiHost | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false -Confirm:$false | Out-Null
							Get-VirtualPortGroup -VMHost $esxiHost | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000061" { 
							Write-Host "   ESXI-70-000061" -NoNewLine
							$esxiHost = Get-VMHost -Name $hostname
							Get-VirtualSwitch -VMHost $esxiHost | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false -Confirm:$false | Out-Null
							Get-VirtualPortGroup -VMHost $esxiHost | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000062" { 
							Write-Host "   ESXI-70-000062" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value "" -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000063" { 
							Write-Host "   ESXI-70-000063" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000064" { 
							Write-Host "   ESXI-70-000064" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000065" { 
							Write-Host "   ESXI-70-000065" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000070" { 
							Write-Host "   ESXI-70-000070" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000072" { 
							Write-Host "   ESXI-70-000072" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000074" { 
							Write-Host "   ESXI-70-000074" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000076" { 
							Write-Host "   ESXI-70-000076" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000078" { 
							Write-Host "   ESXI-70-000078" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000079" { 
							Write-Host "   ESXI-70-000079" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value "0" -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000081" { 
							Write-Host "   ESXI-70-000081" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Set-AdvancedSetting -Value "0" -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000082" { 
							Write-Host "   ESXI-70-000082" -NoNewLine
							# make sure /etc/ssh/sshd_config has "AllowTcpForwarding" set to "no"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#AllowTcpForwarding/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^AllowTcpForwarding/#AllowTcpForwarding/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000083" { 
							Write-Host "   ESXI-70-000083" -NoNewLine
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "slpd"} | Set-VMHostService -Policy Off | Out-Null
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "slpd"} | Stop-VMHostService -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000084" { 
							Write-Host "   ESXI-70-000084" -NoNewLine
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.system.auditrecords.local.set.CreateArgs()
							$arguments.size="100"
							$esxcli.system.auditrecords.local.set.Invoke($arguments) | Out-Null
							$esxcli.system.auditrecords.local.enable.Invoke() | Out-Null
							$esxcli.system.auditrecords.remote.enable.Invoke() | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000085" { 
							Write-Host "   ESXI-70-000085" -NoNewLine
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.system.syslog.config.set.CreateArgs()
							$arguments.x509strict = $true
							$esxcli.system.syslog.config.set.Invoke($arguments) | Out-Null
							$esxcli.system.syslog.reload.Invoke() | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000086" { 
							Write-Host "   ESXI-70-000086" -NoNewLine
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.system.security.certificatestore.add.CreateArgs()
							$arguments.filename = $stigItem.Control_Input
							$esxcli.system.security.certificatestore.add.Invoke($arguments) | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000087" { 
							Write-Host "   ESXI-70-000087" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Mem.MemEagerZero | Set-AdvancedSetting -Value "1" -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000088" { 
							Write-Host "   ESXI-70-000088" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000089" { 
							Write-Host "   ESXI-70-000089" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000090" { 
							Write-Host "   ESXI-70-000090" -NoNewLine
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.system.security.fips140.rhttpproxy.set.CreateArgs()
							$arguments.enable = $true
							$esxcli.system.security.fips140.rhttpproxy.set.Invoke($arguments) | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000091" { 
							Write-Host "   ESXI-70-000091" -NoNewLine
							Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value $stigItem.Control_Input -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000092" { 
							Write-Host "   ESXI-70-000092" -NoNewLine
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo -n >/etc/vmware/settings" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000093" { 
							Write-Host "   ESXI-70-000093" -NoNewLine
							Write-Host "...configuration skipped." -ForegroundColor Yellow
							Break 
						}
						"ESXI-70-000094" { 
							Write-Host "   ESXI-70-000094" -NoNewLine
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.system.settings.encryption.set.CreateArgs()
							$arguments.mode = "TPM"
							$esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000095" { 
							Write-Host "   ESXI-70-000095" -NoNewLine
							$esxcli = Get-EsxCli -v2 -VMHost $esxiHost
							$arguments = $esxcli.system.settings.encryption.set.CreateArgs()
							$arguments.requiresecureboot = $true
							$esxcli.system.settings.encryption.set.Invoke($arguments) | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000097" { 
							Write-Host "   ESXI-70-000097" -NoNewLine
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Set-VMHostService -Policy Off | Out-Null
							Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Stop-VMHostService -Confirm:$false | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						"ESXI-70-000274" { 
							Write-Host "   ESXI-70-000274" -NoNewLine
							# make sure /etc/ssh/sshd_config has "Ciphers" set to "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^#Ciphers/d' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "sed -i 's/^Ciphers/#Ciphers/' /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "echo 'Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config" -TimeOut 30 | Out-Null
							Write-Host "...configuration applied." -ForegroundColor Green
							Break 
						}
						Default {
							Write-Host "   Unrecognized option: " $stigItem.Control_ID -ForegroundColor Yellow
						}
					}
				}
			}
			Write-Host
		}
		Catch{
			Write-Error $_.Exception
		}
	}
	
	if($esxihostssh){
		# Disconnect from the host
		Write-Host "Disconnecting SSH from the ESXi host $hostname"
		Try {
			# Close SSH connection to the ESXi host
			$sshdc = Remove-SSHSession -SessionId $esxihostssh.SessionId
			if(!$sshStatus){
				Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Stop-VMHostService -Confirm:$false | Out-Null
			}
		}
		Catch {
			Write-Error "Failed to disconnect from $hostname"
			Write-Error $_.Exception
			Exit -1
		}
		Write-Host "...Disconnected SSH from $hostname" -ForegroundColor Green
		Write-Host
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
		Write-Error "...Failed to restart host"
		Write-Error $_.Exception
		#Exit -1
	}
	
	# Disconnect from the host
	Write-Host "Disconnecting HTTPS from the ESXi host $hostname"
	Try {
		# Close PowerCLI connection to the ESXi host
		Disconnect-VIServer $hostname -Confirm:$false
	}
	Catch {
		Write-Error "...Failed to disconnect from $hostname"
		Write-Error $_.Exception
		Exit -1
	}
	Write-Host "...Disconnected HTTPS from $hostname" -ForegroundColor Green
	Write-Host
}
