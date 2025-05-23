function DisableCEIP {
    param (
        $VMHostname
    )
	
	Write-Host "Adjusting CEIP configuration"
	Get-VMHost -Name $VMHostname | Get-AdvancedSetting -Name UserVars.HostClientCEIPOptIn | Set-AdvancedSetting -Value 2 -Confirm:$false | Out-Null
	Write-Host "...CEIP Disabled!" -ForegroundColor Green
	Write-Host
}

function MatchVMNetwork {
	param (
		$VMHost
	)
	
	Write-Host "Adjusting 'VM Network' portgroup configuration"
	$mgmtPG = Get-VirtualPortGroup -VMHost $VMHost -Name "Management Network"
	Get-VirtualPortGroup -VMHost $VMHost -Name "VM Network" | Set-VirtualPortGroup -VLanId $mgmtPG.VLanId | Out-Null
	Write-Host "...'VM Network' VLAN set!" -ForegroundColor Green
	Write-Host
}

function StartSSHService {
	param (
		$VMHostname,
		$ServiceAction
	)
	
	Write-Host "Starting SSH Service $ServiceAction"
	Get-VMHost -Name $VMHostname | Get-VMHostService | Where {$_.Label -eq "SSH"} | Start-VMHostService -Confirm:$false | Out-Null
	Write-Host "...SSH service started!" -ForegroundColor Green
	Write-Host
}

function DisableIPv6Support {
	param (
		$VMHostname
	)
	
	Write-Host "Setting IPv6 support"
	$VMHost = Get-VMHost -Name $VMHostname
	$hostcli = Get-EsxCli -VMHost $VMHost -V2
	$argument = $hostcli.system.module.parameters.set.CreateArgs()
	$argument.module = "tcpip4"
	$argument.parameterstring = "ipv6=0"
	$hostcli.system.module.parameters.set.Invoke($argument) | Out-Null
	Write-Host "...IPv6 support disabled!" -ForegroundColor Green
	Write-Host
}

function CreateAdminAccount {
	param (
		$Username,
		$Password
	)
	
	Write-Host "Creating Admin account"
	New-VMHostAccount -Id $Username -Password $Password -Confirm:$false | Out-Null
	New-VIPermission -Entity (Get-Folder root) -Principal $Username -Role Admin -Confirm:$false | Out-Null
	Write-Host "...Additional administrator account created!" -ForegroundColor Green
	Write-Host
}

function UpdateVMHost {
	param (
		$UpdateInfo
	)
	
	Write-Host "Updating host version"
	if($UpdateInfo.Count -eq 2){
		$updateProfile = $UpdateInfo[0]
		$updateURL = $UpdateInfo[1]
		#Invoke-SSHCommand -SessionId $esxihostssh.SessionId -Command "esxcli software profile update -p $updateProfile -d $updateURL" -TimeOut 120 | Out-Null
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