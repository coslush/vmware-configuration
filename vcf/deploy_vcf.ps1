[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,ParameterSetName="cloudbuilderSpec_File")]
    [string]$cloudbuilderSpec_File
)

Write-Host "Ingesting the Cloud Builder deployment specification" -ForegroundColor Green
$cloudbuilderSpec = Get-Content -Raw -Path $cloudbuilderSpec_File | ConvertFrom-Json

Write-Host "Connecting to the Cloud Builder vCenter" -ForegroundColor Green
Connect-VIServer $cloudbuilderSpec.vCenterFQDN

Write-Host "Building the Cloud Builder OVF configuration" -ForegroundColor Green
$cloudbuilder_ovfconfig = Get-OvfConfiguration $cloudbuilderSpec.OVALocation
$cloudbuilder_ovfconfig.Common.guestinfo.ADMIN_USERNAME.Value = "admin"
$cloudbuilder_ovfconfig.Common.guestinfo.ADMIN_PASSWORD.Value = $cloudbuilderSpec.adminPassword
$cloudbuilder_ovfconfig.Common.guestinfo.ROOT_PASSWORD.Value = $cloudbuilderSpec.rootPassword
$cloudbuilder_ovfconfig.Common.guestinfo.hostname.Value = $cloudbuilderSpec.hostname
$cloudbuilder_ovfconfig.Common.guestinfo.ip0.Value = $cloudbuilderSpec.ipAddress
$cloudbuilder_ovfconfig.Common.guestinfo.netmask0.Value = $cloudbuilderSpec.netmask
$cloudbuilder_ovfconfig.Common.guestinfo.gateway.Value = $cloudbuilderSpec.gateway
$cloudbuilder_ovfconfig.Common.guestinfo.DNS.Value = $cloudbuilderSpec.dnsList
$cloudbuilder_ovfconfig.Common.guestinfo.ntp.Value = $cloudbuilderSpec.ntpList
$cloudbuilder_ovfconfig.NetworkMapping.Network_1.Value = $cloudbuilderSpec.portgroupName
$cloudbuilder_host = $cloudbuilderSpec.deploymentHost
$cloudbuilder_rp = $cloudbuilderSpec.deploymentResourcePool
$cloudbuilder_folder = $cloudbuilderSpec.deploymentFolder
$cloudbuilder_ds = $cloudbuilderSpec.datastore
$cloudbuilder_vmname = $cloudbuilderSpec.hostname

Write-Host "Deploying the Cloud Builder appliance" -ForegroundColor Green
$cloudbuilder_vm = Import-VApp -Source $cloudbuilderSpec.OVALocation -OvfConfiguration $cloudbuilder_ovfconfig -Name $cloudbuilder_vmname -VMHost $cloudbuilder_host -Location $cloudbuilder_rp -InventoryLocation $cloudbuilder_folder -Datastore $cloudbuilder_ds -Confirm:$false

Write-Host "Starting the Cloud Builder appliance" -ForegroundColor Green
Start-VM $cloudbuilder_vm

Write-Host "Disconnecting from the Cloud Builder vCenter" -ForegroundColor Green
Disconnect-VIServer $cloudbuilderSpec.vCenterFQDN -Confirm:$false

