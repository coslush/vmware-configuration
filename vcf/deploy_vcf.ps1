[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$cloudbuilderSpec_File,
    [Parameter(Mandatory=$true)]
    [string]$vcfSpec_File
)

Write-Host "Ingest the Cloud Builder deployment specification" -ForegroundColor Green
$cloudbuilderSpec = Get-Content -Raw -Path $cloudbuilderSpec_File | ConvertFrom-Json

Write-Host "Connect to the Cloud Builder vCenter" -ForegroundColor Green
Connect-VIServer $cloudbuilderSpec.vCenterFQDN

Write-Host "Build the Cloud Builder OVF configuration" -ForegroundColor Green
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

Write-Host "Deploy the Cloud Builder appliance" -ForegroundColor Green
$cloudbuilder_vm = Import-VApp -Source $cloudbuilderSpec.OVALocation -OvfConfiguration $cloudbuilder_ovfconfig -Name $cloudbuilderSpec.vmName -VMHost $cloudbuilder_host -Location $cloudbuilder_rp -InventoryLocation $cloudbuilder_folder -Datastore $cloudbuilder_ds -Confirm:$false

Write-Host "Start the Cloud Builder appliance" -ForegroundColor Green
Start-VM $cloudbuilder_vm

Write-Host "Disconnect from the Cloud Builder vCenter" -ForegroundColor Green
Disconnect-VIServer $cloudbuilderSpec.vCenterFQDN -Confirm:$false

Write-Host "Wait for Cloud Builder to come up" -ForegroundColor Green
do { 
    Start-Sleep -Seconds 5 
} until (Test-Connection $cloudbuilderSpec.ipAddress -Quiet -Count 1)

Write-Host "Ingest the VCF deployment specification" -ForegroundColor Green
$vcfSpec = Get-Content -Raw -Path $vcfSpec_File | ConvertFrom-Json
$vcfSpec_Compressed = $vcfSpec | ConvertTo-Json -Compress -Depth 6

Write-Host "Validate the VCF deployment specification" -ForegroundColor Green
$validationURL = "https://$($cloudbuilderSpec.ipAddress)/v1/sddcs/validations"
Write-Host $validationURL
$validationCreds = "admin:$($cloudbuilderSpec.adminPassword)"
Write-Host $validationCreds
curl -k $validationURL -i -u $validationCreds -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d $vcfSpec_Compressed

Write-Host "Wait for the VCF deployment specification validation result" -ForegroundColor Green
do { 
    Start-Sleep -Seconds 30
} until (curl -k $validationURL -i -u $validationCreds -X GET -H 'Content-Type: application/json' -H 'Accept: application/json')