# Configure VMs to be placed on specific Hosts based on tags

# Cluster
$clusterName = "GP-Cluster-01"

# VM Group
$vmGroupName = "TaggedPlacement-VMGroup_Horizon"
$vmGroupCategory = "TaggedPlacement"
$vmGroupTag = "Horizon"

# Host Group
$hostGroupName = "TaggedPlacement-HostGroup_Horizon"
$hostGroupCategory = "TaggedPlacement"
$hostGroupTag = "Horizon"

# VM-Host Rule Name
$vmHostRuleName = "TaggedPlacement-VMHostRule_Horizon"

# VM-Host Rule Policy
$vmHostRulePolicy = "ShouldRunOn"

Try{
	$hostCluster = Get-Cluster -Name $clusterName
	$vmTags = Get-Tag -Name $vmGroupTag -Category $vmGroupCategory
	$hostTags = Get-Tag -Name $hostGroupTag -Category $hostGroupCategory
	$vmsToPlace = Get-VM -Tag $vmTags -Location $hostCluster
	$hostsToPlace = Get-VMHost -Tag $hostTags -Location $hostCluster
}
Catch{
	Write-Error "Missing required information. Exiting."
    Write-Error $_.Exception
    Exit
}
Write-Host
Write-Host "Cluster: " -ForegroundColor Blue
Write-Host "  $clusterName" -ForegroundColor Green
Write-Host
Write-Host "Host Tag/Category: " -ForegroundColor Blue
Write-Host "  $hostGroupTag/$hostGroupCategory" -ForegroundColor Green
Write-Host "Host Group Name: " -ForegroundColor Blue
Write-Host "  $hostGroupName" -ForegroundColor Green
Write-Host "Host List: " -ForegroundColor Blue
Write-Host "  $hostsToPlace" -ForegroundColor Green
Write-Host
Write-Host "VM Tag/Category: " -ForegroundColor Blue
Write-Host "  $vmGroupTag/$vmGroupCategory" -ForegroundColor Green
Write-Host "VM Group Name: " -ForegroundColor Blue
Write-Host "  $vmGroupName" -ForegroundColor Green
Write-Host "VM List: " -ForegroundColor Blue
Write-Host "  $vmsToPlace" -ForegroundColor Green
Write-Host
Write-Host "VM-Host Affinity Rule: " -ForegroundColor Blue
Write-Host "  $vmHostRuleName" -ForegroundColor Green
Write-Host "VM-Host Affinity Policy: " -ForegroundColor Blue
Write-Host "  $vmHostRulePolicy" -ForegroundColor Green
Write-Host

$vmGroupRule = Get-DrsClusterGroup -Name $vmGroupName -Type VMGroup -Cluster $hostCluster -erroraction 'silentlycontinue'
if($vmGroupRule -eq $null){
	$vmGroupRule = New-DrsClusterGroup -Name $vmGroupName -VM $vmsToPlace -Cluster $hostCluster
}else{
	$vmGroupRule = Set-DrsClusterGroup -DrsClusterGroup $vmGroupName -VM $vmsToPlace -Add
}

$hostGroupRule = Get-DrsClusterGroup -Type VMHostGroup -Name $hostGroupName -erroraction 'silentlycontinue'
if($hostGroupRule -eq $null){
	$hostGroupRule = New-DrsClusterGroup -Name $hostGroupName -VMHost $hostsToPlace -Cluster $hostCluster
}else{
	$hostGroupRule = Set-DrsClusterGroup -DrsClusterGroup $hostGroupName -VMHost $hostsToPlace -Add
}

$vmHostRule = Get-DrsVMHostRule -Name $vmHostRuleName -erroraction 'silentlycontinue'
if($vmHostRule -eq $null){
	$vmHostRule = New-DrsVMHostRule -Name $vmHostRuleName -Cluster $hostCluster -VMGroup $vmGroupRule -VMHostGroup $hostGroupRule -Type $vmHostRulePolicy
}else{
	$vmHostRule = Set-DrsVMHostRule -Rule $vmHostRuleName -VMGroup $vmGroupRule -VMHostGroup $hostGroupRule -Type $vmHostRulePolicy
}
