Param(
[string]$omsWorkspaceId,
[string]$omsSharedKey,
[string[]]$locations
)

# Requires Az.Compute and Az.Storage modules

# To test outside of Azure Automation, replace this block with Login-AzAccount
$connectionName = "AzureRunAsConnection"
try
{
# Get the connection "AzureRunAsConnection "
$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName

"Logging in to Azure..."
Add-AzAccount `
-ServicePrincipal `
-TenantId $servicePrincipalConnection.TenantId `
-ApplicationId $servicePrincipalConnection.ApplicationId `
-CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
}
catch {
if (!$servicePrincipalConnection)
{
$ErrorMessage = "Connection $connectionName not found."
throw $ErrorMessage
} else{
Write-Error -Message $_.Exception
throw $_.Exception
}
}

$LogType = "AzureQuota"

$subs = Get-AzSubscription

foreach ($sub in $subs) {

  Write-Output "Processing subscription $($sub.Name)"
  Select-AzSubscription -SubscriptionName $sub.Name

  
$json = ''

# Credit: s_lapointe https://gallery.technet.microsoft.com/scriptcenter/Easily-obtain-AccessToken-3ba6e593
function Get-AzCachedAccessToken {
    <#
    .SYNOPSIS
    Retrieve the cached Azure AccessToken (Bearer) from the current Powershell session and its current Azure Context
  
    .NOTES
    Thanks to Stephane Lapointe (https://www.linkedin.com/in/stephanelapointe/) for this script to get the Bearer Token from an existing Powershell session (https://gallery.technet.microsoft.com/scriptcenter/Easily-obtain-AccessToken-3ba6e593/view/Reviews)
    #>
  
    [CmdletBinding()]
    param ()
  
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    if (-not $azProfile.Accounts.Count) {
        Write-Error 'Could not find a valid AzProfile, please run Connect-AzAccount'
        return
    }
  
    $currentAzureContext = Get-AzContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Tenant.TenantId)
    $token.AccessToken
  }
  

# Network Usage not currently exposed through PowerShell, so need to call REST API
function Get-AzNetworkUsage($location)
{
$token = Get-AzCachedAccessToken
$authHeader = @{
'Content-Type'='application\json'
'Authorization'="Bearer $token"
}
$azureContext = Get-AzContext
$subscriptionId = $azureContext.Subscription.SubscriptionId

$result = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Network/locations/$location/usages?api-version=2017-03-01" -Method Get -Headers $authHeader
return $result.value
}

# Get VM quotas
foreach ($location in $locations)
{
$vmQuotas = Get-AzVMUsage -Location $location
foreach($vmQuota in $vmQuotas)
{
$usage = 0
if ($vmQuota.Limit -gt 0) { $usage = $vmQuota.CurrentValue / $vmQuota.Limit }
$json += @"
{ "Subscription":"$($sub.Name)","Name":"$($vmQuota.Name.LocalizedValue)", "Category":"Compute", "Location":"$location", "CurrentValue":$($vmQuota.CurrentValue), "Limit":$($vmQuota.Limit),"Usage":$usage },
"@
}
}

# Get Network Quota
foreach ($location in $locations)
{
$networkQuotas = Get-AzNetworkUsage -location $location
foreach ($networkQuota in $networkQuotas)
{
$usage = 0
if ($networkQuota.limit -gt 0) { $usage = $networkQuota.currentValue / $networkQuota.limit }
$json += @"
{ "Subscription":"$($sub.Name)","Name":"$($networkQuota.name.localizedValue)", "Category":"Network", "Location":"$location", "CurrentValue":$($networkQuota.currentValue), "Limit":$($networkQuota.limit),"Usage":$usage },
"@
}

}

# Get Storage Quota
$storageQuota = Get-AzStorageUsage -Location $location
$usage = 0
if ($storageQuota.Limit -gt 0) { $usage = $storageQuota.CurrentValue / $storageQuota.Limit }
$json += @"
{ "Subscription":"$($sub.Name)","Name":"$($storageQuota.LocalizedName)", "Location":"", "Category":"Storage", "CurrentValue":$($storageQuota.CurrentValue), "Limit":$($storageQuota.Limit),"Usage":$usage }
"@

# Wrap in an array
$json = "[$json]"

# Create the function to create the authorization signature
Function Build-Signature ($omsWorkspaceId, $omsSharedKey, $date, $contentLength, $method, $contentType, $resource)
{
$xHeaders = "x-ms-date:" + $date
$stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
$keyBytes = [Convert]::FromBase64String($omsSharedKey)

$sha256 = New-Object System.Security.Cryptography.HMACSHA256
$sha256.Key = $keyBytes
$calculatedHash = $sha256.ComputeHash($bytesToHash)
$encodedHash = [Convert]::ToBase64String($calculatedHash)
$authorization = 'SharedKey {0}:{1}' -f $omsWorkspaceId,$encodedHash
return $authorization
}

# Create the function to create and post the request
Function Post-OMSData($omsWorkspaceId, $omsSharedKey, $body, $logType)
{
$method = "POST"
$contentType = "application/json"
$resource = "/api/logs"
$rfc1123date = [DateTime]::UtcNow.ToString("r")
$contentLength = $body.Length
$signature = Build-Signature `
-omsWorkspaceId $omsWorkspaceId `
-omsSharedKey $omsSharedKey `
-date $rfc1123date `
-contentLength $contentLength `
-fileName $fileName `
-method $method `
-contentType $contentType `
-resource $resource
$uri = "https://" + $omsWorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

$headers = @{
"Authorization" = $signature;
"Log-Type" = $logType;
"x-ms-date" = $rfc1123date;
}

$response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
return $response.StatusCode

}   

# Submit the data to the API endpoint
Post-OMSData -omsWorkspaceId $omsWorkspaceId -omsSharedKey $omsSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType










}


