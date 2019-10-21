<#
Deployment Script using Anypoint Platform API
#>

Param(

    [String]$AnyPointUser=$AnyPointUser,

    [String]$AnyPointPwd=$AnyPointPwd,

    [String]$AnyPointOrgName=$AnyPointOrgName,

    [String]$AnyPointEnvName=$AnyPointEnvName,

    [String]$InputFile=$InputFile,

    [String]$Environment=$Environment,

    [String]$MuleVersion=$MuleVersion,

    [String]$Region=$Region,

    [String]$NumWorkers=$NumWorkers,

    [String]$WorkerType=$WorkerType,

    [String]$APIJarFileLocation=$APIJarFileLocation,

    [String]$PlatformClientID=$PlatformClientID,

    [String]$PlatformClientSecret=$PlatformClientSecret,

    [String]$MuleKey=$MuleKey,

    [String]$CompanyAbbreviation=$CompanyAbbreviation,

    [String]$AppDeploySuffix,

    [String]$SplunkURL=$SplunkURL,

    [String]$SplunkToken=$SplunkToken

)


Clear-Host
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#### Make the value "SilentlyContinue" to suppress Debug Logs in Production
$DebugPreference = "Continue"
# $DebugPreference = "SilentlyContinue"
write-host "This is anypointuser = $AnyPointUser and splunkURL = $SplunkURL this is pointorg $AnyPointOrgName***$AnyPointUser,$AnyPointPwd,$AnyPointOrgName,$AnyPointEnvName,$InputFile,$Environment,$MuleVersion,$Region$NumWorkers,$WorkerType,$APIJarFileLocation,$PlatformClientID,$PlatformClientSecret,$MuleKey,$CompanyAbbreviation,$AppDeploySuffix,$SplunkURL,$SplunkToken"
### Requests data is initialized from this template first then attributes that need to be overridden would be set
### then the resulting object is serialized to JSON and used as payload

$APIManagerRequestTemplate = @'
{
	"endpoint": {
		"deploymentType": null,
		"isCloudHub": null,
		"muleVersion4OrAbove": null,
		"proxyUri": null,
		"referencesUserDomain": null,
		"responseTimeout": null,
		"type": null,
		"uri": null
	},
	"instanceLabel": null,
	"spec": {
		"assetId": null,
		"groupId": null,
		"version": null
	}
}
'@

$CHApplicationTemplate = @'

    {
        "domain": null,
        "muleVersion": {
          "version": null
        },
        "properties": {
          "key": "value"
        },
        "region": null,
        "workers": {
          "amount": null,
          "type": {
            "name": null
          }
        },
        "loggingNgEnabled": true,
        "persistentQueues": false,
        "persistentQueuesEncryptionEnabled": false,
        "persistentQueuesEncrypted": false,
        "monitoringEnabled": true,
        "monitoringAutoRestart": true,
        "staticIPsEnabled": false,
        "secureDataGatewayEnabled": false,
        "loggingNgEnabled": true,
        "loggingCustomLog4JEnabled": true,
        "cloudObjectStoreRegion": null,
        "insightsReplayDataRegion": null
      }


'@



$RequestHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$RequestHeaders.Add("Accept", "application/json")
## Auth Header will get added after the Login cal

$REUserAgent = "Green Dot Release Engineering"
$DefaultRequestContentType = "application/json"
$AnyPointBaseURL = "https://anypoint.mulesoft.com/"
$AnyPointLoginURI = $AnyPointBaseURL + "accounts/login"
$APIManagerBaseURL = $AnyPointBaseURL + "apimanager/api/v1/"
$CHDeployURL = $AnyPointBaseURL + "cloudhub/api/v2/applications/"
$CHDomainCHeckURL=$AnyPointBaseURL + "/cloudhub/api/applications/domains/"
## Filled gradually in calls to Login, api/me and so on
$AccessToken = ""
$OrgId = ""
$EnvironmentId = ""

class APIMgmtInputInfo {

    [String]$assetId
    [String]$assetVersion
    [String]$groupId
    [String]$organizationId
    [String]$environmentId

}

<#
        $APIMgmtInputInfo = @{}
        $APIMgmtInputInfo.assetId = ""
        $APIMgmtInputInfo.assetVersion = ""
        $APIMgmtInputInfo.groupId = ""
        $APIMgmtInputInfo.organizationId = ""
        $APIMgmtInputInfo.environmentId = ""
#>



function Invoke-ResponseException ($ErrorMessage, $RESTError) {
    if ($RESTError) {
        $HttpStatusCode = $RESTError.ErrorRecord.Exception.Response.StatusCode.value__
        $HttpStatusDescription = $RESTError.ErrorRecord.Exception.Response.StatusDescription
        Write-Error (" {0} | Status Code: {1} Description: {1}" -f $ErrorMessage, $HttpStatusCode, $HttpStatusDescription)
        exit 1
    }

}



function Add-NewApi([APIMgmtInputInfo]$apiInputs) {
    $assetId = $apiInputs.assetId
    $assetVersion = $apiInputs.assetVersion
    $groupId = $apiInputs.groupId
    $orgId = $apiInputs.organizationId
    $envId = $apiInputs.environmentId
    Write-Host ("Add-NewApi: Attempting creation of New API. assetId: '{0}' | assetVersion: '{1}' | groupId: '{2}' | OrgId: '{3}' | envId: '{4}'" -f $assetId, $assetVersion, $groupId, $orgId, $envId)

    $result = @{ }
    $newAPIRequestObject = $APIManagerRequestTemplate | ConvertFrom-Json
    $newAPIRequestObject.endpoint.deploymentType = "CH"
    $newAPIRequestObject.endpoint.muleVersion4OrAbove = $true
    $newAPIRequestObject.endpoint.type = "raml"
    $newAPIRequestObject.spec.assetId = $assetId
    $newAPIRequestObject.spec.groupId = $groupId
    $newAPIRequestObject.spec.version = $assetVersion
    $newApiJSON = $newAPIRequestObject | ConvertTo-Json

    Write-Debug ([String]::new("-", 80))
    Write-Debug("New API Request JSON: '{0}'" -f $newApiJSON)
    Write-Debug ([String]::new("-", 80))

    $ApiMgrApiURI = $APIManagerBaseURL + "organizations/" + $orgId + "/environments/" + $envId + "/apis"
    Write-Debug ("Add-NewApi: Request URI: '{0}'" -f $ApiMgrApiURI)
    $ApiMgrNewApi = Invoke-WebRequest -Uri $ApiMgrApiURI -Method Post -Headers $RequestHeaders -ContentType $DefaultRequestContentType -Body $newApiJSON -ErrorVariable NewApiCreateError -UseBasicParsing| ConvertFrom-Json

    if ($NewApiCreateError) {
        Invoke-ResponseException "Error creating new API in API Manager", $NewApiCreateError
    }

    $hasId = [bool]($ApiMgrNewApi.PSObject.Properties.name -contains "id")
    $hasError = [bool]($ApiMgrNewApi.PSObject.Properties.name -contains "Error")
    Write-Debug ("Add-NewApi: PSObject Properties check: hasId: '{0}' | hasError: '{1}'" -f $hasId, $hasError)

    if ($hasId -eq $false -and $hasError -eq $true) {
        Write-Error ("Error Creating API with JSON value: '{0}' " -f $newApiJSON)
        exit 1
    }
    $ApiId = $ApiMgrNewApi.id
    $APIAutoDiscoveryApiName = [String]::Format("groupId:{0}:assetId:{1}:assetVersion:{2}:productVersion:{3}", $ApiMgrNewApi.groupId, $ApiMgrNewApi.assetId, $ApiMgrNewApi.assetVersion, $ApiMgrNewApi.productVersion)
    Write-Host ("Add-NewApi: API Manager New instance Created. Id: '{0}' | Composed Auto Discovery API Name: '{1}'" -f $ApiId, $APIAutoDiscoveryApiName)

    $result.apiId = $ApiId
    $result.autoDiscoverApiName = $APIAutoDiscoveryApiName
    return $result
}

function Get-APIManagerInfo ([bool]$changeSpec, $assetList, [APIMgmtInputInfo]$apiInputs) {
    $assetId = $apiInputs.assetId
    $assetVersion = $apiInputs.assetVersion
    $groupId = $apiInputs.groupId
    $orgId = $apiInputs.organizationId
    $envId = $apiInputs.environmentId

    Write-Debug "API Inputs"
    Write-Debug $apiInputs

    Write-Host("Get-APIManagerInfo: ChangeSpec: '{0}' | assetId: '{1}' | assetVersion: '{2}'" -f $changeSpec, $assetId, $assetVersion)
    $result = @{ }
    $assetListCount = $assetList.total
    if ($assetListCount -le 0) {
        $result = Add-NewApi $apiInputs
        return $result
    } ##  API Not found so create

    ## Following should run  when there is an asset i.e., assetList.total > 0
    $FilteredAPIs = New-Object System.Collections.ArrayList
    $apiId = ""
    $autoDiscoveryName = ""
    foreach ($asset in $assetList.assets) {
        foreach ($api in $asset.apis) {
            ## If AppInfo File asks to ChangeSpecification, search by assetId and assetVersion
            ## Else search by assetId only
            ## and add the found API object to the FilteredAPIs list
            if ($changeSpec -eq $false) {
                if ($api.assetVersion -eq $assetVersion -and $api.assetId -eq $assetId) {
                    Write-Debug("API Found for assetId: '{0}' | assetVersion: '{1}'. Adding to FilteredAPIs " -f $assetId, $assetVersion)
                    $FilteredAPIs.Add($api)
                }
            }
            else {
                if ($api.assetId -eq $assetId) {
                    Write-Debug("API Found for assetId: '{0}'. Adding to FilteredAPIs " -f $assetId)
                    $FilteredAPIs.Add($api)
                }
            }
        } ## Loop APIs
    } ### Loop Assets

    ### APICount > 1, exit with error, This is the same irrespective of changeSpec is true or not
    if ($FilteredAPIs.Count -gt 1) {
        Write-Error ("Multiple Instances found with same Asset information. Try again using Instance Label ")
        exit 1
    }

    ## APICount = 0, create New API and return information. This is the same irrespective of changeSpec being true or false
    if ($FilteredAPIs.Count -eq 0) {
        Write-Host("Get-APIManagerInfo: ChangeSpec: '{0}' and Filtered API count is 0 | Calling Add-NewAPI" -f $changeSpec)
        $result = Add-NewApi $apiInputs
        return $result
    }

    ## When both the above ifs are eliminated Filtered API count is 1
    Write-Host ("Collected APIs list count is: {0} " -f $FilteredAPIs.Count)
    $Api = $FilteredAPIs[0]
    $apiId = $Api.id

    ## AppInfo File does NOT ask for ChangeSpec
    if ($changeSpec -eq $false) {
        ## APICount = 1 collect id, autodiscoveryName and return
        $autoDiscoveryName = [String]::Format("groupId:{0}:assetId:{1}:assetVersion:{2}:productVersion:{3}", $Api.groupId, $Api.assetId, $Api.assetVersion, $Api.productVersion)
        Write-Host("Get-APIManagerInfo: ChangeSpec: '{0}' and Filtered API count is 1 | Returning with apiId: '{1}' and AutoDiscoveryName: '{2}' " -f $changeSpec, $apiId, $autoDiscoveryName)
        $result.apiId = $apiId
        $result.autoDiscoverApiName = $autoDiscoveryName
        return $result
    }
    else {
        ### API Info file says ChangeSpec = true
        ## If API count is 1 Patch it with supplied asset version
        $body = @{ }
        $body.assetVersion = $assetVersion
        $bodyJson = $body | ConvertTo-Json
        $patchUri = $APIManagerBaseURL + "organizations/" + $orgId + "/environments/" + $envId + "/apis/" + $apiId
        $apiPatchResponse = Invoke-WebRequest -Uri $patchUri -Method Patch -Headers $RequestHeaders -ContentType $DefaultRequestContentType -Body $bodyJson -ErrorVariable APIPatchError -UseBasicParsing| ConvertFrom-Json
        if ($APIPatchError) {
            Invoke-ResponseException "Error Patching API", $APIPatchError
        }

        ## Although call succeeded, there could be other errors, if the response did contain the "id" property it is being treated as success (?)
        $hasId = [bool]($apiPatchResponse.PSObject.Properties.name -contains "id")
        if ($hasId -eq $false) {
            Write-Error([string]::Format("Error Patching API with Asset Version. Uri: '{0}' | assetVersion: '{1}' ", $patchUri, $assetVersion))
            exit 1
        }
        $autoDiscoveryName = [String]::Format("groupId:{0}:assetId:{1}:assetVersion:{2}:productVersion:{3}", $Api.groupId, $Api.assetId, $Api.assetVersion, $Api.productVersion)
        $result.apiId = $apiId
        $result.autoDiscoverApiName = $autoDiscoveryName
        return $result
    }
    ## blank
    return $result
}

function Invoke-UpdatePolicy ($CurrentAPIBaseURL, [String]$policyId, $policyJson) {
    if ([String]::IsNullOrEmpty($policyId)) {
        Write-Error "Update-Policy invoked with NULL or BLANK policy Id"
        return $null
    }
    if ([String]::IsNullOrEmpty($policyJson)) {
        Write-Error "Update-Policy invoked with NULL or BLANK policy object"
        return $null
    }
    Write-Host("Updating Policy Id: '{0}'", $policyId)
    $policyUri = [String]::Format("{0}policies/{1}/", $CurrentAPIBaseURL, $policyId)
    $jsonBody = $policyJson | ConvertFrom-Json
    $integer_pid = [int]$policyId
    $jsonBody | Add-Member -Type NoteProperty -Name 'id' -Value $integer_pid
    $payloadJSON = $jsonBody | ConvertTo-Json

    Write-Host($payloadJSON | Out-String)
    $policyUpdateResponse = Invoke-WebRequest -Uri $policyUri -Method PATCH -Headers $RequestHeaders -Body $payloadJSON -ContentType $DefaultRequestContentType -ErrorVariable PolicyUpdateError -UseBasicParsing| ConvertFrom-Json

    if ($PolicyUpdateError) {
        Invoke-ResponseException "Error Updating Policy", $PolicyUpdateError
    }
    $hasPolicyTemplateId = [bool]($policyUpdateResponse.PSObject.Properties.name -contains "policyTemplateId")
    if ($hasPolicyTemplateId -eq $false) {
        Write-Error("Error Occurred while updating Policy at API '{0}' and Policy Id: '{1}'", $CurrentAPIBaseURL, $policyId)
        exit 1
    }
    return $policyId
} ## Invoke-UpdatePolicy



function Invoke-ApplyPolicy ($CurrentAPIBaseURL, $policyJson) {
    if ([String]::IsNullOrEmpty($policyJson)) {
        Write-Error "Apply Policy invoked with NULL policy object"
        return $null
    }
    $policyUri = [String]::Format("{0}policies", $CurrentAPIBaseURL)
    $applyPolicyResponse = Invoke-WebRequest -Uri $policyUri -Method Post -Headers $RequestHeaders -Body $policyJson -ContentType $DefaultRequestContentType -ErrorVariable ApplyPolicyError -UseBasicParsing| ConvertFrom-Json

    if ($ApplyPolicyError) {
        Invoke-ResponseException "Error applying policy", $ApplyPolicyError
    }

    ## $hasPolicyTemplateId = [bool]($applyPolicyResponse.PSObject.Properties.name -contains "policyTemplateId")
    $hasId = [bool]($applyPolicyResponse.PSObject.Properties.name -contains "id")

    if ($hasId -eq $false) {
        Write-Error("Applying Policy may have failed. API: '{0}', Policy: '{1}' ", $CurrentAPIBaseURL, $policyJson)
        exit 1
    }
    else {
        $policyId = $applyPolicyResponse.id
        return $policyId

    }

} ## Invoke-ApplyPolicy

function Invoke-ApplySLATiers($CurrentAPIBaseURL, $tierJson){
    if ([String]::IsNullOrEmpty($tierJson)) {
        Write-Error "Apply SLA Tier invoked with NULL policy object"
        return $null
    }
    $slaTierUri = [String]::Format("{0}tiers/", $CurrentAPIBaseURL)
    $applySLATierResponse = Invoke-WebRequest -Uri $slaTierUri -Method Post -Headers $RequestHeaders -Body $tierJson -ContentType $DefaultRequestContentType -ErrorVariable ApplySLATierError -UseBasicParsing| ConvertFrom-Json
    if ($ApplySLATierError) {
        Invoke-ResponseException "Error applying policy", $ApplySLATierError
    }
    $hasId = [bool]($applySLATierResponse.PSObject.Properties.name -contains "id")
    if ($hasId -eq $false) {
        Write-Error("Applying SLA Tiers may have failed. API: '{0}', SLATier: '{1}' ", $CurrentAPIBaseURL, $tierJson)
        exit 1
    }
    else {
        $tierid = $applySLATierResponse.id
        return $tierid

    }
}

function Invoke-UpdateSLATiers ($CurrentAPIBaseURL, [String]$tierId, $tierJson) {
    if ([String]::IsNullOrEmpty($tierId)) {
        Write-Error "Update-SLA Tiers invoked with NULL or BLANK policy Id"
        return $null
    }
    if ([String]::IsNullOrEmpty($tierJson)) {
        Write-Error "Update-SLA Tiers invoked with NULL or BLANK policy object"
        return $null
    }
    Write-Host("Updating SLA Tiers Id: '{0}'", $tierId)
    $slaTierUri = [String]::Format("{0}tiers/{1}/", $CurrentAPIBaseURL, $tierId)

    $applySLATierResponse = Invoke-WebRequest -Uri $slaTierUri -Method PUT -Headers $RequestHeaders -Body $tierJson -ContentType $DefaultRequestContentType -ErrorVariable SLATierUpdateError -UseBasicParsing| ConvertFrom-Json

    if ($SLATierUpdateError) {
        Invoke-ResponseException "Error Updating SLATier", $SLATierUpdateError
    }
    $hasId = [bool]($applySLATierResponse.PSObject.Properties.name -contains "id")
    if ($hasId -eq $false) {
        Write-Error("Error Occurred while updating SLATier at API '{0}' and SLATier Id: '{1}'", $CurrentAPIBaseURL, $tierId)
        exit 1
    }
    return $tierId
}

#{"properties" :{"mule.env": $muleenv,"mule.key": $mulekey,"anypoint.platform.client_id" : $platform_client_id,"anypoint.platform.client_secret" : $platform_client_secret,"api.id" : $api_id}}')
function Invoke-BuildRuntimeProperties($ApiId){
    $runttimeproperties = @()
    $runttimeproperties += [pscustomobject]@{
    'mule.env'=$Environment;
    'mule.key'=$MuleKey;
    'anypoint.platform.client_id'=$PlatformClientID;
    'anypoint.platform.client_secret'=$PlatformClientSecret;
    'anypoint.platform.config.analytics.agent.enabled'=$true
    'api.id'=$ApiId;
    'api.autoDiscoveryInfo'=$autoDiscoveryName
    'splunk.url'= $SplunkURL;
    'splunk.token'= $SplunkToken;

}
return $runttimeproperties
}

function Invoke-DomainAvailability($DomainUri,$DomainName){
    if ([String]::IsNullOrEmpty($DomainName)) {
        Write-Error "Domain Availability invoked with NULL or BLANK domain name"
        return $null
    }
    $DomainUri = [String]::Format("{0}{1}/", $DomainUri,$DomainName)

    $domainAvailabilityResponse = Invoke-WebRequest -Uri $DomainUri -Method GET -Headers $RequestHeaders -ContentType $DefaultRequestContentType -ErrorVariable DomainAvailabilityError -UseBasicParsing| ConvertFrom-Json

    if ($DomainAvailabilityError) {
        Invoke-ResponseException "Error Domain Availability Check", $DomainAvailabilityError
    }
    $isAvailable = $domainAvailabilityResponse.available
    return $isAvailable
}
function Invoke-CheckApplicationStatus($CheckAppUri){
    try{
        $applicationInfo = Invoke-WebRequest $CheckAppUri -Method Get -Headers $RequestHeaders -ContentType $DefaultRequestContentType -UseBasicParsing
        $applicationInfo = $applicationInfo | ConvertFrom-Json

        $status = $applicationInfo


    }catch [System.Net.WebException]{
        $status = @{ }
        $status.status= [int]$_.Exception.Response.StatusCode
    }
    return $status
}

function Invoke-ApplicationDeploy($APPDeployUri, $APIJarFileLocation,$appInfoJson, $actionType){

    $deployStatus = $null
    Add-Type -AssemblyName System.Net.Http
    Add-Type -AssemblyName System.Runtime
    $httpClientHandler = New-Object System.Net.Http.HttpClientHandler
    $httpClient = New-Object System.Net.Http.Httpclient $httpClientHandler
    $packageFileStream = New-Object System.IO.FileStream @($APIJarFileLocation, [System.IO.FileMode]::Open)

    $contentDispositionHeaderValue = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue "form-data"
    $contentDispositionHeaderValue.Name = "file"
    $contentDispositionHeaderValue.FileName = (Split-Path $APIJarFileLocation -leaf)

    $streamContent = New-Object System.Net.Http.StreamContent $packageFileStream
    $streamContent.Headers.ContentDisposition = $contentDispositionHeaderValue
    $streamContent.Headers.ContentType = New-Object System.Net.Http.Headers.MediaTypeHeaderValue "application/java-archive"
    $content = New-Object System.Net.Http.MultipartFormDataContent
    $content.Add($streamContent)

    $autoStartFormData = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue "form-data"
    $autoStartFormData.Name = "`"autoStart`""
    $autoStartContentValue= NEW-Object System.Net.Http.StringContent "true"
    $autoStartContentValue.Headers.ContentDisposition = $autoStartFormData
    $content.Add($autoStartContentValue)

    $appInfoJsonFormData= New-Object System.Net.Http.Headers.ContentDispositionHeaderValue] 'form-data'
    $appInfoJsonFormData.Name="`"appInfoJson`""
    $appInfoJsonContentValue=New-Object System.Net.Http.StringContent ($appInfoJson | Out-String)
    $appInfoJsonContentValue.Headers.ContentDisposition =$appInfoJsonFormData
    $content.Add($appInfoJsonContentValue)

    try{
        Write-Host("Before Invoking the request")
        $httpClient.DefaultRequestHeaders.Add("X-ANYPNT-ENV-ID",$EnvironmentId)
        $httpClient.DefaultRequestHeaders.Add("X-ANYPNT-ORG-ID",$OrgId)
        $httpClient.DefaultRequestHeaders.Add("Authorization", $AuthToken)

        $httpClient.Timeout = New-TimeSpan  -Minutes 10
        if($actionType.ToLower() -eq "create"){
        $response =  $httpClient.PostAsync($APPDeployUri, $content).GetAwaiter().GetResult()
        } elseif($actionType.ToLower() -eq "update"){
            $response =  $httpClient.PutAsync($APPDeployUri, $content).GetAwaiter().GetResult()

        }

       Write-host("Received -Respone '{0}' " -f $response.StatusCode)

			if (!$response.IsSuccessStatusCode)
			{
				$responseBody = $response.Content.ReadAsStringAsync().Result
				$errorMessage = "Status code {0}. Reason {1}. Server reported the following message: {2}." -f $response.StatusCode, $response.ReasonPhrase, $responseBody

                Write-Error("Error Occured while deploying the application to cloudhub environment with '{0}' ",  $errorMessage)
                exit 1
			}
            $deploymentResponse= $response.Content.ReadAsStringAsync().Result | ConvertFrom-Json
            $deployStatus=$deploymentResponse.status


    }catch [Exception]{
        Write-Error("Error occure while deploying the application {0}", $_.Exception.ToString())

    }finally{
        if($null -ne $httpClient)
            {
                $httpClient.Dispose()
            }

            if($null -ne $response)
            {
                $response.Dispose()
            }
            if($null -ne $packageFileStream){
                $packageFileStream.Close()
            }

    }

    return $deployStatus



<#


    $filepath= Get-ChildItem $APIJarFileLocation
    $fileBytes = [System.IO.File]::ReadAllBytes($APIJarFileLocation)
    $filename=$filepath.name
    Write-Host($filename)
    $boundary=[System.Guid]::NewGuid().ToString();
    $fileEnc=[System.Text.Encoding]::GetEncoding('UTF-8').GetString($fileBytes)
    $LF="`r`n"
    $payloadFormData= @(
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$filename`"$LF" ,
        "Content-Type: application/java-archive$LF"
        $fileEnc,
        "--$boundary",
        "Content-Disposition: form-data; name=`"appInfoJson`"$LF",
        $appInfoJson,
        "--$boundary",
        "Content-Disposition: form-data; name=`"autoStart`"$LF",
        $true,
     "--$boundary--$LF"
    ) -join $LF


    $deployResponse= Invoke-WebRequest -URi $APPDeployUri -Method POST -ContentType "multipart/form-data; boundary=`"---$boundary`""  -Headers $RequestHeaders -Body $payloadFormData -ErrorVariable DeployResponseError -Verbose

    if ($DeployResponseError) {
        Write-Host($DeployResponseError)
        Invoke-ResponseException "New Deploy Application Error", $DeployResponseError

    }
    Write-Host($deployResponse)


    #>




}


function Banner ($Content) {
    Write-Host ([String]::new("=", 80))
    Write-Host ([datetime]::Now.ToString())
    Write-Host ($Content)
    Write-Host ([String]::new("=", 80))

}


#### ===================================================================
## Script Start
#### ===================================================================

Banner "Beginning Deployment ... "

## Login
$LoginPayload = @{ }
$LoginPayload.username = $AnyPointUser
$LoginPayload.password = $AnyPointPwd
$LoginPayloadJSON = $LoginPayload | ConvertTo-Json

$LoginResponse = Invoke-WebRequest -Uri $AnyPointLoginURI -Method Post -Headers $RequestHeaders -Body $LoginPayloadJSON -UserAgent $REUserAgent -ContentType $DefaultRequestContentType -ErrorVariable LoginError -UseBasicParsing | ConvertFrom-Json -Verbose

if ($LoginError) {
    Invoke-ResponseException "Error Logging in", $LoginError
}
[string] $AccessToken = $LoginResponse.access_token
if ($AccessToken -eq '') {
    Write-Error ([String]::Format("Access TOken is retrieved is NULL for userName name '{0}'", $AnyPointUser))
    exit 1
}
Write-Debug  "Login Payload: $LoginPayloadJSON | Login Response: $LoginResponse | Access Token: $AccessToken"

$AuthToken = [String]::Format("Bearer {0}", $AccessToken)
Write-Debug "Bearer Token Added to Headers ... "
$RequestHeaders.Add("Authorization", $AuthToken)

Write-Host  "Login Complete. Retrieving Org.Id ...... "
$APIMeURI = $AnyPointBaseURL + "accounts/api/me"

$MeResponse = Invoke-WebRequest -Uri $APIMeURI -Method Get -Headers $RequestHeaders -ContentType $DefaultRequestContentType -ErrorVariable APIMeError -UseBasicParsing| ConvertFrom-Json

if ($APIMeError) {
    Invoke-ResponseException "Error retrieving user profile details", $APIMeError
}
Write-Debug "Me Response: "
Write-Debug ($MeResponse | ConvertTo-Json)
$memberships = $MeResponse.user.memberOfOrganizations

foreach ($Org in $memberships) {
    Write-Debug ("Processing Org:" + $Org.name)
    if ($Org.name -eq $AnyPointOrgName) {
        Write-Debug ("Found Organization " + $AnyPointOrgName)
        $OrgId = $Org.id
        break;
    }
}

Write-Debug ("Organization Id: " + $OrgId)
if ($orgId -eq '') {
    Write-Error ([String]::Format("Organization Id retrrieved is NULL for Organization name '{0}'", $AnyPointOrgName))
    exit 1
}


Write-Host  "Org.Id Retrieved. Retrieving EnvId ... "
$EnvURI = $AnyPointBaseURL + "accounts/api/organizations/" + $OrgId + "/environments"

$EnvDetailsResponse = Invoke-WebRequest -Uri $EnvURI -Method Get -Headers $RequestHeaders -ContentType $DefaultRequestContentType -ErrorVariable EnvDetailsError -UseBasicParsing| ConvertFrom-Json
if ($EnvDetailsError) {
    Invoke-ResponseException "Error retrieving Organization Details", $EnvDetailsError
}

Write-Debug "Org Details Response: "
Write-Debug ($EnvDetailsResponse | ConvertTo-Json)

foreach ($env in $EnvDetailsResponse.data) {
    Write-Debug ("Processing Environment " + $env.name)
    if ($env.name.ToLower() -eq $AnyPointEnvName.ToLower())  {
        Write-Debug ("Found Environment id for " + $AnyPointEnvName)
        $EnvironmentId = $env.id
        break;
    }
}
Write-Debug ("Environment Id: " + $EnvironmentId)
Write-Host  "Environment Id Retrieved. ... "
if ($EnvironmentId -eq '') {
    Write-Error ([String]::Format("Environment Id retrrieved is NULL for Environment name '{0}'", $AnyPointEnvName))
    exit 1
}

Write-Host ([String]::new("-", 80))
Write-Host ("Retrieved id '{0}' for Organization '{1}'" -f $OrgId, $AnyPointOrgName)
Write-Host ("Retrieved id '{0}' for Environment '{1}' " -f $EnvironmentId, $AnyPointEnvName)
Write-Host ([String]::new("-", 80))

<# ~~~~~~~~~~~~~~~~~ All Prerequisites have been retrieved so far ~~~~~~~~~~~~~~~~~ #>

if ([System.IO.File]::Exists($InputFile) -eq $false) {
    Write-Error ([String]::Format("File '{0}' Not found", $InputFile))
    exit 1
}

$AppInfo = (Get-Content $InputFile -Raw) | ConvertFrom-Json

if ($null -eq $AppInfo) {
    Write-Error ([String]::Format("Error parsing AppInfo JSON from '{0}'", $InputFile))
    exit 1
}


<## EXCHANGE #>

$assetId = $AppInfo.exchangeAssetInfo.assetId
$groupId = $AppInfo.exchangeAssetInfo.groupId
$assetVersion = $AppInfo.exchangeAssetInfo.version
$assetType = $AppInfo.exchangeAssetInfo.assetType
$productVersion = $AppInfo.exchangeAssetInfo.productVersion

$apiManagementInfo = $AppInfo.apiManagement | Where-Object { ($_.env.ToLower() -eq $AnyPointEnvName.ToLower())} | Select-Object -first 1
if($null -eq $apiManagementInfo){
    $apiManagementInfo = $AppInfo.apiManagement | Where-Object { ($_.env -eq "")} | Select-Object -first 1
    Write-Host($apiManagementInfo| ConvertTo-Json)
    if($null -eq $apiManagementInfo ) {
        Write-Error("Invalid API Management info specified in the input file. No matching API Management info for the environment {0}" -f $AnyPointEnvName)
        exit 1
    }

}

Write-Debug($apiManagementInfo)





$instanceLabel = $apiManagementInfo.instanceLabel
[bool]$changeSpecification = $apiManagementInfo.changeSpecification

<# --------------- SEEMS NOT USED --------------- #>
## $autoGeneratedInstanceLabel = [String]::Format("auto-generated-{0}-{1}", $AnyPointEnvName, [datetime]::Now.ToString("yyyyMMddHHmmssfff"))
<# --------------- SEEMS NOT USED --------------- #>


if ($null -eq $assetId -or $null -eq $groupId -or $null -eq $assetVersion) {
    Write-Error ([String]::Format("Required Parameters missing in App Information. Input File contents: '{0}' ", ($AppInfo | ConvertTo-Json)))
    exit 1
}

Write-Host ("Input file Processed. Checking Asset existence ... ")
$assetDetailsURI = $AnyPointBaseURL + "exchange/api/v1/assets/$groupId/$assetId/$assetVersion"
$assetDetailQueryResponse = Invoke-WebRequest -Uri $assetDetailsURI -Method Get -Headers $RequestHeaders -ContentType $DefaultRequestContentType -ErrorVariable AssetDetailsError -UseBasicParsing| ConvertFrom-Json
if ($AssetDetailsError) {
    Invoke-ResponseException "Error querying for Asset existence", $AssetDetailsError
}
Write-Host("Found Asset with id '{0}'", $assetDetailQueryResponse.assetId)
$assetStatus = $assetDetailQueryResponse.status
$assetType = $assetDetailQueryResponse.type

if ($assetStatus -is [int] -and $assetStatus -gt 399 ) {
    Write-Error ("Asset not found in Exchange")
    exit 1
}

Write-Host("Found Asset with id '{0}' with status '{1}'" -f $assetDetailQueryResponse.assetId, $assetStatus)
## ---------- END EXCHANGE CALLS
<## API MANAGEMENT #>
$searchURLFragment = [String]::Format("organizations/{0}/environments/{1}/apis?assetId={2}&groupId={3}&productVersion={4}&ascending=false&limit=20&offset=0&sort=createdDate", $OrgId, $EnvironmentId, $assetId, $groupId, $productVersion)
if ([String]::IsNullOrEmpty($instanceLabel) -eq $false) {
    $searchURLFragment = [String]::Format("organizations/{0}/environments/{1}/apis?assetId={2}&groupId={3}&productVersion={4}&instanceLabel={5}&ascending=false&limit=20&offset=0&sort=createdDate", $OrgId, $EnvironmentId, $assetId, $groupId, $productVersion, $instanceLabel)
}

Write-Debug ([String]::Format("Instance Label: {0} | Search URL Fragment: {1}", $instanceLabel, $searchURLFragment))
$ApiManagerSearchURL = $APIManagerBaseURL + $searchURLFragment

$assetListData = Invoke-WebRequest -Uri $ApiManagerSearchURL -Method Get -Headers $RequestHeaders -ContentType $DefaultRequestContentType -ErrorVariable AssetListError -UseBasicParsing| ConvertFrom-Json
if ($AssetListError) {
    Invoke-ResponseException "Error getting Asset List", $AssetListError
}

$apiInput = New-Object APIMgmtInputInfo
$apiInput.assetId = $assetId
$apiInput.assetVersion = $assetVersion
$apiInput.groupId = $groupId
$apiInput.organizationId = $OrgId
$apiInput.environmentId = $EnvironmentId

$APIData = Get-APIManagerInfo $changeSpecification $assetListData $apiInput
## This variable is used in subsequent ops
$ApiId = $APIData.apiId
## This variable is composed from API meta data and is associated with the deployment for tracking
$APIAutoDiscoveryApiName = $APIData.autoDiscoverApiName

$CurrentAPIBaseURL = $APIManagerBaseURL + "organizations/" + $OrgId + "/environments/" + $EnvironmentId + "/apis/" + $ApiId + "/"

Banner "API POLICY"

## Read policy settings from AppInfo file
$Policies = $apiManagementInfo.policies

if ($null -ne $Policies -and [String]::IsNullOrEmpty($ApiId) -eq $false) {

    $policiesUri = $CurrentAPIBaseURL + "policies?fullInfo=true"
    $apiManagerPolicies = Invoke-WebRequest -Uri $policiesUri -Method Get -Headers $RequestHeaders -ContentType $DefaultRequestContentType -ErrorVariable PolicyQueryError -UseBasicParsing | ConvertFrom-Json

    if ($PolicyQueryError) {
        Invoke-ResponseException "Error Getting Policy Info from API Manager", $PolicyQueryError
    }
    Write-Debug "API Manager Policies"
    Write-Debug ($apiManagerPolicies | ConvertTo-Json)
    foreach ($policy in $Policies) {
        $policyAssetId = $policy.assetId
        $policyAssetVersion = $policy.assetVersion
        $policyOverride = $policy.policyOverride
        $requiredPolicy = $null

        foreach ($policyItem in $apiManagerPolicies.policies) {
            if ($policyItem.template.assetId -eq $policyAssetId -and $policyItem.template.assetVersion -eq $policyAssetVersion) {
                $requiredPolicy = $policyItem
                Write-Host ("Found Policy with assetId: '{0}' and assetVersion: '{1}' | Override: '{2}'" -f $policyAssetId, $policyAssetVersion, $policyOverride)
                Write-Debug ("Required Policy found. Id: '{0}'" + $policyId)
                break
            }
        } ## Policies defined in APIManager

        $policyId = $requiredPolicy.policyId


        if ($null -ne $requiredPolicy) {
            if ($policyOverride -eq $true) {
                $pJson = $policy | ConvertTo-Json ## This is whats defined in the AppInfo file
                $resp_policyId = Invoke-UpdatePolicy $CurrentAPIBaseURL $policyId $pJson
                if ($null -ne $resp_policyId -and [String]::IsNullOrEmpty($resp_policyId) -eq $false ) {
                    Write-Host ("Policy update with the latest information for '{0}'" -f $resp_policyId)
                }
                else {
                    Write-Error ("Error While applying policy for API Manager Instance '{0}' for the policy id '{1}' " -f $ApiId, $policyId)

                }

            }
            else {
                Write-Host ("Policy already available for '{0}'" -f $policyId)
            }
        }
        else {
            $pJson = $policy | ConvertTo-Json ## This is whats defined in the AppInfo file
            Write-Host($policy| ConvertFrom-Json)
            $resp_policyId = Invoke-ApplyPolicy $CurrentAPIBaseURL $pJson
            if ($null -ne $resp_policyId -and [String]::IsNullOrEmpty($resp_policyId) -eq $false ) {
                Write-Host ("Policy created successfully with and Policy ID is '{0}'" -f $resp_policyId)
            }
            else {
                Write-Error ("Error While applying policy for API Manager Instance '{0}'" -f $ApiId)

            }



        }
    } ## Loop Policies defined in AppInfo File
}
else { Write-Host "No Policy Updates defined in App Info" }


Banner "SLAs"
## Read SLA settings from AppInfo file
$SLATiers = $apiManagementInfo.SLATier

if ($null -ne $SLATiers -and [String]::IsNullOrEmpty($ApiId) -eq $false) {
    $slaUri = $CurrentAPIBaseURL + "tiers"
    $apiManagerSLAs = Invoke-WebRequest $slaUri -Method Get -Headers $RequestHeaders -ContentType $DefaultRequestContentType -ErrorVariable SLAGetError -UseBasicParsing| ConvertFrom-Json

    if ($SLAGetError) {
        Invoke-ResponseException "Error getting SLAS for Current API " + $ApiId , $SLAGetError
    }
    $totalCnt = $apiManagerSLAs.total
    $requiredTier = $null
    $tierId = ""
    $requiredTierLimits = New-Object System.Collections.ArrayList
    [bool]$slaTierOtherParameterChange = $true


    foreach ($slaTier in $SLATiers) {
        $tierName = $slaTier.name
        $tierDescription = $slaTier.Description
        $tierAutoApproval = $slaTier.autoApprove
        $tierLimits = $slaTier.limits

        foreach ($apiTier in $apiManagerSLAs.tiers) {
            if ($apiTier.name -eq $tierName) {
                $requiredTier = $apiTier
                break
            }
        }
        if ($null -ne $requiredTier) {
            $tierId = $requiredTier.id
            foreach ($limit in $requiredTier.limits) {
                $requiredTierLimits.Add($limit)
            }
            if($requiredTier.name -eq $tierName -and $requiredTier.description -eq $tierDescription -and $requiredTier.autoApprove -eq $tierAutoApproval){
                $slaTierOtherParameterChange = $false
            }
            $compareResult = Compare-Object $requiredTierLimits $tierLimits

            if($null -eq $compareResult -and $slaTierOtherParameterChange -eq $false ){
                Write-Host ("SLA already available for '{0}' with SLA Tier ID '{1}" -f $ApiId,$tierId)
            }
            else{
                $pJson = $slaTier | ConvertTo-Json ## This is whats defined in the AppInfo file
                $resp_tierId = Invoke-UpdateSLATiers $CurrentAPIBaseURL $tierId $pJson
                if ($null -ne $resp_tierId -and [String]::IsNullOrEmpty($resp_tierId) -eq $false ) {
                    Write-Host ("SLATier updated successfully for the API Manager Instance '{0}' and SLA Tier ID is '{1}'" -f $ApiId, $resp_tierId)
                }
            }
}
        else{
            $pJson = $slaTier | ConvertTo-Json ## This is whats defined in the AppInfo file
            $resp_tierId = Invoke-ApplySLATiers $CurrentAPIBaseURL $pJson
            if ($null -ne $resp_tierId -and [String]::IsNullOrEmpty($resp_tierId) -eq $false ) {
                Write-Host ("SLATier created successfully for the API Manager Instance '{0}' and SLATier ID is '{1}'" -f $ApiId, $resp_tierId)
            }
            else {
                Write-Error ("Error While applying policy for API Manager Instance '{0}'" -f $ApiId)

            }
        }
    }   ## Loop SLAs defined in AppInfo File



}
else { Write-Host "No SLAs defined in App Info" }

Banner "Deployment"
## Application deployment to Cloudhub environment.
## Construct the domain name for the application
$domainname=[String]::Format("{0}-{1}-{2}{3}",$CompanyAbbreviation,$assetId,$Environment,$AppDeploySuffix)
Write-Host("Domain Name is '{0}'" -f $domainname)
$RequestHeaders.Add("X-ANYPNT-ENV-ID",$EnvironmentId)
$RequestHeaders.Add("X-ANYPNT-ORG-ID",$OrgId)
$applicationInfo=""


$applicationInfoUri = [String]::Format("{0}{1}/", $CHDeployURL, $domainname)
# Check Application Status
$status = Invoke-CheckApplicationStatus $applicationInfoUri
Write-Host($status.status)


## Building Runtime Properties

$runttimeproperties = Invoke-BuildRuntimeProperties($ApiId)
$newApplicationInfoObject = $CHApplicationTemplate | ConvertFrom-Json
$newApplicationInfoObject.domain = $domainname
$newApplicationInfoObject.muleVersion.version = $MuleVersion
$newApplicationInfoObject.region = $Region
$newApplicationInfoObject.workers.amount = $NumWorkers
$newApplicationInfoObject.workers.type.name = $WorkerType
$newApplicationInfoObject.properties = $runttimeproperties

$newAppInfoJson = $newApplicationInfoObject | ConvertTo-Json
## Application domain name not found in the cloudhub instance. Proceed with new deployment
if($status.status -eq 404){
    $isDomainAvailable = Invoke-DomainAvailability $CHDomainCHeckURL $domainname
    if($false -eq $isDomainAvailable){
        Write-Error("Domain Name is not available : '{0}'", $domainname);
    }else{
        Write-Host($APIJarFileLocation)
        $actiontype="CREATE"
        $appResponseStatus = Invoke-ApplicationDeploy $CHDeployURL $APIJarFileLocation $newAppInfoJson $actiontype
    }


}else{
    Write-Host("Updating Existing Application in Cloudhub '{0}'" -f $domainname)
    $CHDeployURL = [String]::Format("{0}{1}/", $CHDeployURL,$domainname)
    $actiontype="UPDATE"
    $appResponseStatus = Invoke-ApplicationDeploy $CHDeployURL $APIJarFileLocation $newAppInfoJson $actiontype
}

if($null -eq $appResponseStatus ){
    Write-Error("Error occured while deploying the application to cloudhub environment")
    exit 1
}elseif($appResponseStatus -eq "UNDEPLOYED"){

    $count = 0
    do{
        $appResponseStatus = Invoke-CheckApplicationStatus $applicationInfoUri
        $count++
    Write-Host("sleep count is '{0}'" -f $count )
    Write-Host("Status is '{0}'" -f $appResponseStatus.status )
        If($appResponseStatus.status -eq "UNDEPLOYED" -or $appResponseStatus.status -eq "DEPLOYING"){
            START-SLEEP -SECONDS 60
        }

    }while($count -lt 9 -and ($appResponseStatus.status -eq "UNDEPLOYED" -or $appResponseStatus.status -eq "DEPLOYING" ))

    if($appResponseStatus.status -like "*FAIL*"){
        Write-Error("Error occured while deploying the application to cloudhub environment")
        exit 1
    } elseif ($appResponseStatus.status -eq "STARTED" -and [String]::IsNullOrEmpty($appResponseStatus.deploymentUpdateStatus) -eq $false -and $appResponseStatus.deploymentUpdateStatus -like "*FAIL*"){
        Write-HOST("Error occured while deploying the application to cloudhub environment")
        exit 1

    }
    elseif ($appResponseStatus.status -eq "STARTED"){
        Write-HOST("Application Deployed successfully to the Cloudhub environment")
        exit 0

    }else {
        Write-HOST("Application is still in UNDEPLOYED status. Please check the application logs for additional details")
        exit 1

    }

}

elseif($appResponseStatus -like "*FAIL*"){
    Write-Error("Error occured while deploying the application to cloudhub environment")
    exit 1

}
elseif($appResponseStatus -like "*STARTED*" -and  $actiontype -eq "UPDATE"){

    $count = 0
    do{
        $appResponseStatus = Invoke-CheckApplicationStatus $applicationInfoUri
        $count++
    Write-Host("sleep count is '{0}'" -f $count)
    Write-Host("Current Status '{0}'" -f $appResponseStatus.status)
    Write-Host("Current Status '{0}'" -f $appResponseStatus.deploymentUpdateStatus)
        If($appResponseStatus.deploymentUpdateStatus -eq "DEPLOYING" -or $count -le 2){
            START-SLEEP -SECONDS 60
        }

    }while($count -lt 9 -and ([String]::IsNullOrEmpty($appResponseStatus.deploymentUpdateStatus) -eq $false -or $count -lt 3))

    if($appResponseStatus.status -like "*FAIL*"){
        Write-Error("Error occured while deploying the application to cloudhub environment")
        exit 1
    } elseif ($appResponseStatus.status -eq "STARTED" -and [String]::IsNullOrEmpty($appResponseStatus.deploymentUpdateStatus) -eq $false -and $appResponseStatus.deploymentUpdateStatus -like "*FAIL*"){
        Write-HOST("Error occured while deploying the application to cloudhub environment")
        exit 1

    }
    elseif ($appResponseStatus.status -eq "STARTED"){
        Write-HOST("Application Deployed successfully to the Cloudhub environment")
        exit 0

    }else {
        Write-HOST("Application is still in UNDEPLOYED status. Please check the application logs for additional details")
        exit 1

    }

}
else{

    Write-HOST("Application Deployed successfully to the Cloudhub environment")
    exit 0

}
