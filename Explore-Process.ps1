<#

.SYNOPSIS
Explore-Process performs advanced searching and information gathering or processes running.

.DESCRIPTION
Explore-Process performs advanced searching and information gathering or processes running.
For example, it can read hidden processes that Get-Process cannot and it can retrieve usernames of processes. 
Additionally, it can also retrieve virus total results for process binaries.
LICENSE: MIT License

.EXAMPLE 
.\Explore-Process.ps1   
Gets details Process Information. If Run from Elevated Prompt, also get's hidden processes.

.EXAMPLE 
.\Explore-Process.ps1 -SearchFilter {Where-Object {$_.ProcessName -eq "rawcap.exe"}} -IncludeUserName True
Apply A search filter and include process username

.EXAMPLE 
.\Explore-Process.ps1 -IncludeUserName True -SearchFilter {Where-Object {$_.ProcessName -eq 'rawcap.exe'}} -VirusTotal True -GetHashes True -Upload True -ApiKey "1234567891011121314151617181920212223242526272829303132333435363" -StoreApiKey True
Apply A search filter, include username, hash binaries and upload to virustotal for results, supplies a Virus Total API Key and stores it as a securestring

.PARAMETER ApiKey
Virus Total API Key Is a 64 Character Hex String.

.PARAMETER SearchFilter
A Where Script Block To Filter Process Objects. Example:`n { Where-Object {`_.ProcessName -eq 'svchost'} }`n

.PARAMETER StoreApiKey
-StoreApiKey True
Stores VirusTotal API Key As Secure String so you dont have to keep specifying this from the command line.

.PARAMETER ComputerName
Remote Computer To Get Processes From

.PARAMETER Credential
Manually Specify Credentials For Remote Host

.PARAMETER VirusTotal
-VirusTotal True
Search VirusTotal For Process Binary. Default is False. BE CAREFUL: Due to the Virus Total API limit of 4 requests Per minute, be sure to apply a very specific -SearchFilter to reduce the number of binaries processed. Unless of course your -ApiKey Specified has a higher limit.

.PARAMETER Upload
-Upload True
If -Upload False then hash will be searched instead.

.PARAMETER GetHashes
-GetHashes True
To Get Process Excutable File Hashes.

.PARAMETER IncludeUserName
Include Process Username

.PARAMETER Proxy
Set the proxy information here

.PARAMETER ProxyCredential
Proxy Credential Information Here

.PARAMETER ProxyUseDefaultCredentials
Use default proxy credentials

.PARAMETER SkipCertChecks
Skip All Certificate Checks When using SSL to connect to remote computer

.NOTES
Create by Christopher Davis. Uses some powershell code created by DarkOperator to submit Virustotal Results. 
See darkoperators work here https://github.com/darkoperator/Posh-VirusTotal/blob/master/Posh-VirusTotal.psm1

.LINK
https://github.com/chrisjd20/Explore-Process

#>

[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
param(
    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="Virus Total API Key Is a 64 Character Hex String.")]
    [string]
    $ApiKey,

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="A Where Script Block To Filter Process Objects. Example:`n { Where-Object {`$_.ProcessName -eq 'svchost'} }`n")]
    [ScriptBlock]
    $SearchFilter = {Where-Object {$_}},

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="Stores VirusTotal API Key As Secure String")]
    [ValidateSet( "True", "False" )]
    $StoreApiKey = "False",

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="Remote Computer To Get Processes From")]
    [string]$ComputerName,

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="Manually Specify Credentials For Remote Host")]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="Search VirusTotal For Process Binary. Default is False. BE CAREFUL: Due to the Virus Total API limit of 4 requests Per minute, be sure to apply a very specific -SearchFilter to reduce the number of binaries processed. Unless of course your -ApiKey Specified has a higher limit.")]
    [ValidateSet( "True", "False" )]    
    $VirusTotal = "False",

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="If -Upload False then hash will be searched instead.")]
    [ValidateSet( "True", "False" )]    
    $Upload = "False",

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="To Get File Hashes, -GetHashes True")]
    [ValidateSet( "True", "False" )]    
    $GetHashes = "False",

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="Include Process Username")]
    [ValidateSet( "True", "False" )]    
    $IncludeUserName = "False",

    [Parameter(Mandatory=$false,
        ParameterSetName="Default",
        HelpMessage="Skip All Certificate Checks When using SSL to connect to remote computer")]
    [ValidateSet( "True", "False" )]    
    $SkipCertChecks = "False",

    [Parameter(ParameterSetName = 'Default',
        Mandatory=$false,
        HelpMessage="Set the proxy information here")]
    [string]$Proxy,

    [Parameter(ParameterSetName = 'Default',
        Mandatory=$false,
        HelpMessage="Proxy domain\username Here")]
    [string]$ProxyUser,

    [Parameter(ParameterSetName = 'Default',
        Mandatory=$false,
        HelpMessage="Proxy Password Here")]
    [string]$ProxyPass,

    [Parameter(ParameterSetName = 'Default',
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        HelpMessage="Use default proxy credentials")]
    [Switch]$ProxyUseDefaultCredentials
)
function parse_params() {
    $StoreApiKey = [System.Convert]::ToBoolean($StoreApiKey)
    $VirusTotal = [System.Convert]::ToBoolean($VirusTotal)
    $Upload = [System.Convert]::ToBoolean($Upload)
    $GetHashes = [System.Convert]::ToBoolean($GetHashes)
    $IncludeUserName = [System.Convert]::ToBoolean($IncludeUserName)
    $SkipCertChecks = [System.Convert]::ToBoolean($SkipCertChecks)
    if ($VirusTotal) {
        if ($ApiKey -Match '^[a-f0-9]{64}$' -and $StoreApiKey) { 
            $secure_api_key = (ConvertTo-SecureString -AsPlainText -String $ApiKey -Force) | Convertfrom-Securestring
        } elseif ([System.Environment]::GetEnvironmentVariable('VTAPIKEY') -ne $null -and -not [System.Convert]::ToBoolean(($ApiKey.length))) { 
            try {
                $secure_api_key = [System.Environment]::GetEnvironmentVariable('VTAPIKEY')
            } catch {
                [System.Environment]::SetEnvironmentVariable('VTAPIKEY', $null, [System.EnvironmentVariableTarget]::User)
            }
        }
        if (-not [System.Convert]::ToBoolean($secure_api_key.length) -and -not $ApiKey -Match '^[a-f0-9]{64}$') {
            $securePassword = Read-Host "Virus Total API Key" -AsSecureString
            if ($securePassword.length -ne 64) {
                Throw "Invalid Virus total API Key"
            } else {
                $secure_api_key = ($securePassword | Convertfrom-Securestring)
            }
        }
        if ([System.Convert]::ToBoolean($secure_api_key.length) -and $secure_api_key -Match '^[a-f0-9]+$') { 
            $ApiKey = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto(([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR( ($secure_api_key | Convertto-Securestring) ))))
        }
        if ($StoreApiKey) {
            if (-not [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")){
                throw "Cannot Store API Key Because Not Running As Elevated PowerSHell Prompt"
            } else {
                [System.Environment]::SetEnvironmentVariable('VTAPIKEY', $secure_api_key, [System.EnvironmentVariableTarget]::User)
            }
        }
    }
    $ApiKey
    $VirusTotal
    $Upload
    $GetHashes
    $IncludeUserName
    $SkipCertChecks
}
function main() {
    $ApiKey,$VirusTotal,$Upload,$GetHashes,$IncludeUserName,$SkipCertChecks = parse_params
    $AScriptBlock = {
        param($ApiKey, $SearchFilter, $VirusTotal, $Upload, $GetHashes, $IncludeUserName, $Proxy, $ProxyUser, $ProxyPass, $ProxyUseDefaultCredentials)
        if ($ProxyUser -and $ProxyPass) {
            $password = $ProxyPass | ConvertTo-SecureString -asPlainText -Force
            $ProxyCredential = New-Object System.Management.Automation.PSCredential($ProxyUser,$password)
        }
        $VirusTotal = [System.Convert]::ToBoolean($VirusTotal)
        $Upload = [System.Convert]::ToBoolean($Upload)
        $GetHashes = [System.Convert]::ToBoolean($GetHashes)
        $IncludeUserName = [System.Convert]::ToBoolean($IncludeUserName)
        if ($IncludeUserName) {
            $userpids = Get-Process -IncludeUserName | select UserName,Id | Where-Object {$_.UserName.length}
        }
        $SearchFilter = [Scriptblock]::Create($SearchFilter)
        $all_processes = Get-WmiObject -Class Win32_Process | Foreach-Object {
            $Readable = $false
            if ($GetHashes -or $VirusTotal) {
                try {
                    [System.IO.File]::OpenRead($_.ExecutablePath).Close()
                    $Readable = $true
                } catch {}
            }
            $tmpobj = [PSCustomObject]@{
                ProcessName = $_.ProcessName
                CommandLine = $_.CommandLine
                PSComputerName = $_.PSComputerName
                CreationDate = ([WMI] '').ConvertToDateTime($_.CreationDate)
                CreationDateTimeStamp = $_.CreationDate
                ExecutablePath = $_.ExecutablePath
                Handle = $_.Handle
                Id = $_.Handle
                ProcessId = $_.ProcessId
                SessionId = $_.SessionId                # If 1, this is running under logged in user
                ParentProcessId = $_.ParentProcessId
                ParentProcess = ""
                Path = $_.Path
            }
            if ($IncludeUserName) {
                $tmpuser = ($userpids | Where-Object {$_.Id -eq $tmpobj.ProcessId}).UserName
                if ($tmpuser) {
                    Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "UserName" -Value ( $userpids | Where-Object {$_.Id -eq $tmpobj.ProcessId}).UserName
                } else {
                    Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "UserName" -Value ""
                }
            }
            if ($GetHashes -or $VirusTotal) {
                if ($Readable) {
                    Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "SHA256" -Value (Get-FileHash $_.ExecutablePath -Algorithm SHA256).Hash.ToLower()
                    Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "MD5" -Value (Get-FileHash $_.ExecutablePath -Algorithm MD5).Hash.ToLower()
                } else {
                    Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "SHA256" -Value "Binary Path Not Accessible"
                    Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "MD5" -Value "Binary Path Not Accessible"
                }
            }
            if ($VirusTotal) {
                Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "VTResourceId" -Value $_.SHA256
                Add-Member -InputObject $tmpobj -MemberType NoteProperty -Name "VTResults" -Value ""
            }
            $tmpobj
        }
        $selected_processes = $all_processes | Invoke-Command -ScriptBlock $SearchFilter | Foreach-Object {
            $Readable = $false
            if ($_.SHA256 -ne "Binary Path Not Accessible") {
                $Readable = $true
            }
            if ($Readable -and ($GetHashes -or $VirusTotal)) {
                if ($virustotal -and $Upload) {
                    foreach ($num in 1..3) {
                        if ($ProxyUseDefaultCredentials -or $ProxyCredential -or $Proxy) {
                            $ProxyObject = New-Object System.Net.WebProxy
                            $ProxyObject.Address = [uri]$Proxy
                            if ($ProxyUseDefaultCredentials) {
                                $ProxyObject.UseDefaultCredentials = $ProxyUseDefaultCredentials
                            }
                            if ($ProxyCredential) {
                                $ProxyObject.Credentials = $ProxyCredential.GetNetworkCredential()
                            }
                            $req.Proxy = $ProxyObject
                        }
                        $req = [System.Net.WebRequest]::Create('http://www.virustotal.com/vtapi/v2/file/scan')
                        $req.Method = 'POST'
                        $req.AllowWriteStreamBuffering = $true
                        $req.SendChunked = $false
                        $req.KeepAlive = $true

                        # Set the proper headers.
                        $headers = New-Object -TypeName System.Net.WebHeaderCollection

                        # Prep the POST Headers for the message
                        $headers.add('apikey',$ApiKey)
                        $boundary = '----------------------------' + [DateTime]::Now.Ticks.ToString('x')
                        $req.ContentType = 'multipart/form-data; boundary=' + $boundary
                        [byte[]]$boundarybytes = [System.Text.Encoding]::ASCII.GetBytes("`r`n--" + $boundary + "`r`n")
                        [string]$formdataTemplate = "`r`n--" + $boundary + "`r`nContent-Disposition: form-data; name=`"{0}`";`r`n`r`n{1}"
                        [string]$formitem = [string]::Format($formdataTemplate, 'apikey', $ApiKey)
                        [byte[]]$formitembytes = [System.Text.Encoding]::UTF8.GetBytes($formitem)
                        [string]$headerTemplate = "Content-Disposition: form-data; name=`"{0}`"; filename=`"{1}`"`r`nContent-Type: application/octet-stream`r`n`r`n"
                        [string]$header = [string]::Format($headerTemplate, 'file', $_.ProcessName)
                        [byte[]]$headerbytes = [System.Text.Encoding]::UTF8.GetBytes($header)
                        [string]$footerTemplate = "Content-Disposition: form-data; name=`"Upload`"`r`n`r`nSubmit Query`r`n" + $boundary + '--'
                        [byte[]]$footerBytes = [System.Text.Encoding]::UTF8.GetBytes($footerTemplate)

                        # Read the file and format the message
                        $stream = $req.GetRequestStream()
                        $rdr = new-object System.IO.FileStream($_.ExecutablePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
                        [byte[]]$buffer = new-object byte[] $rdr.Length
                        [int]$total = [int]$count = 0
                        $stream.Write($formitembytes, 0, $formitembytes.Length)
                        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
                        $stream.Write($headerbytes, 0,$headerbytes.Length)
                        $count = $rdr.Read($buffer, 0, $buffer.Length)
                        do{
                            $stream.Write($buffer, 0, $count)
                            $count = $rdr.Read($buffer, 0, $buffer.Length)
                        }while ($count > 0)
                        $stream.Write($boundarybytes, 0, $boundarybytes.Length)
                        $stream.Write($footerBytes, 0, $footerBytes.Length)
                        $stream.close()

                        Try {
                            # Upload the file
                            $response = $req.GetResponse()

                            # Read the response
                            $respstream = $response.GetResponseStream()
                            $sr = new-object System.IO.StreamReader $respstream
                            $_.VTResourceId = ($sr.ReadToEnd() | ConvertFrom-Json).resource
                            break
                        } Catch [Net.WebException] {
                            if ($Error[0].ToString() -like '*403*') {
                                Throw "API key is not valid! $($Error[0].ToString())"
                                return
                            } elseif ($Error[0].ToString() -like '*204*') {
                                Write-Host "API Request Per Minute Limit Reached. Waiting 60 Seconds... $($Error[0].ToString())"
                                Start-Sleep 60
                            } else {
                                Throw $Error[0].ToString()
                                return
                            }
                        }
                    }
                }
            }
            if ($VirusTotal) {
                foreach ($num in 1..3) {
                    if (-not [System.Convert]::ToBoolean($_.VTResourceId.length)) {
                        $_.VTResourceId = $_.SHA256
                    }
                    $OldEAP = $ErrorActionPreference
                    $ErrorActionPreference = 'SilentlyContinue'
                    $Body =  @{'resource'= $_.VTResourceId; 'apikey'= $ApiKey}
                    $Params =  @{}
                    $Params.add('Body', $Body)
                    $Params.add('Method', 'Get')
                    $Params.add('Uri','https://www.virustotal.com/vtapi/v2/file/report')
                    $Params.Add('ErrorVariable', 'RESTError')
                    if ($ProxyUseDefaultCredentials -or $ProxyCredential -or $Proxy) {
                        $Params.Add('Proxy', $Proxy)
                        if ($ProxyCredential){
                            $Params.Add('ProxyCredential', $ProxyCredential)
                        }
                        if ($ProxyUseDefaultCredentials) {
                            $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
                        }
                    }
                    if ($CertificateThumbprint) {
                        $Params.Add('CertificateThumbprint', $CertificateThumbprint)
                    }
                    $_.VTResults = Invoke-RestMethod @Params
                    $ErrorActionPreference = $OldEAP
                    if ($RESTError) {
                        if ($RESTError.Message.Contains('403')){
                            throw 'API key is not valid.'
                        } elseif ($RESTError.Message -like '*204*') {
                            Write-Host "`nAPI Request Limit Reached OR VirusTotal.`nWaiting 60 Seconds before trying again..."
                            Start-Sleep -Seconds 60
                            continue
                        } else {
                            throw $RESTError
                        }
                    }
                    if ($_.VTResults.response_code -ne 1) {
                        Write-Host "`nAPI Request Limit Reached OR VirusTotal Still Processesing Binary.`nWaiting 60 Seconds before trying again..."
                        Start-Sleep -Seconds 60
                        continue
                    } else {
                        break
                    }
                }
            }
            $_
        }
        foreach ($res in $all_processes) {
            $res.ParentProcess = $all_processes | Where-Object { 
                $_.ProcessId -eq $res.ParentProcessId
            }
        }
        $selected_processes
    }
    $sessionOptions = New-PSSessionOption
    if ($SkipCertChecks) {
        $sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    }
    if ($ComputerName.length -and $Credential.length) {
        $processes = Invoke-Command -UseSSL -SessionOption $sessionOptions -ScriptBlock $AScriptBlock -ComputerName $ComputerName -Credential $Credential -ArgumentList $ApiKey, $SearchFilter, $VirusTotal, $Upload, $GetHashes, $IncludeUserName, $Proxy, $ProxyUser, $ProxyPass, $ProxyUseDefaultCredentials
    } elseif ($ComputerName.length) {
        $processes = Invoke-Command -UseSSL -SessionOption $sessionOptions -ScriptBlock $AScriptBlock -ComputerName $ComputerName -ArgumentList $ApiKey, $SearchFilter, $VirusTotal, $Upload, $GetHashes, $IncludeUserName, $Proxy, $ProxyUser, $ProxyPass, $ProxyUseDefaultCredentials
    } else {
        $processes = Invoke-Command -ScriptBlock $AScriptBlock -ArgumentList $ApiKey, $SearchFilter, $VirusTotal, $Upload, $GetHashes, $IncludeUserName, $Proxy, $ProxyUser, $ProxyPass, $ProxyUseDefaultCredentials
    }
    $processes
}
main