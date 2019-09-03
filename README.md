# Explore-Process
Explore-Process Is like Get-Process For Windows PowerShell Only More PowerFul and With VirusTotal Binary Submission Built-In

Thanks to darkoperator at for some Sample VirusTotal Submission code found [here](https://github.com/darkoperator/Posh-VirusTotal/blob/master/Posh-VirusTotal.psm1)

### Features:

1. Virus total Hash Search / File Upload of process binary
2. More Detailed Process Information
3. View Hidden Processes that `Get-Process` can miss (Elevated Command Prompt Required)
4. Get Process full command line
5. Parent Processes Accessible as members. (can access parent process as attribute and that parents parent etc...)
6. Run On Remote Computers
7. Run through proxy (needs testing)
8. Get MD5 and SHA256 Hashes of process binary Built-In

### Requirements: 

* PowerShell Version 3 or later to run this - havent tested to verify
* Run From Elevated Command Prompt if you want hidden processes as well
* If using the VirusTotal command line option, you will need an API key you can get from [here](https://www.virustotal.com/gui/join-us).

### Limitations: 

VirusTotal's API using Public Keys has a limitation of 4 requests per minute. As a result, unless you have a Private Virus Total API key with a higher limit, using the `-VirusTotal` flag could be slow depending on how specific a `-SearchFilter` you supply. If the script detects the request limit has been reached, it will attempt to wait 60 seconds before making more requests. As such, it's a good idea to be very specific with your `-SearchFilter` to limit the Virus Total Submissions to a couple processes or less.

If you have a Private Virus Total API key with a much higher limit, or you dont care about waiting longer, than ignore the above limitation.

### Todo:

1. Test Proxy Functionality
2. Want to create script checker that inteligently retrieves and uploads any scriptable code or script file in `CommandLine` to virustotal as well.
3. Need to switch Boolean command line switches to switches instead of True / False
4. Want to add a powershell deobfuscator option for any powershell malware. 
5. Cleanup and restructure the code. Right now it's just in a working state.

### Usage:

**Basic Example - Gets details of the tenth Process in the results. If Run from Elevated Prompt, also get's hidden processes.**

``` powershell
PS C:\> (.\Explore-Process.ps1)[10]

Name                           Value
----                           -----
SessionId                      0
CommandLine                    C:\Windows\system32\svchost.exe -k DcomLaunch -p
ProcessId                      640
CreationDateTimeStamp          20190822150231.560079-240
Handle                         640
ParentProcessId                1004
ProcessName                    svchost.exe
CreationDate                   8/22/2019 3:02:31 PM
Path                           C:\Windows\system32\svchost.exe
ExecutablePath                 C:\Windows\system32\svchost.exe
Id                             640
PSComputerName                 IMALITTLETEAPOT
CSName                         IMALITTLETEAPOT
```

**Advanced Example - Grabs the `RawCap.exe` Process and Includes the Process Owner's username**

``` powershell
PS C:\> .\Explore-Process.ps1 -SearchFilter {Where-Object {$_.ProcessName -eq "rawcap.exe"}} -IncludeUserName True

Name                           Value
----                           -----
SessionId                      1
CommandLine                    "C:\Users\rickybobby\Desktop\Admin_Tools\RawCap.exe"
ProcessId                      1300304
CreationDateTimeStamp          20190830172356.991682-240
UserName                       IMALITTLETEAPOT\rickybobby
Handle                         1300304
ParentProcessId                1288124
ProcessName                    RawCap.exe
CreationDate                   8/30/2019 5:23:56 PM
Path                           C:\Users\rickybobby\Desktop\Admin_Tools\RawCap.exe
ExecutablePath                 C:\Users\rickybobby\Desktop\Admin_Tools\RawCap.exe
Id                             1300304
PSComputerName                 IMALITTLETEAPOT
CSName                         IMALITTLETEAPOT
```

**Full Example - Includes Submitting To VirusTotal:**

Apply A search filter, include username, hash binaries and upload to virustotal for results, supplies a Virus Total API Key and stores it as a securestring

``` powershell
PS C:\> $process = .\Explore-Process.ps1 -IncludeUserName True -SearchFilter {Where-Object {$_.ProcessName -eq 'rawcap.exe'}} -VirusTotal True -GetHashes True -Upload True -ApiKey "1234567891011121314151617181920212223242526272829303132333435363" -StoreApiKey True
PS C:\> $process.VTResults      # Not an array if only one result returned. Use $process[2].VTResults etc... otherwise

scans         : @{Bkav=; MicroWorld-eScan=; FireEye=; CAT-QuickHeal=; ALYac=; Malwarebytes=; Zillya=; SUPERAntiSpyware=; K7AntiVirus=; Alibaba=;
                K7GW=; Cybereason=; Arcabit=; Invincea=; Baidu=; F-Prot=; Symantec=; TotalDefense=; APEX=; Avast=; ClamAV=; Kaspersky=;
                BitDefender=; NANO-Antivirus=; Paloalto=; AegisLab=; Rising=; Ad-Aware=; Sophos=; Comodo=; F-Secure=; DrWeb=; VIPRE=; TrendMicro=;
                McAfee-GW-Edition=; Trapmine=; CMC=; Emsisoft=; SentinelOne=; Cyren=; Jiangmin=; eGambit=; Avira=; Fortinet=; Kingsoft=; Endgame=;
                Microsoft=; ViRobot=; ZoneAlarm=; Avast-Mobile=; TACHYON=; AhnLab-V3=; Acronis=; McAfee=; MAX=; VBA32=; Cylance=; Zoner=;
                ESET-NOD32=; TrendMicro-HouseCall=; Tencent=; Yandex=; Ikarus=; MaxSecure=; GData=; Webroot=; AVG=; Panda=; CrowdStrike=;
                Qihoo-360=}
scan_id       : f6917fa47ce498af0dd840e1467c29c1701dde0a850009ae7523f554b12ad379-1567444350
sha1          : c427933591274c97ad00516ab91454c9ea71c5eb
resource      : f6917fa47ce498af0dd840e1467c29c1701dde0a850009ae7523f554b12ad379
response_code : 1
scan_date     : 2019-09-02 17:12:30
permalink     : https://www.virustotal.com/file/f6917fa47ce498af0dd840e1467c29c1701dde0a850009ae7523f554b12ad379/analysis/1567444350/
verbose_msg   : Scan finished, information embedded
total         : 70
positives     : 0
sha256        : f6917fa47ce498af0dd840e1467c29c1701dde0a850009ae7523f554b12ad379
md5           : 0d7a08e7f58bfe020c59d739911ee519
```

**Getting Help:**

`Get-Help .\Explore-Process.ps1 -Detailed`

```
NAME
    .\Explore-Process.ps1

SYNOPSIS
    .\Explore-Process performs advanced searching and information gathering or processes running.


SYNTAX
    .\Explore-Process.ps1 [<CommonParameters>]

    Explore-Process.ps1 [-ApiKey <String>] [-SearchFilter <ScriptBlock>] [-StoreApiKey <True or False>]
    [-ComputerName <String>] [-Credential <PSCredential>] [-VirusTotal <True or False>] [-Upload <True or False>] [-GetHashes <True or False>] [-IncludeUserName
    <True or False>] [-Proxy <String>] [-ProxyCredential <PSCredential>] [-ProxyUseDefaultCredentials] [<CommonParameters>]


DESCRIPTION
    Explore-Process performs advanced searching and information gathering or processes running.
    For example, it can read hidden processes that Get-Process cannot and it can retrieve usernames of processes.
    Additionally, it can also retrieve virus total results for process binaries.


PARAMETERS
    -ApiKey <String>
        Virus Total API Key Is a 64 Character Hex String.

    -SearchFilter <ScriptBlock>
        A Where Script Block To Filter Process Objects. Example:`n { Where-Object {`_.ProcessName -eq 'svchost'} }`n

    -StoreApiKey <True or False>
        -StoreApiKey True
        Stores VirusTotal API Key As Secure String so you dont have to keep specifying this from the command line.

    -ComputerName <String>
        Remote Computer To Get Processes From

    -Credential <PSCredential>
        Manually Specify Credentials For Remote Host

    -VirusTotal <True or False>
        -VirusTotal True
        Search VirusTotal For Process Binary. Default is False. BE CAREFUL: Due to the Virus Total API limit of 4 requests Per minute, be sure to
        apply a very specific -SearchFilter to reduce the number of binaries processed. Unless of course your -ApiKey Specified has a higher limit.

    -Upload <True or False>
        -Upload True
        If -Upload False then hash will be searched instead.

    -GetHashes <True or False>
        -GetHashes True
        To Get Process Excutable File Hashes.

    -IncludeUserName <True or False>
        Include Process Username

    -Proxy <String>
        Set the proxy information here

    -ProxyCredential <PSCredential>
        Proxy Credential Information Here

    -ProxyUseDefaultCredentials [<SwitchParameter>]
        Use default proxy credentials

    -SkipCertChecks <True or False>
        Skip All Certificate Checks When using SSL to connect to remote computer
```

**Note:** You can also specify multiple conditions in `-SearchFilter`. For example - `.\Explore-Process -SearchFilter {Where-Object {$_.ProcessName -eq "rawcap.exe" -or $_.ParentProcessId -eq 1234}}`

**WARNING:** `-SearchFilter` evaluates any scriptblock you provide it. This is intended to use the `Where-Object` powershell commandlet but will technically execute any scriptblock. So don't pass any scriptblock to this argument unless you created it or fully understand it.

**SearchFilter-able Process Attributes:** Here Are A List Of Attribute Properties that can be specified in `-SearchFilter {Where-Object {$_.ProcessName -eq "rawcap.exe"}}`  in place of `ProcessName` to filter out your desired processes:

``` powershell
   TypeName: System.Management.ManagementObject

Name                       MemberType     Definition
----                       ----------     ----------
Handles                    AliasProperty  Handles = Handlecount
ProcessName                AliasProperty  ProcessName = Name
PSComputerName             AliasProperty  PSComputerName = __SERVER
VM                         AliasProperty  VM = VirtualSize
WS                         AliasProperty  WS = WorkingSetSize
AttachDebugger             Method         System.Management.ManagementBaseObject AttachDebugger()
GetAvailableVirtualSize    Method         System.Management.ManagementBaseObject GetAvailableVirtualSize()
GetOwner                   Method         System.Management.ManagementBaseObject GetOwner()
GetOwnerSid                Method         System.Management.ManagementBaseObject GetOwnerSid()
SetPriority                Method         System.Management.ManagementBaseObject SetPriority(System.Int32 Priority)
Terminate                  Method         System.Management.ManagementBaseObject Terminate(System.UInt32 Reason)
Caption                    Property       string Caption {get;set;}
CommandLine                Property       string CommandLine {get;set;}
CreationClassName          Property       string CreationClassName {get;set;}
CreationDate               Property       string CreationDate {get;set;}
CSCreationClassName        Property       string CSCreationClassName {get;set;}
CSName                     Property       string CSName {get;set;}
Description                Property       string Description {get;set;}
ExecutablePath             Property       string ExecutablePath {get;set;}
ExecutionState             Property       uint16 ExecutionState {get;set;}
Handle                     Property       string Handle {get;set;}
HandleCount                Property       uint32 HandleCount {get;set;}
InstallDate                Property       string InstallDate {get;set;}
KernelModeTime             Property       uint64 KernelModeTime {get;set;}
MaximumWorkingSetSize      Property       uint32 MaximumWorkingSetSize {get;set;}
MinimumWorkingSetSize      Property       uint32 MinimumWorkingSetSize {get;set;}
Name                       Property       string Name {get;set;}
OSCreationClassName        Property       string OSCreationClassName {get;set;}
OSName                     Property       string OSName {get;set;}
OtherOperationCount        Property       uint64 OtherOperationCount {get;set;}
OtherTransferCount         Property       uint64 OtherTransferCount {get;set;}
PageFaults                 Property       uint32 PageFaults {get;set;}
PageFileUsage              Property       uint32 PageFileUsage {get;set;}
ParentProcessId            Property       uint32 ParentProcessId {get;set;}
PeakPageFileUsage          Property       uint32 PeakPageFileUsage {get;set;}
PeakVirtualSize            Property       uint64 PeakVirtualSize {get;set;}
PeakWorkingSetSize         Property       uint32 PeakWorkingSetSize {get;set;}
Priority                   Property       uint32 Priority {get;set;}
PrivatePageCount           Property       uint64 PrivatePageCount {get;set;}
ProcessId                  Property       uint32 ProcessId {get;set;}
QuotaNonPagedPoolUsage     Property       uint32 QuotaNonPagedPoolUsage {get;set;}
QuotaPagedPoolUsage        Property       uint32 QuotaPagedPoolUsage {get;set;}
QuotaPeakNonPagedPoolUsage Property       uint32 QuotaPeakNonPagedPoolUsage {get;set;}
QuotaPeakPagedPoolUsage    Property       uint32 QuotaPeakPagedPoolUsage {get;set;}
ReadOperationCount         Property       uint64 ReadOperationCount {get;set;}
ReadTransferCount          Property       uint64 ReadTransferCount {get;set;}
SessionId                  Property       uint32 SessionId {get;set;}
Status                     Property       string Status {get;set;}
TerminationDate            Property       string TerminationDate {get;set;}
ThreadCount                Property       uint32 ThreadCount {get;set;}
UserModeTime               Property       uint64 UserModeTime {get;set;}
VirtualSize                Property       uint64 VirtualSize {get;set;}
WindowsVersion             Property       string WindowsVersion {get;set;}
WorkingSetSize             Property       uint64 WorkingSetSize {get;set;}
WriteOperationCount        Property       uint64 WriteOperationCount {get;set;}
WriteTransferCount         Property       uint64 WriteTransferCount {get;set;}
__CLASS                    Property       string __CLASS {get;set;}
__DERIVATION               Property       string[] __DERIVATION {get;set;}
__DYNASTY                  Property       string __DYNASTY {get;set;}
__GENUS                    Property       int __GENUS {get;set;}
__NAMESPACE                Property       string __NAMESPACE {get;set;}
__PATH                     Property       string __PATH {get;set;}
__PROPERTY_COUNT           Property       int __PROPERTY_COUNT {get;set;}
__RELPATH                  Property       string __RELPATH {get;set;}
__SERVER                   Property       string __SERVER {get;set;}
__SUPERCLASS               Property       string __SUPERCLASS {get;set;}
ConvertFromDateTime        ScriptMethod   System.Object ConvertFromDateTime();
ConvertToDateTime          ScriptMethod   System.Object ConvertToDateTime();
Path                       ScriptProperty System.Object Path {get=$this.ExecutablePath;}
```

### Follow Up Parent Processes Tree

A useful feature of this is that each process object contains a member called `.ParentProcess` pointing to it's parent and that parent's parent and that parent's parent etc... This can be accessed all the way up the chain. For example:

``` powershell
PS C:\> $res = .\Explore-Process.ps1 -SearchFilter {Where-Object {$_.ProcessName -eq 'powershell.exe'}}
PS C:\> $res.ParentProcess

ProcessName           : RuntimeBroker.exe
CommandLine           : C:\Windows\System32\RuntimeBroker.exe -Embedding
PSComputerName        : IMALITTLETEAPOT
CreationDate          : 9/2/2019 1:57:51 PM
CreationDateTimeStamp : 20190902135751.119879-240
CSName                : IMALITTLETEAPOT
ExecutablePath        : C:\Windows\System32\RuntimeBroker.exe
Handle                : 13916
Id                    : 13916
ProcessId             : 13916
SessionId             : 1
ParentProcessId       : 148
ParentProcess         : @{ProcessName=svchost.exe; CommandLine=C:\Windows\system32\svchost.exe -k DcomLaunch -p; PSComputerName=IMALITTLETEAPOT;
                        CreationDate=9/2/2019 1:57:39 PM; CreationDateTimeStamp=20190902135739.264556-240; CSName=IMALITTLETEAPOT;
                        ExecutablePath=C:\Windows\system32\svchost.exe; Handle=148; Id=148; ProcessId=148; SessionId=0; ParentProcessId=1004;
Path                  : C:\Windows\System32\RuntimeBroker.exe

PS C:\> $res.ParentProcess.ParentProcess

ProcessName           : svchost.exe
CommandLine           : C:\Windows\system32\svchost.exe -k DcomLaunch -p
PSComputerName        : IMALITTLETEAPOT
CreationDate          : 9/2/2019 1:57:39 PM
CreationDateTimeStamp : 20190902135739.264556-240
CSName                : IMALITTLETEAPOT
ExecutablePath        : C:\Windows\system32\svchost.exe
Handle                : 148
Id                    : 148
ProcessId             : 148
SessionId             : 0
ParentProcessId       : 1004
                        CreationDateTimeStamp=20190902135739.044867-240; CSName=IMALITTLETEAPOT; ExecutablePath=; Handle=1004; Id=1004;
                        ProcessId=1004; SessionId=0; ParentProcessId=932; ParentProcess=; Path=}
Path                  : C:\Windows\system32\svchost.exe

PS C:\> $res.ParentProcess.ParentProcess.ParentProcess

ProcessName           : services.exe
CommandLine           :
PSComputerName        : IMALITTLETEAPOT
CreationDate          : 9/2/2019 1:57:39 PM
CreationDateTimeStamp : 20190902135739.044867-240
CSName                : IMALITTLETEAPOT
ExecutablePath        :
Handle                : 1004
Id                    : 1004
ProcessId             : 1004
SessionId             : 0
ParentProcessId       : 932
ParentProcess         : @{ProcessName=wininit.exe; CommandLine=; PSComputerName=IMALITTLETEAPOT; CreationDate=9/2/2019 1:57:38 PM;
                        CreationDateTimeStamp=20190902135738.970280-240; CSName=IMALITTLETEAPOT; ExecutablePath=; Handle=932; Id=932; ProcessId=932;
                        SessionId=0; ParentProcessId=792; ParentProcess=; Path=}
Path                  :
```


### Sample Virus total Output

`$res = .\Explore-Process.ps1 -SearchFilter {Where-Object {$_.ProcessName -eq 'powershell.exe'}} -VirusTotal True`

``` powershell
PS C:\> $res

ProcessName           : powershell.exe
CommandLine           : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PSComputerName        : IMALITTLETEAPOT
CreationDate          : 9/2/2019 4:06:43 PM
CreationDateTimeStamp : 20190902160643.087411-240
CSName                : IMALITTLETEAPOT
ExecutablePath        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Handle                : 29044
Id                    : 29044
ProcessId             : 29044
SessionId             : 1
ParentProcessId       : 13916
ParentProcess         : @{ProcessName=RuntimeBroker.exe; CommandLine=C:\Windows\System32\RuntimeBroker.exe -Embedding; PSComputerName=IMALITTLETEAPOT;
                        CreationDate=9/2/2019 1:57:51 PM; CreationDateTimeStamp=20190902135751.119879-240; CSName=IMALITTLETEAPOT;
                        ExecutablePath=C:\Windows\System32\RuntimeBroker.exe; Handle=13916; Id=13916; ProcessId=13916; SessionId=1;
                        ParentProcessId=148; ParentProcess=; Path=C:\Windows\System32\RuntimeBroker.exe;
                        SHA256=3f82d416fbee431b0ae798078f9c354711577f48b38901788c784a5ec0dd13b3; MD5=2879bf3f6f6ce63477135f7c061b14f3; VTResourceId=;
                        VTResults=}
Path                  : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SHA256                : de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c
MD5                   : 7353f60b1739074eb17c5f4dddefe239
VTResourceId          : de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c
VTResults             : @{scans=; scan_id=de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c-1567067444;
                        sha1=6cbce4a295c163791b60fc23d285e6d84f28ee4c; resource=de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c;
                        response_code=1; scan_date=2019-08-29 08:30:44; permalink=https://www.virustotal.com/file/de96a6e69944335375dc1ac238336066889d9
                        ffc7d73628ef4fe1b1b160ab32c/analysis/1567067444/; verbose_msg=Scan finished, information embedded; total=66; positives=0;
                        sha256=de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c; md5=7353f60b1739074eb17c5f4dddefe239}

PS C:\> $res.VTResults

scans         : @{Bkav=; MicroWorld-eScan=; CMC=; CAT-QuickHeal=; McAfee=; Cylance=; SUPERAntiSpyware=; K7AntiVirus=; BitDefender=; K7GW=;
                CrowdStrike=; Arcabit=; Invincea=; Baidu=; F-Prot=; ESET-NOD32=; APEX=; Paloalto=; ClamAV=; Kaspersky=; Alibaba=; NANO-Antivirus=;
                ViRobot=; Avast=; Tencent=; Endgame=; Sophos=; Comodo=; F-Secure=; DrWeb=; Zillya=; TrendMicro=; McAfee-GW-Edition=; Trapmine=;
                FireEye=; Emsisoft=; SentinelOne=; Cyren=; Jiangmin=; Webroot=; Avira=; Antiy-AVL=; Kingsoft=; Microsoft=; AegisLab=; ZoneAlarm=;
                Avast-Mobile=; GData=; TACHYON=; AhnLab-V3=; Acronis=; VBA32=; ALYac=; MAX=; Ad-Aware=; Malwarebytes=; Zoner=; TrendMicro-HouseCall=;
                Rising=; Yandex=; Ikarus=; eGambit=; Fortinet=; AVG=; Panda=; Qihoo-360=}
scan_id       : de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c-1567067444
sha1          : 6cbce4a295c163791b60fc23d285e6d84f28ee4c
resource      : de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c
response_code : 1
scan_date     : 2019-08-29 08:30:44
permalink     : https://www.virustotal.com/file/de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c/analysis/1567067444/
verbose_msg   : Scan finished, information embedded
total         : 66
positives     : 0
sha256        : de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c
md5           : 7353f60b1739074eb17c5f4dddefe239
```

### Pretty-Printing Results in JSON format:

`PS C:\Users\rickybobby\Desktop> .\Explore-Process.ps1 -ComputerName DC03 -SkipCertChecks True -SearchFilter {Where-Object {$_.ProcessName -eq 'powershell.exe'}} -VirusTotal True  -ApiKey "1234567891011121314151617181920212223242526272829303132333435363" | ConvertTo-Json -Depth 10`

``` json
{
    "ProcessName":  "powershell.exe",
    "CommandLine":  "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ",
    "CreationDate":  "\/Date(1566855960142)\/",
    "CreationDateTimeStamp":  "20190826174600.142320-420",
    "CSName":  "DC03",
    "ExecutablePath":  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "Handle":  "4024",
    "Id":  "4024",
    "ProcessId":  4024,
    "SessionId":  1,
    "ParentProcessId":  2988,
    "ParentProcess":  {
                          "ProcessName":  "explorer.exe",
                          "CommandLine":  "C:\\Windows\\Explorer.EXE",
                          "PSComputerName":  "DC03",
                          "CreationDate":  "\/Date(1566855942261)\/",
                          "CreationDateTimeStamp":  "20190826174542.261197-420",
                          "CSName":  "DC03",
                          "ExecutablePath":  "C:\\Windows\\Explorer.EXE",
                          "Handle":  "2988",
                          "Id":  "2988",
                          "ProcessId":  2988,
                          "SessionId":  1,
                          "ParentProcessId":  4676,
                          "ParentProcess":  null,
                          "Path":  "C:\\Windows\\Explorer.EXE",
                          "SHA256":  "06d93419b7721f7dfe69af7fdb3bd6b2b46fa2aeb870a96ad86fd5ca8771b585",
                          "MD5":  "57fb57fc919229a8cf294ed8670c2d51",
                          "VTResourceId":  null,
                          "VTResults":  ""
                      },
    "Path":  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "SHA256":  "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
    "MD5":  "097ce5761c89434367598b34fe32893b",
    "VTResourceId":  "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
    "VTResults":  {
                      "scans":  {
                                    "Bkav":  {
                                                 "detected":  false,
                                                 "version":  "1.3.0.10239",
                                                 "result":  null,
                                                 "update":  "20190822"
                                             },
                        < --------------- REDACTED VIRUS SCAN RESULTS --------------- >
                                    "Qihoo-360":  {
                                                      "detected":  false,
                                                      "version":  "1.0.0.1120",
                                                      "result":  null,
                                                      "update":  "20190822"
                                                  }
                                },
                      "scan_id":  "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436-1566492551",
                      "sha1":  "044a0cf1f6bc478a7172bf207eef1e201a18ba02",
                      "resource":  "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
                      "response_code":  1,
                      "scan_date":  "2019-08-22 16:49:11",
                      "permalink":  "https://www.virustotal.com/file/ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436/analysis/1566492551/",
                      "verbose_msg":  "Scan finished, information embedded",
                      "total":  68,
                      "positives":  0,
                      "sha256":  "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
                      "md5":  "097ce5761c89434367598b34fe32893b"
                  },
    "PSComputerName":  "DC03",
    "RunspaceId":  "54973742-8833-441f-abb9-22a8cf49837f",
    "PSShowComputerName":  true
}
```