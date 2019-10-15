#requires -RunAsAdministrator
#requires -modules Posh-SYSLOG
#requires -Version 5.0 

<#
.SYNOPSIS
This script is designed to query the Zerto ZVM Alerts API to pull the relevant alerts and send those alerts to a Syslog server of the users choosing. 
.DESCRIPTION
Leveraging the Zerto Rest API the script with authenticate with the ZVM to pull the alerts from the relevant site. Once the alerts are collected the script will send the alerts to a Syslog server
that the user has configured in the script variables below. At the end of the script the API session will be closed, as the script is intended to be run as a Task or via orchestration every few minutes.

To run this script the computer executing the script must have the Posh-Syslog module installed before running the script. For more information 
please review the module in the PowerShell Gallery (https://www.powershellgallery.com/packages/Posh-SYSLOG/3.3). 

It is important to note which protocol (TCP / UDP) and what default port the Syslog application listens on. By default Syslog protocol uses UDP and port 514, but some Syslog Server
applications do not share these same defaults.

.EXAMPLE
Examples of script execution
.VERSION
Applicable versions of Zerto Products script has been tested on. Unless specified, all scripts in repository will be 6.0u3 and later. If you have tested the script on multiple
versions of the Zerto product, specify them here. If this script is for a specific version or previous version of a Zerto product, note that here and specify that version
in the script filename. If possible, note the changes required for that specific version.
.LEGAL
Legal Disclaimer:
 
----------------------
This script is an example script and is not supported under any Zerto support program or service.
The author and Zerto further disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
 
In no event shall Zerto, its authors or anyone else involved in the creation, production or delivery of the scripts be liable for any damages whatsoever (including, without
limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or the inability
to use the sample scripts or documentation, even if the author or Zerto has been advised of the possibility of such damages. The entire risk arising out of the use or
performance of the sample scripts and documentation remains with you.
----------------------
#>

################ Variables for your script ######################

$strZVMIP = "Enter ZVM IP"
$strZVMPort = "9669"
$strZVMUser = "Enter ZVM User"
$strZVMPwd = "EnterZVMPassword"
$bookMarkFile = "Enter bookmark location for file to save"
$SyslogServer = "EnterSyslogIP"
$SyslogProtocol = "Enter UDP, TCP, or TCPwithTLS "
$SyslogPort = "Enter SyslogPort"
$LogDataDir = "Enter folder location for transcript data to save"
$SyslogFacility = "syslog"

########################################################################################################################
# Nothing to configure below this line - Starting the main function of the script
########################################################################################################################

Write-Host -ForegroundColor Yellow "Informational line denoting start of script GOES HERE." 
Write-Host -ForegroundColor Yellow "   Legal Disclaimer:

----------------------
This script is an example script and is not supported under any Zerto support program or service.
The author and Zerto further disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.

In no event shall Zerto, its authors or anyone else involved in the creation, production or delivery of the scripts be liable for any damages whatsoever (including, without 
limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or the inability 
to use the sample scripts or documentation, even if the author or Zerto has been advised of the possibility of such damages.  The entire risk arising out of the use or 
performance of the sample scripts and documentation remains with you.
----------------------
"
#------------------------------------------------------------------------------#
#Setting log directory and starting transcript logging
#------------------------------------------------------------------------------#
$CurrentMonth = get-date -Format MM.yy
$CurrentTime = get-date -format hh.mm.ss
$CurrentLogDataDir = $LogDataDir + $CurrentMonth
$CurrentLogDataFile = $LogDataDir + $CurrentMonth + "\SysLogMessageLog-" + $CurrentTime + ".txt"
#Testing path exists, if not creating it
$ExportDataDirTestPath = test-path $CurrentLogDataDir
If($ExportDataDirTestPath -eq $False)
{
New-item -ItemType Directory -Force -Path $CurrentLogDataDir
}
start-transcript -path $CurrentLogDataFile -NoClobber

############### ignore self signed SSL ##########################
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()
#################################################################

#--------------------------------------------------------------------------------------------------#
# Perform authentication to ZVM to allow Zerto APIst to run, capture session ID for future requests
#--------------------------------------------------------------------------------------------------#

function getxZertoSession ($userName, $password){
    $baseURL = "https://" + $strZVMIP + ":" + $strZVMPort
    $xZertoSessionURL = $baseURL +"/v1/session/add"
    $authInfo = ("{0}:{1}" -f $userName,$password)
    $authInfo = [System.Text.Encoding]::UTF8.GetBytes($authInfo)
    $authInfo = [System.Convert]::ToBase64String($authInfo)
    $headers = @{Authorization=("Basic {0}" -f $authInfo)}
    $contentType = "application/json"
    $xZertoSessionResponse = Invoke-WebRequest -Uri $xZertoSessionURL -Headers $headers -Method POST -ContentType $contentType

    return $xZertoSessionResponse.headers.get_item("x-zerto-session")
}

#------------------------------------------------------------------------------#
#Extract x-zerto-session from the response, and add it to the API: 
#------------------------------------------------------------------------------#
$xZertoSession = getxZertoSession $strZVMUser $strZVMPwd
$zertoSessionHeader = @{"x-zerto-session"=$xZertoSession}
$zertoSessionHeader_json = @{"Accept"="application/json"
"x-zerto-session"=$xZertoSession}


#------------------------------------------------------------------------------#
# Configuring Bookmark file for timestamp 
#------------------------------------------------------------------------------#
If(Test-Path $bookMarkFile){
    
    #If bookmark exists, add 1 millisecond to timestamp for next alert query
    [DateTime]$currentBookmark = $(get-content -raw -path $bookMarkFile | convertfrom-json).value
    $startTime = $currentBookmark.AddMilliseconds(1).toString('yyyy-MM-ddTHH:mm:ss.fff')
      
}
Else{
    
    #If bookmark does not exist, use ZVR install date as alert query start time
    $startTime = $(Get-ChildItem -Directory 'C:\Program Files' | Where-Object {$_.Name -like "Zerto"} | Select-object CreationTime).CreationTime.ToString('yyyy-MM-ddTHH:mm:ss.fff') 

}

#------------------------------------------------------------------------------#
# Build PeersList API URL
#------------------------------------------------------------------------------#
$peerListApiUrl = "https://" + $strZVMIP + ":"+$strZVMPort+"/v1/alerts?startDate="+$startTime

#------------------------------------------------------------------------------#
# Iterate with JSON:
#------------------------------------------------------------------------------#
 $alertListJSON = Invoke-RestMethod -Uri $peerListApiUrl -Headers $zertoSessionHeader

If ($alertListJSON){
    $latestAlert = $alertListJSON[0].TurnedOn

    #Order alerts from oldest to newest
    $alertListJSON | sort-object {$_.TurnedOn}
    
    foreach ($alert in $alertListJSON){
        if($latestAlert -lt $alert.TurnedOn){
            $latestAlert = $alert.TurnedOn

        }

    # Build Info Syslog severity for license and upgrade alerts    
        switch -Regex ($alert.HelpIdentifier)
            {  
                "LIC000[1-8]" {$alertLevel = 'info'; Break}
                "ZVM0006"     {$alertLevel = 'info'; Break}
                default       {$alertLevel = $alert.Level}
            }
              
    # Remove HTML tag from License alert description    
    if($alert.HelpIdentifier -like "LIC*"){
        $alertInfo = $alertInfo.Replace("<a href='mailto:salesteam@zerto.com'>","").Replace("</a>","")
    }
    else {
        $alertInfo = $alert.Description
    }

    $TimeStamp = $alert.TurnedOn 
    $MessageID = $alert.HelpIdentifier
    # Send alert to Syslog server 
    Send-SyslogMessage -Server $SyslogServer -Message $alertInfo -TimeStamp $Timestamp -Severity $alertLevel -MessageID $MessageID -Port $SyslogPort -Transport $SyslogProtocol -Facility $SyslogFacility -ProcessID '-' -ApplicationName "Zerto Virtual Replication"      
                   
    }
    $latestAlert | ConvertTo-Json | Set-Content -path $bookMarkFile
}

#------------------------------------------------------------------------------#
# Ending API Session
#------------------------------------------------------------------------------#
$deleteApiSessionURL = "https://" + $strZVMIP + ":"+$strZVMPort+"/v1/session"
Invoke-WebRequest -Uri $deleteApiSessionURL -Headers $zertoSessionHeader -Method Delete -ContentType $contentType

Exit
##End of script
