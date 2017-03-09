<#
.SYNOPSIS
Written by JBear

.DESCRIPTION
Before use -- set the following values to your own environment information:
Line 59, 65, 71, 77, 85

This script/function is designed to retrieve all windows services being run by any service accounts (not including standard defaults - see lines 142-148 to adjust). This is to assist SysAdmins in finding all service accounts currently in operation during password change timeframes.
All switches ( currently -S -K -W -H ) may be linked to their respective OU.

When server or workstation hostnames are supplied to the pipeline, the search will only apply to those values (multiple values supported in pipeline; must separate by comma).
When switches are applied, the search will only apply to those specifically.
If no switches are applied, the search will DEFAULT to the parent OU (Line 85).

.EXAMPLE
.\Get-NonStandardSeviceAccounts.ps1 -S -K -ConvertToHTML

.EXAMPLE
.\Get-NonStandardSeviceAccounts.ps1

.EXAMPLE
.\Get-NonStandardSeviceAccounts.ps1 SuperSecretServer01.acme.com

.EXAMPLE
.\Get-NonStandardSeviceAccounts.ps1 192.168.93.12

.EXAMPLE
.\Get-NonStandardSeviceAccounts.ps1 SuperSecretServer01, NotSoSecretServer01.acme.com, 192.168.93.12
#>

Param(
[parameter(ValueFromPipeline=$true)]
    [String[]]$Names,
    [Switch]$S,
    [Switch]$K,
    [Switch]$W,
    [Switch]$H,
    [Switch]$ConvertToHTML
)

Try {

    Import-Module ActiveDirectory -ErrorAction Stop
}

Catch {

    Write-Host -ForegroundColor Yellow "`nUnable to load Active Directory Module; it is required to run this script. Please, install RSAT and configure this server properly."
    Break
}

#Format today's date
$LogDate = (Get-Date -format yyyyMMdd)

#S server OU switch
if($S) {

    $SearchOU += "OU=S,OU=Computers,DC=acme,DC=com"
}

#K server OU switch
if($K) {

    $SearchOU += "OU=K,OU=Computers,DC=acme,DC=com"
}

#W server OU switch
if($W) {

    $SearchOU += "OU=W,OU=Computers,DC=acme,DC=com" 
}

#H server OU switch
if($H) {

    $SearchOU += "OU=H,OU=Computers,DC=acme,DC=com"
}

#If no OU switches are present, use parent 05_Servers OU for array
if(!($S.IsPresent -or $K.IsPresent -or $W.IsPresent -or $H.IsPresent)){
    
    if([string]::IsNullOrWhiteSpace($Names)) { 
        #Set $SearchOU to parent server OU
        $SearchOU = "OU=Computers,DC=acme,DC=coms"
    }
}

Write-Host "`nRetrieving server information from:"

if([String]::IsNullOrWhiteSpace($Names)) {
    
    #Process each item in $SearchOU
    foreach($OU in $SearchOU) {

        Write-Progress -Activity "Retrieving information from selected servers..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $SearchOU.count) * 100) + "%") -CurrentOperation "Processing $($OU)..." -PercentComplete ((($j++) / $SearchOU.count) * 100)
    
        #OU can't be $null or whitespace
        if(!([string]::IsNullOrWhiteSpace($OU))) {
    
            #Retrieve all server names from $OU
            $Names = (Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter *).Name

            #Add server names to $ComputerList Array
            $ComputerList += $Names
        }
    }
}

else {

    $ComputerList += $Names
}

foreach ($C in $ComputerList) {

    Write-Host "$C"
}

$i=0
$j=0

#Create function
function Get-Accounts {

    #Process each item in $ComputerList
    foreach ($Computer in $ComputerList) {
        
        #Progress bar/completion percentage of all items in $ComputerList
        Write-Progress -Activity "Creating job for $Computer to query Local Services..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $ComputerList.count) * 100) + "%") -CurrentOperation "Processing $($Computer)..." -PercentComplete ((($j++) / $ComputerList.count) * 100)

        #Only continue if able to ping
        if(Test-Connection -Quiet -Count 1 $Computer) {

            #Creat job to run parallel
            Start-Job -ScriptBlock { param($Computer)

                <# Query each computer
                Note: Get-CIMInstance -ComputerName $Computer -ClassName Win32_Service -ErrorAction SilentlyContinue 
                won't currently work with some out of date servers #>
                $WMI = (Get-WmiObject -ComputerName $Computer -Class Win32_Service -ErrorAction SilentlyContinue | 

                #Filter out the standard service accounts
                Where-Object -FilterScript {$_.StartName -ne "LocalSystem"}                  |
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\NetworkService"}  | 
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\LocalService"}    |
                Where-Object -FilterScript {$_.StartName -ne "Local System"}                 |
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\Local Service"}   |
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\Network Service"} |
                Where-Object -FilterScript {$_.StartName -ne "NT AUTHORITY\system"})
                
                if($WMI.count -eq 0) {
                
                    [pscustomobject] @{

                        StartName    = "No Service Accounts Found "
                        Name         = "N/A"
                        DisplayName  = "N/A"
                        StartMode    = "N/A"
                        SystemName   = $Computer
                    }  
                }

                else {

                    foreach($Obj in $WMI) {
                        
                        [pscustomobject] @{

                            StartName    = $Obj.StartName
                            Name         = $Obj.Name
                            DisplayName  = $Obj.DisplayName
                            StartMode    = $Obj.StartMode
                            SystemName   = $Obj.SystemName
                        }
                    }
                }
            } -ArgumentList $Computer
        }

        else {
        
            Start-Job -ScriptBlock { param($Computer)

                [pscustomobject] @{

                    StartName    = "Unable to Ping"
                    Name         = "N/A"
                    DisplayName  = "N/A"
                    StartMode    = "N/A"
                    SystemName   = $Computer
                }
            } -ArgumentList $Computer
        }
    }

#Output for alerting last job created
Write-Host "`nAll jobs have been created on reachable machines... Please wait..."
}

#Convert to HTML output switch
switch($ConvertToHTML.IsPresent) {
    
    #If -ConvertToHTML is present
    $true {
    
        #Set location for the report to executing users' My Documents folder
        $Report = [environment]::getfolderpath("mydocuments") + "\Service_Account-Audit_Report-" + $logdate + ".html"

        #Set HTML formatting
        $HTML =
@"
<title>Non-Standard Service Accounts</title>
<style>
BODY{background-color :#FFFFF}
TABLE{Border-width:thin;border-style: solid;border-color:Black;border-collapse: collapse;}
TH{border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: ThreeDShadow}
TD{border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: Transparent}
</style>
"@

        #Converts the output to HTML format and writes it to a file
        Get-Accounts | Wait-Job | Receive-Job | Select StartName, Name, DisplayName, StartMode, SystemName | ConvertTo-Html -Property StartName, Name, DisplayName, StartMode, SystemName -Head $HTML -Body "<H2>Services Executed by Non-Standard Service Accounts $Computer</H2>"| Out-File $Report -Force
        Write-Output "`nHTML Report has been saved to $Report for future viewing."
}

    #Default value set to Export-CSV
    default {

        #Set location for the report to executing users' My Documents folder
        $Report = [environment]::getfolderpath("mydocuments") + "\Service_Account-Audit_Report-" + $logdate + ".csv"

        #Converts the output to CSV format and writes it to a file
        Get-Accounts | Wait-Job | Receive-Job | Select StartName, Name, DisplayName, StartMode, SystemName | Export-Csv $Report -NoTypeInformation -Force
        Write-Output "`nCSV Report has been saved to $Report for future viewing."
    }
}

#Launches report for viewing
Invoke-Item $Report