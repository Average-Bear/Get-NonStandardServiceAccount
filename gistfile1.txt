<#
.SYNOPSIS
Written by JBear 2/22/2017
Check requested servers for Services that are running with Service Account credentials (Any Non-Standard Accounts) and report findings.

.DESCRIPTION
Check requested servers for Services that are running with Service Account credentials (Any Non-Standard Accounts) and report findings.

.NOTES 
This version was specified for a particular domain. Changes may be made to fit your own domain/OU's or to parameterize all OU/File inputs.
#>

Param(

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

    Write-Host -ForegroundColor Yellow "`nUnable to load Active Directory Module; this is required to run this script. Please, install RSAT and configure this server properly."
    Break
}

#Empty Array
$SearchOU = @()

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

#If no OU switches are present, use parent OU for array
if(!($S.IsPresent -or $K.IsPresent -or $W.IsPresent -or $H.IsPresent)){

    #Set $SearchOU to parent server OU
    $SearchOU = "OU=Computers,DC=acme,DC=com"
}

Write-Host "`nRetrieving servers from the following OU's:"

#Process each item in $SearchOU
foreach($OU in $SearchOU) {

    Write-Progress -Activity "Retrieving servers from selected OU..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i++) / $SearchOU.count) * 100) + "%") -CurrentOperation "Processing $($OU)..." -PercentComplete ((($j++) / $SearchOU.count) * 100)
    Write-Host "$OU"

    #OU can't be $null or whitespace
    if(!([string]::IsNullOrWhiteSpace($OU))) {

        #Retrieve all server names from $OU
        $Names = (Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter *).Name

        #Add server names to $ComputerList Array
        $ComputerList += $Names
    }
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

                #Query each computer
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

                        StartName    = "N/A"
                        Name         = "N/A"
                        DisplayName  = "N/A"
                        StartMode    = "No Service Accounts Found On"
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

                    StartName    = "N/A"
                    Name         = "N/A"
                    DisplayName  = "N/A"
                    StartMode    = "Unable to Ping"
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
        $Report = [environment]::getfolderpath("mydocuments") + "\Service_Account-Audit_Report.html"

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
        Get-Accounts | Wait-Job | Receive-Job | Select StartName, Name, DisplayName, StartMode, SystemName | ConvertTo-Html -Property StartName, Name, DisplayName, StartMode, SystemName -Head $HTML -Body "<H2>Non-Standard Service Accounts on $Computer</H2>"| Out-File $Report -Force
        Write-Output "`nHTML Report has been saved to $Report for future viewing."
}

    #Default value set to Export-CSV
    default {

        #Set location for the report to executing users' My Documents folder
        $Report = [environment]::getfolderpath("mydocuments") + "\Service_Account-Audit_Report.csv"

        #Converts the output to CSV format and writes it to a file
        Get-Accounts | Wait-Job | Receive-Job | Select StartName, Name, DisplayName, StartMode, SystemName | Export-Csv $Report -NoTypeInformation -Force
        Write-Output "`nCSV Report has been saved to $Report for future viewing."
    }
}

#Launches report for viewing
Invoke-Item $Report