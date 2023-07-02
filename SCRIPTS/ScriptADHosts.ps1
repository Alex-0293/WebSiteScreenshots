<#
    .NOTES
        AUTHOR  AlexK (1928311@tuta.io)
        CREATED 12.07.2022
        VER     1
        
    .LINK
        https://github.com/Alex-0293/WindowsStabilityMonitor.git
    
    .COMPONENT
        AlexkUtils

    .SYNOPSIS 

    .DESCRIPTION
        Get windows stability score and problems for remote windows computers. 

   

    .EXAMPLE
        WindowsStabilityMonitor.ps1

#>
Param (
    [Parameter( Mandatory = $false, Position = 0, HelpMessage = "Initialize global settings." )]
    [bool] $InitGlobal = $true,
    [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Initialize local settings." )]
    [bool] $InitLocal  = $true   
)
Begin {
    $Global:ScriptInvocation = $MyInvocation
    if ($env:AlexKFrameworkInitScript){
        . "$env:AlexKFrameworkInitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -InitGlobal $InitGlobal -InitLocal $InitLocal
    } Else {
        Write-host "Environmental variable [AlexKFrameworkInitScript] does not exist!" -ForegroundColor Red
        exit 1
    }
    if ($LastExitCode) { exit 1 }

    # Error trap
    trap {
        if (get-module -FullyQualifiedName AlexkUtils) {
            Get-ErrorReporting -Trap ( $_ )
            . "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1" 
        }
        Else {
            Write-Host "[$($MyInvocation.MyCommand.path)] There is error before logging initialized. Error: $_" -ForegroundColor Red
        }   
        exit 1
    }
    #################################  Mermaid diagram  #################################
    <#
    ```mermaid

    ```
    #>
    ################################# Script start here #################################


}

process {
    #region requires
    #endregion
    #region functions
        Function Get-ComputerParameters {
        <#
            .DESCRIPTION
                Get Username, IP, MAC from computer description.
        #>
            [OutputType([string])]
            [CmdletBinding()]
            Param(
                [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Computer description." )]
                [string] $Data
            )
            try {
                #region functions
                #endregion

                $Result = $null

                $ActiveUserPattern = '(?<ActiveUser>[a-zA-Z]+[a-zA-Z0-9\.]*)?'
                $LogonTimePattern  = '(?<LogonTime>[\d]{2}\.[\d]{2}\.[\d]{4}\s[\d]{2}:[\d]{2}:[\d]{2})?'
                $IPPattern         = '(?<IP>[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})'
                $MACPattern        = '(?<MAC>([A-Fa-f0-9]{2}(:|-)?){6})'
                $DataPattern       = "$ActiveUserPattern\s?\(?$LogonTimePattern\)?;?\s?($IPPattern\s\($MACPattern\)[,\s]?)*"

                $Match = [regex]::matches( $Data, $DataPattern )

                if ( $match[0].groups ){
                    $LogonTime = $match[0].groups['LogonTime'].value
                    try{
                        $LogonTime = get-date -date $LogonTime
                    }
                    Catch{
                        $LogonTime = $null
                    }
                    
                    $ActiveUser = $match[0].groups['ActiveUser'].value
                    
                    $NETArray    = @()
                
                    foreach ( $item in ( 0..( $match.count - 1 ) ) ){                    
                        $IP  = $match[$item].groups['IP'].value
                        $MAC = $match[$item].groups['MAC'].value
                        if ( $MAC ){
                            $MAC = $MAC.replace('-', ':')
                        }
                        
                        $Net = [PSCustomObject]@{
                            IP  = $IP
                            MAC = $MAC
                        }
                        if ( $IP -or $MAC ){
                            $NETArray += $Net
                        }
                    }

                    $Result = [PSCustomObject]@{
                        LogonTime  = $LogonTime
                        ActiveUser = $ActiveUser
                        NET        = $NETArray | Sort-Object -property 'IP' -Descending
                    }
                }                
            }
            catch {
                write-host "$( $_ | out-string )"
            }

            return $Result
        }
        Function Get-DomainComputers {
            <#
            .SYNOPSIS 
                AUTHOR Alexk
                DATE 06.05.2020
                VER 1   
            .DESCRIPTION
            Get domain computers in OU.
            .EXAMPLE
            Get-DomainComputers -Computer "Host1" -Credentials $Credential 
            #>    
            [CmdletBinding()]   
            Param(
                [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Remote computer name." )]
                [ValidateNotNullOrEmpty()]
                [string] $Computer,
                [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Credential." )]
                [PSCredential] $Credential,
                [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Distinguish name." )]
                [ValidateNotNullOrEmpty()]
                [string] $DN,
                [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Get computer user, owner and last logon/logoff date." )]
                [ValidateNotNullOrEmpty()]
                [switch] $GetExtendedData
            )    

            [array]$output = @()

            if ( $DN ){
                Add-ToLog -Message "Get AD computers in [$DN] on DC [$Computer]." -logFilePath $Global:gsScriptLogFilePath -Display -category "" -Status "info"
            }
            Else {
                Add-ToLog -Message "Get AD computers  on DC [$Computer]." -logFilePath $Global:gsScriptLogFilePath -Display -category "" -Status "info"
            }
            
            $ScriptBlock = {
                try {
                    $res = Import-Module 'ActiveDirectory' -PassThru
                    
                    if ( $Res ) {
                        [array]$output = @()  
                        $ADComputers = Get-AdComputer -Filter * -Properties *
                        
                        return $ADComputers
                    }
                    Else {
                        throw "Error [$_] while loading module [ActiveDirectory]"
                    }
                }
                catch{

                }

            } 
            
            $output = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Computer -Credentials $Credential -TestComputer
            if ( $GetExtendedData ){
                foreach ( $item in $output ){
                    if ( $item.Description ){
                        $ExtendedData = Get-ComputerParameters -Data $item.Description
                        if ( $ExtendedData ){
                            $item | Add-Member -NotePropertyName 'NET' -NotePropertyValue $ExtendedData.NET
                            $item | Add-Member -NotePropertyName 'LogonTime' -NotePropertyValue $ExtendedData.LogonTime  
                            $item | Add-Member -NotePropertyName 'ActiveUser' -NotePropertyValue $ExtendedData.ActiveUser                        
                        }
                    }
                    
                    $ManagedBy = $Item.ManagedBy
                    if ( $ManagedBy ){                    
                        $User     = ( $ManagedBy.split(',') | select-object -First 1 ).split('=') | select-object -skip 1
                        if ( $User ){
                            $item | Add-Member -NotePropertyName 'User' -NotePropertyValue $User
                        }
                    }
                }
            }
            
            return $output 
        }
    #endregion

    #https://4sysops.com/archives/monitoring-windows-system-stability-with-powershell/
    
    $Credential = Get-SingleCredential -FQDN $Global:DC

    $View      = 'ObjectClass', 'DNSHostName', 'OperatingSystem', 'User', 'NET', 'ActiveUser', 'LogonTime'
    $ADData    = Get-DomainComputers -Computer $Global:DC -Credential $Credential -GetExtendedData                
    $Computers = $ADData | Where-Object { ( $_.OperatingSystem -like "*windows*" ) -and ( $_.Enabled )} | Sort-Object  'DNSHostName' | Select-Object $View

    $DataArray = @()

    $ComputerNameWithStatus = Test-RemoteHostWSMan -RemoteHostName $Computers.DNSHostName -LocalAsRemote -TestConnection -GetAccountSettingPathsFromRealmData -PingCount 10 -PingDelay 1 -NonInteractive -Group

    foreach ( $Computer in $ComputerNameWithStatus ){
        if ( $Computer.AccountSettingPath ){
            $Address = $Computer.Address                        
            $Credential = Get-AESData -DataFilePath $Computer.AccountSettingPath -NewDomain $Computer.NetBIOS
        
            $PSO = [PSCustomObject]@{
                Name = Value
            }

            $DataArray  += $PSO
        }
    }
}

end {
    
    
    ################################# Script end here ###################################
    . "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
}