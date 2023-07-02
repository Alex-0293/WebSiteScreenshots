<#
    .NOTES
        AUTHOR  AlexK (1928311@tuta.io)
        CREATED 02.07.2023
        VER     1
        
    .LINK
        https://github.com/Alex-0293/WebSiteScreenshots.git
    
    .COMPONENT
        AlexkUtils

    .SYNOPSIS 

    .DESCRIPTION
        Create whole site screenshots with N depth 

   

    .EXAMPLE
        WebSiteScreenshots.ps1

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
    #endregion


}

end {
    
    
    ################################# Script end here ###################################
    . "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
}

