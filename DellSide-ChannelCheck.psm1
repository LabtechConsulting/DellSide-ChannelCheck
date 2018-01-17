function Get-DellSpeculationControlBIOSVersion {
<#
.DESCRIPTION
    Lists the minimum BIOS version needed to protect against the side-channel vulnerabilities Specre and Meltdown.

.PARAMETER Model
    The model of the Dell machine, Example: "OptiPlex 5050"
    If a model is not provided the current machines model will be detected and checked.

.NOTES
    Version:        1.0
    Author:         Chris Taylor
    Creation Date:  1/16/2018
    Purpose/Change: Initial script development

.LINK
  labtechconsulting.com
  christaylor.rocks
  http://www.dell.com/support/article/us/en/04/sln308587/microprocessor-side-channel-vulnerabilities-cve-2017-5715-cve-2017-5753-cve-2017-5754-impact-on-dell-products
  
.EXAMPLE
    Get-DellSpeculationControlBIOSVersion -Model "Latitude E5570"
    - This will lookup the minimum BIOS version for the specified Dell model "Latitude E5570".

    Get-DellSpeculationControlBIOSVersion
    - This will lookup the minimum BIOS version for the local machine.
#>
[CmdletBinding()]
param (
    [parameter(ValueFromPipeline)]
    $Model
    )
    if(!$Model){
        $Model = (Get-WmiObject Win32_Computersystem | Where {$_.manufacturer -like "*Dell*"}).model
        if (!$Model) {
            Write-Warning "ERROR: Dell model not detected. You can specify a model with the -Model switch."
            exit 1
        }
        $Local = $true
    }
    $_Model = ($Model -replace 'non-vPro', '').trim()
    $_Model = $_Model -replace ' Tower',''
    $_Model = $_Model -replace ' ','.*'
    $url = 'http://www.dell.com/support/article/us/en/04/sln308587/microprocessor-side-channel-vulnerabilities-cve-2017-5715-cve-2017-5753-cve-2017-5754-impact-on-dell-products?lang=en'
    $test = iwr $url
    $Contetnt = $test.ParsedHtml.getElementById('dvDynamicContent')
    $PlainText = $Contetnt.outerText

    $Split = ($PlainText -split '\n\s*\n\s*\n')
    try {
        $Min = ((($Split | select-string -pattern $_Model) -split '[\r\n]') |? {$_})[1]
        if ($Local ) {
            $Current = (Get-WmiObject win32_bios).SMBIOSBIOSVersion
            $Output = @{
                "Model" = $Model
                "Minimum Version" = $Min
                "Current Version" = $Current
                "Protected" = $Current -ge $Min
            }
        } else {
            $Output = $Min
        }
        
        Write-Output $Output
    } catch {
        Write-Warning "ERROR: Unable to find model."
    }
}
