using namespace System.Collections.ObjectModel
using namespace System.DirectoryServices.AccountManagement
using namespace System.Management.Automation

<#
.SYNOPSIS
Validate a credential.

.DESCRIPTION
Validate a credential in either the domain or machine context.

.PARAMETER Credential
The credential to test.

.PARAMETER Context
Which context to test the credential in.

.PARAMETER ContextOptions
A combination of one or more ContextOptions enumeration values the options
used to bind to the server.
#>
function Test-Credential {
    
    [CmdletBinding()]
    [OutputType( [bool] )]
    Param(
    
        [Parameter( Mandatory = $true )]
        [object]
        $Credential,

        [ContextType]
        $Context = 'Domain',

        [ContextOptions[]]
        $ContextOptions = 'Negotiate'

    )

    DynamicParam {

        $ParamDictionary = [RuntimeDefinedParameterDictionary]::new()

        switch ( $Context ) {

            'ApplicationDirectory' {
                
                $ParameterAttribute = [ParameterAttribute]::new()
                $ParameterAttribute.Mandatory = $true

                $AttributeCollection = [Collection[Attribute]]::new()
                $AttributeCollection.Add( $ParameterAttribute )

                $ServerParam = [RuntimeDefinedParameter]::new( 'Server', [string], $AttributeCollection )
                $ParamDictionary.Add( 'Server', $ServerParam )

                $PortParam = [RuntimeDefinedParameter]::new( 'Port', [uint32], $AttributeCollection )
                $ParamDictionary.Add( 'Port', $PortParam )

            }
            
            'Domain' {
                
                $ParameterAttribute = [ParameterAttribute]::new()
                
                $AttributeCollection = [Collection[Attribute]]::new()
                $AttributeCollection.Add( $ParameterAttribute )

                $DomainParam = [RuntimeDefinedParameter]::new( 'Domain', [string], $AttributeCollection )
                $ParamDictionary.Add( 'Domain', $DomainParam )

            }

            'Machine' {
                
                $ParameterAttribute = [ParameterAttribute]::new()

                $AttributeCollection = [Collection[Attribute]]::new()
                $AttributeCollection.Add( $ParameterAttribute )

                $ComputerNameParam = [RuntimeDefinedParameter]::new( 'ComputerName', [string], $AttributeCollection )
                $ParamDictionary.Add( 'ComputerName', $ComputerNameParam )
            
            }
            
        }
        
        return $ParamDictionary

    }

    process {

        switch ( $Context ) {

            'ApplicationDirectory' {

                Write-Verbose ( 'Testing credential against AD LDS server {0} on port {1}.' -f $PSBoundParameters.Server, $PSBoundParameters.Port )

                $AuthObj = [PrincipalContext]::new( $Context, ( $PSBoundParameters.Server, $PSBoundParameters.Port -join ':' ) )
            
            }

            'Domain' {

                if ( -not $PSBoundParameters.ContainsKey('Domain') ) {
                    $PSBoundParameters.Domain = $env:USERDNSDOMAIN
                }

                Write-Verbose ( 'Testing credential against domain {0}.' -f $PSBoundParameters.Domain )

                $AuthObj = [PrincipalContext]::new( $Context, $PSBoundParameters.Domain )

            }

            'Machine' {

                if ( $PSBoundParameters.ContainsKey('ComputerName') ) {

                    Write-Verbose ( 'Testing credential against machine {0}.' -f $PSBoundParameters.ComputerName )

                    $AuthObj = [PrincipalContext]::new( $Context, $PSBoundParameters.ComputerName )

                } else {

                    Write-Verbose ( 'Testing credential against machine {0}.' -f $env:COMPUTERNAME )

                    $AuthObj = [PrincipalContext]::new( $Context )

                }

            }

        }

        if ( $Credential -isnot [pscredential] ) {
            $Credential = Get-Credential -UserName ($Credential -as [string])
        }

        try {

            $AuthObj.ValidateCredentials(
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password,    
                $ContextOptions
            )

        } finally {

            $AuthObj.Dispose()

        }

    }

}