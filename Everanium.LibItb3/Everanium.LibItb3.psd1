# Module manifest for the ITB PowerShell binding.

@{
    RootModule           = 'Everanium.LibItb3.psm1'
    ModuleVersion        = '0.5.1'
    GUID                 = 'ac3aa715-a34c-46de-906f-51d29510463b'
    Author               = 'Andrey Kuvshinov <andrew@encloud.blue>'
    Copyright            = '(c) 2026 Andrey Kuvshinov'
    Description          = 'ITB Symmetric Cipher Construction with Ambiguity-Based Security - PowerShell'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'New-ItbOpts'
        'New-ItbProfile'
        'Get-ItbProfile'
        'Get-ItbProfileName'
        'Register-ItbProfile'
        'New-ItbPipeline'
        'Import-ItbPipeline'
        'Save-ItbPipeline'
        'Set-ItbMaxWorkers'
        'Invoke-ItbRekey'
        'Close-ItbPipeline'
        'Invoke-ItbEncrypt'
        'Invoke-ItbDecrypt'
        'Invoke-ItbEncryptStream'
        'Invoke-ItbDecryptStream'
        'New-ItbEncryptStream'
        'New-ItbDecryptStream'
        'Get-ItbVersion'
        'Set-ItbMemoryLimit'
        'Set-ItbGCPercent'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('cryptography', 'encryption', 'cipher', 'symmetric', 'aead')
            LicenseUri = 'https://github.com/everanium/itb/blob/main/LICENSE'
            ProjectUri = 'https://github.com/everanium/itb'
        }
    }
}
