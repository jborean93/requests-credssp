[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [String]
    $UserName,

    [Parameter(Mandatory)]
    [String]
    $Password
)

Write-Information -MessageData "Allow local admins over network auth"
$regInfo = @{
    Path         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Name         = "LocalAccountTokenFilterPolicy"
    Value        = 1
    PropertyType = "DWord"
    Force        = $true
}
New-ItemProperty @regInfo

Write-Information -MessageData 'Enabling WinRM and CredSSP'
Enable-PSRemoting -Force
$null = Enable-WSManCredSSP -Role Server -Force
Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $true

Write-Information -MessageData 'Recreating WSMan listeners'
Remove-Item -Path WSMan:\localhost\Listener\* -Recurse -Force
$null = New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{
    Address   = '*'
    Transport = 'HTTP'
}

$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation cert:\LocalMachine\My
$wsmanParams = @{
    ResourceURI = 'winrm/config/Listener'
    SelectorSet = @{
        Address   = '*'
        Transport = 'HTTPS'
    }
    ValueSet    = @{
        CertificateThumbprint = $cert.Thumbprint
    }
}
$null = New-WSManInstance @wsmanParams

Write-Information -MessageData 'Opening up firewall'
$firewallParams = @{
    Profile   = @('Domain', 'Private', 'Public')
    Direction = 'Inbound'
    Action    = 'Allow'
    Protocol  = 'TCP'
}
$null = New-NetFirewallRule -DisplayName "WinRM HTTP" -LocalPort 5985 @firewallParams
$null = New-NetFirewallRule -DisplayName "WinRM HTTPS" -LocalPort 5986 @firewallParams

Write-Information -MessageData 'Create local admin user'
$userParams = @{
    Name                 = $UserName
    Password             = (ConvertTo-SecureString -AsPlainText -Force -String $Password)
    AccountNeverExpires  = $true
    PasswordNeverExpires = $true
}
$null = New-LocalUser @userParams
Add-LocalGroupMember -Group Administrators -Member $userParams.Name
