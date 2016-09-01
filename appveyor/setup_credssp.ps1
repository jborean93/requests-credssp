# Script to setup WinRM with CredSSP on a HTTPS listener. Used for functional tests in Appveyor.
# Authors: Jordan Borean
# License: CC0 1.0 Universal: http://creativecommons.org/publicdomain/zero/1.0/

function SetupUser() {
    $computername = $env:computername
    $username = 'User'
    $password = 'Password01'
    $desc = 'Automatically created local admin account'

    $computer = [ADSI]"WinNT://$computername,computer"
    $user = $computer.Create("user", $username)
    $user.SetPassword($password)
    $user.Setinfo()
    $user.description = $desc
    $user.setinfo()
    $user.UserFlags = 65536
    $user.SetInfo()
    $group = [ADSI]("WinNT://$computername/administrators,group")
    $group.add("WinNT://$username,user")
}

function SetupWinRMWithCredSSP() {
    # Create a HTTPS listener on WinRM
    $hostname = $env:computername
    $c = New-SelfSignedCertificate -DnsName $hostname -CertStoreLocation cert:\LocalMachine\My
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$hostname`";CertificateThumbprint=`"$($c.ThumbPrint)`"}"hostname

    # Enable CredSSP on WinRM listener
    Enable-WSManCredSSP -Role Server -Force
    Set-Item -Path "WSMan:\localhost\Service\Auth\CredSSP" -Value $true
}

function main() {
    SetupUser
    SetupWinRMWithCredSSP
}

main