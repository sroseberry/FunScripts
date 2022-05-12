$ScriptPath = Split-Path $MyInvocation.MyCommand.Path
$Output = New-Object -Type PSObject


#Clear-Host

write-host ""
write-host ""
write-host "+------------------------------------------------------------------------------+"
write-host "|                        Extracteur de configuration v1                        |"
write-host "+------------------------------------------------------------------------------+"
write-host "|   Sélectionnez le type de poste à valider                                    |"
write-host "|   1. Client Win10 pour le VPN (VPN doit être en fonction!)                   |"
write-host "|   2. Routeur Externe (vers l'Internet)                                       |"
write-host "|   3. Routeur Interne (entre les réseaux client et serveur) / DNS Secondaire  |"
write-host "|   4. Poste Win10 Interne                                                     |"
write-host "|   5. Contrôleur de domaine / DNS                                             |"
write-host "+------------------------------------------------------------------------------+"
write-host ""
$vmToTest = Read-Host -prompt "Quelle machine voulez-vous tester?"


If ($vmToTest -eq 1) {
  ############################################
  # Client Win10 pour le VPN
  ############################################
  # Identifier Nom de la machine
  $ComputerName = $env:computername
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_ComputerName" -Value $env:computername
  # Identifier si le poste est dans le domaine
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_isInDomain" -Value (gwmi win32_computersystem).partofdomain

  # Identifier le type de système
  $OS = gcim Win32_OperatingSystem | select name, caption
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsName" -Value $OS.name
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsCaption" -Value $OS.Caption

  # Identifier cartes réseaux
  $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}
  $i=1
  foreach ($Network in $Networks) {
    $IPAddress  = $Network.IpAddress[0]
    $SubnetMask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder
    $WINS1 = $Network.WINSPrimaryServer
    $WINS2 = $Network.WINSSecondaryServer
    $WINS = @($WINS1,$WINS2)
    $IsDHCPEnabled = $false
    If($network.DHCPEnabled) {
     $IsDHCPEnabled = $true
    }
    $MACAddress  = $Network.MACAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IPAddress$i" -Value $IPAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_SubnetMask$i" -Value $SubnetMask
    $Output | Add-Member -MemberType NoteProperty -Name "Net_Gateway$i" -Value ($DefaultGateway -join ",")
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IsDHCPEnabled$i" -Value $IsDHCPEnabled
    $Output | Add-Member -MemberType NoteProperty -Name "Net_DNSServers$i" -Value ($DNSServers -join ",")
    $i+=1
  }

  # Valider connectivité avec l'externe
  $ping = Test-NetConnection 8.8.8.8
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Succeeded" -Value $ping.PingSucceeded

  # Valider connectivité avec l'externe (prise 2)
  $ping = Test-NetConnection "www.roseberry.tech"
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Succeeded" -Value $ping.PingSucceeded

  $VPNs = Get-VpnConnection | select *
  $i=1
  foreach ($VPN in $VPNs) {
    $Name  = $VPN.Name
    $ConnectionStatus = $VPN.ConnectionStatus
    $ServerAddress = $VPN.ServerAddress
    $AuthenticationMethod = $VPN.AuthenticationMethod

    $Output | Add-Member -MemberType NoteProperty -Name " VPN_Name$i" -Value $Name
    $Output | Add-Member -MemberType NoteProperty -Name "VPN_ConnectionStatus$i" -Value $ConnectionStatus
    $Output | Add-Member -MemberType NoteProperty -Name "VPN_ServerAddress$i" -Value $ServerAddress
    $Output | Add-Member -MemberType NoteProperty -Name "VPN_AuthenticationMethod$i" -Value $AuthenticationMethod
    #$Output | Add-Member -MemberType NoteProperty -Name "Net_DNSServers$i" -Value ($DNSServers -join ",")
    $i+=1
  }




  $Output | export-clixml -Path "$ScriptPath\1_$ComputerName.TPFinal"
  $MessageFin = @("
  < N'oubliez pas d'envoyer les fichiers TPFinal >
  < à Sam et de valider la réception!            >
    ---------------------------------------------
          \   ^__^
           \  (**)\_______
              (__)\       )\/\
               U  ||----w |
                  ||     ||
  ")


}
elseif ($vmToTest -eq 2) {
  ############################################
  # Routeur Externe (vers l'Internet)
  ############################################
  # Identifier Nom de la machine
  $ComputerName = $env:computername
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_ComputerName" -Value $env:computername
  # Identifier si le poste est dans le domaine
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_isInDomain" -Value (gwmi win32_computersystem).partofdomain

  # Identifier le type de systême
  $OS = gcim Win32_OperatingSystem | select name, caption
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsName" -Value $OS.name
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsCaption" -Value $OS.Caption

  # Identifier cartes réseaux
  $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}
  $i=1
  foreach ($Network in $Networks) {
    $IPAddress  = $Network.IpAddress[0]
    $SubnetMask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder
    $WINS1 = $Network.WINSPrimaryServer
    $WINS2 = $Network.WINSSecondaryServer
    $WINS = @($WINS1,$WINS2)
    $IsDHCPEnabled = $false
    If($network.DHCPEnabled) {
     $IsDHCPEnabled = $true
    }
    $MACAddress  = $Network.MACAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IPAddress$i" -Value $IPAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_SubnetMask$i" -Value $SubnetMask
    $Output | Add-Member -MemberType NoteProperty -Name "Net_Gateway$i" -Value ($DefaultGateway -join ",")
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IsDHCPEnabled$i" -Value $IsDHCPEnabled
    $Output | Add-Member -MemberType NoteProperty -Name "Net_DNSServers$i" -Value ($DNSServers -join ",")
    $i+=1
  }

  # Valider connectivité avec l'externe
  $ping = Test-NetConnection 8.8.8.8
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Succeeded" -Value $ping.PingSucceeded

  # Valider connectivité avec l'externe (prise 2)
  $ping = Test-NetConnection "www.roseberry.tech"
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Succeeded" -Value $ping.PingSucceeded



  # Valider connectivité avec Routeur Interne
  $IP_RouteurInterne = read-host -prompt "Veuillez entrer l'IP de votre routeur interne: "
  $Output | Add-Member -MemberType NoteProperty -Name "IP_RouteurInterne" -Value $IP_RouteurInterne
  $ping = Test-NetConnection $IP_RouteurInterne
  $Output | Add-Member -MemberType NoteProperty -Name "PingRouteurInt_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingRouteurInt_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingRouteurInt_Succeeded" -Value $ping.PingSucceeded



  # Identifier les rôles
  #$RoleAndFeatures = Get-WindowsFeature RemoteAccess, DirectAccess-VPN, Routing, Web-Application-Proxy | select Name, InstallState
  try {
    $Output | Add-Member -MemberType NoteProperty -Name "Role_RemoteAccess" -Value (Get-WindowsFeature RemoteAccess -ErrorAction SilentlyContinue | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DirectAccess-VPN" -Value (Get-WindowsFeature DirectAccess-VPN | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Routing" -Value (Get-WindowsFeature Routing | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Web-Application-Proxy" -Value (Get-WindowsFeature Web-Application-Proxy | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DNS" -Value (Get-WindowsFeature DNS | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_ADDS" -Value (Get-WindowsFeature AD-Domain-Services | select InstallState).InstallState

  }
  catch{
    $Output | Add-Member -MemberType NoteProperty -Name "Role_RemoteAccess" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DirectAccess-VPN" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Routing" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Web-Application-Proxy" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DNS" -Value "NUL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_ADDS"-Value "NULL"
  }

  # Valider NAT
  $i=1
  foreach ($Adapter in (Get-NetAdapter)) {
    $text = cmd /c netsh routing ip nat show interface $Adapter.name
    $Output | Add-Member -MemberType NoteProperty -Name "NAT_Adapter$i" -Value $Adapter.name
    try {
        $Output | Add-Member -MemberType NoteProperty -Name "NAT_Mode$i" -Value $text[3].split(":")[1] -errorAction stop
    }
    catch {
        $Output | Add-Member -MemberType NoteProperty -Name "NAT_Mode$i" -Value "NULL"
    }
    $i+=1
  }

  # Valider Table de routage
  $text = cmd /c route print -4
  $i=1
  foreach ($line in $Text) {
    $Output | Add-Member -MemberType NoteProperty -Name "ROUTE_TableLine_$i" -Value $line
    $i+=1
  }


  $Output | export-clixml -Path "$ScriptPath\2_$ComputerName.TPFinal"
  $MessageFin = @("
  < N'oubliez pas d'envoyer les fichiers TPFinal >
  < à Sam et de valider la réception!            >
    ---------------------------------------------
          \
            \     (.)_(.)
               _ (   _   ) _
              / \/`-----'\/ \
            __\ ( (     ) ) /__
            )   /\ \._./ /\   (
             )_/ /|\   /|\ \_(
  ")

}
elseif ($vmToTest -eq 3) {
  ############################################
  # Routeur Interne
  # Check DNS à la main
  ############################################
  # Identifier Nom de la machine
  $ComputerName = $env:computername
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_ComputerName" -Value $env:computername
  # Identifier si le poste est dans le domaine
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_isInDomain" -Value (gwmi win32_computersystem).partofdomain

  # Identifier le type de systême
  $OS = gcim Win32_OperatingSystem | select name, caption
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsName" -Value $OS.name
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsCaption" -Value $OS.Caption

  # Identifier cartes réseaux
  $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}
  $i=1
  foreach ($Network in $Networks) {
    $IPAddress  = $Network.IpAddress[0]
    $SubnetMask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder
    $WINS1 = $Network.WINSPrimaryServer
    $WINS2 = $Network.WINSSecondaryServer
    $WINS = @($WINS1,$WINS2)
    $IsDHCPEnabled = $false
    If($network.DHCPEnabled) {
     $IsDHCPEnabled = $true
    }
    $MACAddress  = $Network.MACAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IPAddress$i" -Value $IPAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_SubnetMask$i" -Value $SubnetMask
    $Output | Add-Member -MemberType NoteProperty -Name "Net_Gateway$i" -Value ($DefaultGateway -join ",")
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IsDHCPEnabled$i" -Value $IsDHCPEnabled
    $Output | Add-Member -MemberType NoteProperty -Name "Net_DNSServers$i" -Value ($DNSServers -join ",")
    $i+=1
  }

  # Valider connectivité avec l'externe
  $ping = Test-NetConnection 8.8.8.8
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Succeeded" -Value $ping.PingSucceeded

  # Valider connectivité avec l'externe (prise 2)
  $ping = Test-NetConnection "www.roseberry.tech"
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Succeeded" -Value $ping.PingSucceeded

  # Valider connectivité avec le DC
  $IP_DC = read-host -prompt "Veuillez entrer l'IP de votre DC: "
  $Output | Add-Member -MemberType NoteProperty -Name "IP_DC" -Value $IP_DC
  $ping = Test-NetConnection $IP_DC
  $Output | Add-Member -MemberType NoteProperty -Name "PingDC_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingDC_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingDC_Succeeded" -Value $ping.PingSucceeded

  # Identifier les rôles
  #$RoleAndFeatures = Get-WindowsFeature RemoteAccess, DirectAccess-VPN, Routing, Web-Application-Proxy | select Name, InstallState
  try {
    $Output | Add-Member -MemberType NoteProperty -Name "Role_RemoteAccess" -Value (Get-WindowsFeature RemoteAccess -ErrorAction SilentlyContinue | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DirectAccess-VPN" -Value (Get-WindowsFeature DirectAccess-VPN | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Routing" -Value (Get-WindowsFeature Routing | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Web-Application-Proxy" -Value (Get-WindowsFeature Web-Application-Proxy | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DNS" -Value (Get-WindowsFeature DNS | select InstallState).InstallState
    $Output | Add-Member -MemberType NoteProperty -Name "Role_ADDS" -Value (Get-WindowsFeature AD-Domain-Services | select InstallState).InstallState

  }
  catch{
    $Output | Add-Member -MemberType NoteProperty -Name "Role_RemoteAccess" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DirectAccess-VPN" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Routing" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_Web-Application-Proxy" -Value "NULL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_DNS" -Value "NUL"
    $Output | Add-Member -MemberType NoteProperty -Name "Role_ADDS"-Value "NULL"
  }

  # Valider NAT
  $i=1
  foreach ($Adapter in (Get-NetAdapter)) {
    $text = cmd /c netsh routing ip nat show interface $Adapter.name
    $Output | Add-Member -MemberType NoteProperty -Name "NAT_Adapter$i" -Value $Adapter.name
    try {
        $Output | Add-Member -MemberType NoteProperty -Name "NAT_Mode$i" -Value $text[3].split(":")[1] -errorAction stop
    }
    catch {
        $Output | Add-Member -MemberType NoteProperty -Name "NAT_Mode$i" -Value "NULL"
    }
    $i+=1
  }

  # Valider Table de routage
  $text = cmd /c route print -4
  $i=1
  foreach ($line in $Text) {
    $Output | Add-Member -MemberType NoteProperty -Name "ROUTE_TableLine_$i" -Value $line
    $i+=1
  }

  F
  $Output | export-clixml -Path "$ScriptPath\3_$ComputerName.TPFinal"
  $MessageFin = @("
  < N'oubliez pas d'envoyer les fichiers TPFinal >
  < à Sam et de valider la réception!            >
    ---------------------------------------------
          \
            \
                 ,
                /|      __
               / |   ,-~ /
              Y :|  //  /
              | jj /( .^
              >-""~""-v""
             /       Y
            jo  o    |
           ( ~T~     j
            >._-' _./
          /   ""~""  |
         Y     _,  |
        /| ;-""~ _  l
       / l/ ,-""~    \
       \//\/      .- \
        Y        /    Y
        l       I     !
        ]\      _\    /""\
       ("" ~----( ~   Y.  )
     ~~~~~~~~~~~~~~~~~~~~~~~~~")

}
elseif ($vmToTest -eq 4) {
  ############################################
  # Poste Win10 Interne
  ############################################
  # Identifier Nom de la machine
  $ComputerName = $env:computername
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_ComputerName" -Value $env:computername
  # Identifier si le poste est dans le domaine
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_isInDomain" -Value (gwmi win32_computersystem).partofdomain

  # Identifier le type de systême
  $OS = gcim Win32_OperatingSystem | select name, caption
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsName" -Value $OS.name
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsCaption" -Value $OS.Caption

  # Identifier cartes réseaux
  $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}
  $i=1
  foreach ($Network in $Networks) {
    $IPAddress  = $Network.IpAddress[0]
    $SubnetMask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder
    $WINS1 = $Network.WINSPrimaryServer
    $WINS2 = $Network.WINSSecondaryServer
    $WINS = @($WINS1,$WINS2)
    $IsDHCPEnabled = $false
    If($network.DHCPEnabled) {
     $IsDHCPEnabled = $true
    }
    $MACAddress  = $Network.MACAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IPAddress$i" -Value $IPAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_SubnetMask$i" -Value $SubnetMask
    $Output | Add-Member -MemberType NoteProperty -Name "Net_Gateway$i" -Value ($DefaultGateway -join ",")
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IsDHCPEnabled$i" -Value $IsDHCPEnabled
    $Output | Add-Member -MemberType NoteProperty -Name "Net_DNSServers$i" -Value ($DNSServers -join ",")
    $i+=1
  }

  # Valider connectivité avec l'externe
  $ping = Test-NetConnection 8.8.8.8
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Succeeded" -Value $ping.PingSucceeded

  # Valider connectivité avec l'externe (prise 2)
  $ping = Test-NetConnection "www.roseberry.tech"
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Succeeded" -Value $ping.PingSucceeded

   # Valider connectivité avec le DC
  $IP_DC = read-host -prompt "Veuillez entrer l'IP de votre DC: "
  $Output | Add-Member -MemberType NoteProperty -Name "IP_DC" -value $IP_DC
  $ping = Test-NetConnection $IP_DC
  $Output | Add-Member -MemberType NoteProperty -Name "PingDC_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingDC_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingDC_Succeeded" -Value $ping.PingSucceeded

  $Output | export-clixml -Path "$ScriptPath\4_$ComputerName.TPFinal"
  $MessageFin = @("
  < N'oubliez pas d'envoyer les fichiers TPFinal >
  < à Sam et de valider la réception!            >
    ---------------------------------------------
          \
            \    _
                / \      _-'
              _/|  \-''- _ /
         __-' { |          \
             /             \
             /       ""o.  |o }
             |            \ ;
                           ',
                \_         __\
                  ''-_    \.//
                    / '-____'
                   /
                 _'
               _-'")
}
elseif ($vmToTest -eq 5) {
  ############################################
  # Contrôleur de domaine / DNS
  ############################################
  # Identifier Nom de la machine
  $ComputerName = $env:computername
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_ComputerName" -Value $env:computername
  # Identifier si le poste est dans le domaine
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_isInDomain" -Value (gwmi win32_computersystem).partofdomain

  # Identifier le type de systême
  $OS = gcim Win32_OperatingSystem | select name, caption
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsName" -Value $OS.name
  $Output | Add-Member -MemberType NoteProperty -Name "Gen_OsCaption" -Value $OS.Caption

  # Identifier cartes réseaux
  $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}
  $i=1
  foreach ($Network in $Networks) {
    $IPAddress  = $Network.IpAddress[0]
    $SubnetMask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder
    $WINS1 = $Network.WINSPrimaryServer
    $WINS2 = $Network.WINSSecondaryServer
    $WINS = @($WINS1,$WINS2)
    $IsDHCPEnabled = $false
    If($network.DHCPEnabled) {
     $IsDHCPEnabled = $true
    }
    $MACAddress  = $Network.MACAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IPAddress$i" -Value $IPAddress
    $Output | Add-Member -MemberType NoteProperty -Name "Net_SubnetMask$i" -Value $SubnetMask
    $Output | Add-Member -MemberType NoteProperty -Name "Net_Gateway$i" -Value ($DefaultGateway -join ",")
    $Output | Add-Member -MemberType NoteProperty -Name "Net_IsDHCPEnabled$i" -Value $IsDHCPEnabled
    $Output | Add-Member -MemberType NoteProperty -Name "Net_DNSServers$i" -Value ($DNSServers -join ",")
    $i+=1
  }

  # Valider connectivité avec l'externe
  $ping = Test-NetConnection 8.8.8.8
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt1_Succeeded" -Value $ping.PingSucceeded

  # Valider connectivité avec l'externe (prise 2)
  $ping = Test-NetConnection "www.roseberry.tech"
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingExt2_Succeeded" -Value $ping.PingSucceeded

  # Valider connectivité avec DNS Secondaire
  $IP_DNS = read-host -prompt "Veuillez entrer l'IP de votre serveur DNS secondaire (routeur interne): "
  $Output | Add-Member -MemberType NoteProperty -Name "IP_DNS" -Value $IP_DNS
  $ping = Test-NetConnection $IP_DNS
  $Output | Add-Member -MemberType NoteProperty -Name "PingDNS_Interface" -Value $ping.InterfaceAlias
  $Output | Add-Member -MemberType NoteProperty -Name "PingDNS_Source" -Value $ping.SourceAddress
  $Output | Add-Member -MemberType NoteProperty -Name "PingDNS_Succeeded" -Value $ping.PingSucceeded

  <# Valider les comptes d'usagers
  try {
    $temp = Get-Aduser -Identity Administrateur
    $Output | Add-Member -MemberType NoteProperty -Name "AD_AdminEnabled" -Value $temp.enabled
  }
  catch {
    $Output | Add-Member -MemberType NoteProperty -Name "AD_AdminEnabled" -Value "Erreur"
  }#>










  $Output | export-clixml -Path "$ScriptPath\5_$ComputerName.TPFinal"
  $MessageFin = @("
  < N'oubliez pas d'envoyer les fichiers TPFinal >
  < à Sam et de valider la réception!            >
    ---------------------------------------------
          \
            \
                   ,.---.
         ,,,,     /    _ `.
          \\\\   /      \  )
           |||| /\/``-.__\/
           ::::/\/_
   {{`-.__.-'(`(^^(^^^(^ 9 `.========='
   {{{{{{ { ( ( (  (   (-----:=
   {{.-'~~'-.(,(,,(,,,(__6_.'=========.
           ::::\/\
           |||| \/\  ,-'/\
          ////   \ `` _/  )
         ''''     \  `   /
                   `---''")
}
else {
  $MessageFin = "Cette option n'existe pas!!!!"

}



write-host $MessageFin
write-host ""
Read-Host -Prompt "Appuyez sur une touche pour quitter"