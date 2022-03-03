

##############################################################################
# Variables importantes pour le script
##############################################################################

# Configuration de base à exécuter au démarrage de la session PowerShell
$Domain = "domaine.local"		# Nom du domaine à créer

# Configuration des cartes Ethernet
$ExternalNIC = "Ethernet0"
$InternalNIC = "Ethernet1"

# Configuration carte Ethernet secondaire (Ethernet1)
$NetworkID = "192.168.64.0/24"		# Réseau et masque
$IpAddress = "192.168.64.2"				# IP du serveur (doit être dans la plage de $NetworkID)
$Mask = "24"											# Masque réseau du serveur ex.: 24 pour /24
$MaskLong = "255.255.255.0"
$DefaultGateway = "192.168.64.1"
$DnsForwarder = "1.1.1.1"					# IP du redirecteur DNS externe ex.: 8.8.8.8

# Configuration DHCP
$DhcpScopeID = "192.168.64.0"
$DhcpStartRange = "192.168.64.10"
$DhcpEndRange = "192.168.64.50"
$RouterIP = "192.168.64.1"




$ErrorActionPreference= 'silentlycontinue'

##############################################################################
# Vérification et configuration de l'interface interne
##############################################################################
# Validation de l'existence de la seconde interface réseau
Invoke-Expression "Get-NetIPInterface -InterfaceAlias '$InternalNIC'" -ErrorVariable badoutput | out-null
if ($badoutput -ne "") {
	write-host 'Il manque une carte réseau! Arrêt du script'
	Read-Host
	exit
}

# Configuration d'une IP statique sur la seconde carte si ce n'est pas déjà fait ;-)
if ((Get-NetIPInterface -InterfaceAlias $InternalNIC -AddressFamily IPv4).Dhcp -eq 'Enabled')
{
	Set-NetIPInterface -InterfaceAlias $InternalNIC -Dhcp Disabled
	New-NetIPAddress -InterfaceAlias $InternalNIC -IPAddress $IpAddress -PrefixLength $Mask -DefaultGateway $DefaultGateway
	Invoke-Expression "Set-DnsClientServerAddress -InterfaceAlias $InternalNIC -ServerAddresses @('127.0.0.1','1.1.1.1')" -ErrorVariable badoutput | out-null

}

if ($env:computername -like 'WIN-*') {
	write-host "Le nom du serveur $($env:computername) devrait être changé."
	write-host 'Appuyer sur la touche Entrée pour continuer ou arrêter ce script.'
	Read-Host
	write-host 'Ne jamais exécuter un script sans savoir ce qu''il fait. MOUWAHAHAHA'
	# Zstylzhemghi est la progéniture de Ycnágnnisssz et mère de Tsathoggua
	Rename-Computer -newName 'Zstylzhemghi' -Restart
}

##############################################################################
# Installation AD et DNS
##############################################################################
# Installation de Active Directory (AD DS) et création d'une forêt
if ((Get-WindowsFeature | where {($_.name -like 'AD-Domain-Services')}).Installed -eq $False) {
	Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools	}

# Installation du DNS si nécessaire...
if ((Get-WindowsFeature | where {($_.name -like 'DNS')}).Installed -eq $False){
	Install-WindowsFeature DNS -IncludeManagementTools }
# Configuration de la forêt
$WorkgroupOrDomain = $Domain.split('.')[0]
if ($env:UserDomain -notlike "$WorkgroupOrDomain*") {
	Install-ADDSForest -DomainName $Domain -confirm:$false }


##############################################################################
# Configuration et validation DNS
##############################################################################

Add-DnsServerPrimaryZone -NetworkID $NetworkID -ZoneFile "$IpAddress.in-addr.arpa.dns"
Add-DnsServerForwarder -IPAddress $DnsForwarder -PassThru

# Validation du DNS
if ((Test-DnsServer -IPAddress $IpAddress -ZoneName $Domain).result -eq "Success")
{
	write-host "DNS Configuré avec succès"
}
else
{
	write-host "Erreur(s) DNS, validez la zone inverse et le redirecteur vers l'externe"
}

##############################################################################
# DHCP
##############################################################################
if ((Get-WindowsFeature | where {($_.name -like 'DHCP')}).Installed -eq $False){
	Install-WindowsFeature DHCP -IncludeManagementTools }

netsh dhcp add securitygroups

Add-DHCPServerv4Scope -Name 'Postes des employés' -StartRange $DhcpStartRange -EndRange $DhcpEndRange -SubnetMask $MaskLong -State Active
Set-DhcpServerv4Scope -ScopeId $DhcpScopeID -LeaseDuration (New-TimeSpan -Hours 6)     #1.00:00:00   # 8h
Set-DHCPServerv4OptionValue -ScopeID $DhcpScopeID -DnsDomain $Domain -DnsServer $IpAddress -Router $RouterIP
Add-DhcpServerInDC -DnsName $Domain -IpAddress $IpAddress


Get-DhcpServerv4Scope
Get-DhcpServerInDC
Restart-service dhcpserver

write-host "Tout est terminé"
