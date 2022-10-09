function ShowBanner {
    $banner  = @()
    $banner+= $Global:Spacing + ''
$banner+= $Global:Spacing + '    ___    ____     ______                           __            '
$banner+= $Global:Spacing + '   /   |  / __ \   / ____/__  ____  ___  _________ _/ /_____  _____'
$banner+= $Global:Spacing + '  / /| | / / / /  / / __/ _ \/ __ \/ _ \/ ___/ __ `/ __/ __ \/ ___/'
$banner+= $Global:Spacing + ' / ___ |/ /_/ /  / /_/ /  __/ / / /  __/ /  / /_/ / /_/ /_/ / /    '
$banner+= $Global:Spacing + '/_/  |_/_____/   \____/\___/_/ /_/\___/_/   \__,_/\__/\____/_/     '
$banner+= $Global:Spacing + ''                                                                   
$banner+= $Global:Spacing + 'Vulnerable Active Directory Domain Generator by The Mayor'
$banner+= $Global:Spacing + ''
	$banner | foreach-object {
        Write-Host $_ -ForegroundColor "Yellow"
	}
}

function Write-Good { param( $String ) Write-Host $Global:InfoLine $String $Global:InfoLine1 -ForegroundColor 'Green' }
function Write-Info { param( $String ) Write-Host $Global:PlusLine  $String -ForegroundColor 'Gray'}
$Global:Spacing = "`t"
$Global:PlusLine = "`t[+]"
$Global:InfoLine = "`t[*]"
$Global:InfoLine1 = "[*]"

#Group Generation
$Global:Senior = "Senior Management"
$Global:ITAdmins = "IT Admins"
$Global:Engineering = "Engineering"
$Global:Sales = "Sales"


#Domain Information
$Global:Domain = "";

function promoteUser {
$username = ((gwmi win32_computersystem).username).split('\')[1]
Write-Good "Promoting $username to appropriate Domain Administrative roles required for the course."
Write-Info "Promoting $username to Enterprise Administrator."
net group "Enterprise Admins" $username /add /domain
Write-Info "Promoting $username to Domain Administrator."
net group "Domain Admins" $username /add /domain
Write-Info "Promoting $username to Group Policy Creator Owners."
net group "Group Policy Creator Owners" $username /add /domain
Write-Info "Promoting $username to Local Administrator (error output may occur - this is expected)."
net localgroup "administrators" $username /add
}

function renameDC {
$username = whoami
Write-Good "Renaming the domain controller to DC01"
Rename-computer -NewName "DC01" -DomainCredential $username
mkdir C:\Shared; new-smbshare -Name "Shared" -Path "C:\Shared" -ReadAccess "Users"
wget https://github.com/dievus/ADGenerator/archive/refs/heads/main.zip -outfile C:\Shared\adgenerator.zip
Expand-Archive -Path C:\Shared\adgenerator.zip -DestinationPath C:\Shared\adgenerator
}

function AddADGroup {
$domainFront = $Global:domain.split('.')[0]
$domainBack = $Global:domain.split('.')[1]
Write-Good "Creating Domain Groups"
New-ADGroup -name $Global:Senior -GroupScope Global
Write-Info "Adding $Global:Senior to $Global:domain"
New-ADGroup -name $Global:ITAdmins -GroupScope Global
Write-Info "Adding $Global:ITAdmins to $Global:domain"
New-ADGroup -name $Global:Engineering -GroupScope Global
Write-Info "Adding $Global:Engineering to $Global:domain"
New-ADGroup -name $Global:Sales -GroupScope Global
Write-Info "Adding $Global:Sales to $Global:domain"
Write-Good "Generating Organizational Units for the $Global:domain."
New-ADOrganizationalUnit -Name "SeniorManagement" -Path "DC=$domainFront,DC=$domainBack"
New-ADOrganizationalUnit -Name "ITAdmins" -Path "DC=$domainFront,DC=$domainBack"
New-ADOrganizationalUnit -Name "Engineering" -Path "DC=$domainFront,DC=$domainBack"
New-ADOrganizationalUnit -Name "Sales" -Path "DC=$domainFront,DC=$domainBack"
Write-Info "Organizational Units added."
}

function AddADUser {
Write-Good "Creating Domain Users"
$firstname = "Aaron"
$lastname = "Adams"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "C0nc0Rd1776!"
$domainFront = $Global:domain.split('.')[0]
$domainBack = $Global:domain.split('.')[1]
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=SeniorManagement,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Senior Group"
Add-ADGroupMember -Identity $Global:Senior -Members $samAccountName
Write-Info "Adding $samAccountName to Domain Administrators Group"
Add-ADGroupMember -Identity "Domain Admins" -Members $samAccountName
$firstname = "Jonathon"
$lastname = "Taylor"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Lexington1776!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=ITAdmins,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:ITAdmins Group"
Add-ADGroupMember -Identity $Global:ITAdmins -Members $samAccountName
Add-ADGroupMember -Identity "Administrators" -Members $samAccountName
$firstname = "Jillian"
$lastname = "Anthony"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "H1dD3nV4ll3y!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Engineering,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Engineering Group"
Add-ADGroupMember -Identity $Global:Engineering -Members $samAccountName
$firstname = "Tabitha"
$lastname = "Carter"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "AhArGuY5Nm7U3!@"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Engineering,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Engineering Group"
Add-ADGroupMember -Identity $Global:Engineering -Members $samAccountName
$firstname = "Megan"
$lastname = "Phillips"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "L4k3LiV3L0ve!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Engineering,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Engineering Group"
Add-ADGroupMember -Identity $Global:Engineering -Members $samAccountName
Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members $samAccountName
$firstname = "Richard"
$lastname = "Smith"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Baseball123!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Engineering,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Engineering Group"
Add-ADGroupMember -Identity $Global:Engineering -Members $samAccountName
$firstname = "Samantha"
$lastname = "Chisholm"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "FallOutBoy1!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Sales,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Sales"
Add-ADGroupMember -Identity $Global:Sales -Members $samAccountName
$firstname = "Margaret"
$lastname = "Seitz"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Phi11i35@44"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Engineering,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Engineering Group"
Add-ADGroupMember -Identity $Global:Engineering -Members $samAccountName
$firstname = "Aaron"
$lastname = "Tarolli"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Password123!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Sales,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Sales"
Add-ADGroupMember -Identity $Global:Sales -Members $samAccountName
$firstname = "Zane"
$lastname = "Dickens"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "M0t0rH3Ad65^$#"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Path "OU=Sales,DC=$domainFront,DC=$domainBack" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Sales"
Add-ADGroupMember -Identity $Global:Sales -Members $samAccountName

$firstname = "SearchField"
$lastname = "Example"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "adsfASDFwq322!21"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -Description "Password - adsfASDFwq322!21" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
}

function ASREPRoasting {
$asrepUser = "a.tarolli"	
Write-Good "Modifying pre-authentication privileges"
Set-ADAccountControl -Identity $asrepUser -DoesNotRequirePreAuth 1
Write-Info "ASREP privileges granted to $asrepUser"
}

function kerberoasting {
$svc = "mssql_svc"
#$spn = "mssqlserver"
$kerb_pass = "Password123!"
Write-Good "Adding Kerberoastable service account to domain"
net user $svc $kerb_pass /add /domain
#New-ADServiceAccount -Name $svc -ServicePrincipalNames "mssql_svc/mssqlserver.$Global:domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $kerb_pass -AsPlainText -Force)
#Set-ADServiceAccount mssql_svc -PrincipalsAllowedToDelegateToAccount (Get-ADComputer Workstation-01)
#Get-ADComputer -Identity Workstation-02 | Set-ADAccountControl -TrustedForDelegation $true
#Write-Info "Workstation-02 granted unconstrained delegation rights on DC01."
setspn -a DC01/$svc.$Global:Domain:60111 $domainFront\$svc
Write-Info "mssql_svc service account added"
}

function AD-AddACL {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Destination,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Security.Principal.IdentityReference]$Source,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Rights

        )
        $ADObject = [ADSI]("LDAP://" + $Destination)
        $identity = $Source
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
        $type = [System.Security.AccessControl.AccessControlType] "Allow"
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
        $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
        $ADObject.psbase.commitchanges()
}

function badAcls {
Write-Good "Granting $Global:ITAdmins GenericAll rights on Domain Admins."
$DestinationGroup = Get-ADGroup -Identity "$Global:ITAdmins"
$SourceGroup = Get-ADGroup -Identity "Domain Admins"
AD-AddACL -Source $DestinationGroup.sid -Destination $SourceGroup.DistinguishedName -Rights "GenericAll"
Write-Info "$Global:ITAdmins group granted GenericAll permissions for the Domain Admins group."
Write-Good "Adding misconfigured ACL rule for the $Global:Engineering group."	
$DestinationGroup = Get-ADGroup -Identity $Global:Engineering
$SourceGroup = Get-ADGroup -Identity $Global:ITAdmins
AD-AddACL -Source $DestinationGroup.sid -Destination $SourceGroup.DistinguishedName -Rights "GenericAll"
Write-Info "Whoops! GenericAll rights granted to $Global:Engineering."
Write-Good "Adding misconfigured ACL rule for Margaret Seitz."
$vulnAclUser = Get-ADUser -Identity "m.seitz"
$SourceUser = Get-ADUser -Identity "j.taylor"
AD-AddACL -Source $vulnAclUser.sid -Destination $SourceUser.DistinguishedName -Rights "GenericAll"
Write-Info "Whoops! GenericAll rights granted to m.seitz."
Write-Good "Adding misconfigured ACL rule for the $Global:Sales group."	
$DestinationGroup = Get-ADGroup -Identity $Global:Sales
$SourceGroup = Get-ADGroup -Identity $Global:Engineering
AD-AddACL -Source $DestinationGroup.sid -Destination $SourceGroup.DistinguishedName -Rights "GenericAll"
Write-Info "Whoops! GenericAll rights granted to $Global:Sales."

}	

function PSRemote {
Write-Good "Configuring some GPO policies required for the domain."
import-module grouppolicy
$domain = Get-ADDomain
$forest = $domain.Forest
$DN = $domain.DistinguishedName

$FwRule = "Allow WinRM TCP 5985 To Domain Joined Systems"
$GpoName = "WinRM Firewall TCP 5985"
$TargetOU = $DN
$PolicyStoreName = "$forest\" + $GpoName
New-Gpo -Name $GpoName | New-Gplink -target $TargetOU
$GpoSessionName = Open-NetGPO -PolicyStore $PolicyStoreName
New-NetFirewallRule -DisplayName $FwRule -Profile Any -Direction Inbound -GPOSession $GpoSessionName -PolicyStore $GpoName -Protocol TCP -LocalPort 5985
Save-NetGPO -GPOSession $GpoSessionName
Write-Info "A GPO for PowerShell Remoting was created for authenticated users on the domain."
}	

function Set-WinRMPolicy {
Write-Good "Configuring GPO policies to enable PowerShell remoting on hosts."
    $domainGPO = Get-ADDomain
    $forest = $domainGPO.Forest
    $DN = $domainGPO.DistinguishedName
    $GpoName = "Enable PSRemoting Desktops"
    $TargetOU = $DN
    $PolicyStoreName = "$forest\" + $GpoName
    New-Gpo -Name $GpoName | New-Gplink -target $TargetOU

    $domain = (Get-ADDomain).forest
    $id = (Get-GPO -name $GpoName).id
    $RemotingParams = @{
            Name=$GpoName;
            Key = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service';
            }
    
    try {
        Set-GPRegistryValue @RemotingParams -ValueName 'AllowAutoConfig' -Value 1 -Type DWord
        Set-GPRegistryValue @RemotingParams -ValueName 'IPv4Filter' -Value '*' -Type String
        Set-GPRegistryValue @RemotingParams -ValueName 'IPv6Filter' -Value '*' -Type String
        Write-Info "Registry setting for Powershell Remoting OK!"
        }
    catch { "Error enabling remoting policy" }

    $ServiceParams = @{
            Name=$GpoName;
            Key = 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM';
            }
    
    try {
        Set-GPRegistryValue @ServiceParams -ValueName 'Start' -Value 2 -Type DWord
        Set-GPRegistryValue @ServiceParams -ValueName 'DelayedAutoStart' -Value 0 -Type DWord
        Write-Info "Service setting for Powershell Remoting OK!"
        }
    catch { "Error enabling remoting policy" }
}

function Invoke-ADGenerator {
	Param(
	[Parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]
	[System.String]
	$DomainName
)
ShowBanner
$Global:Domain = $DomainName
promoteUser
Write-Good "Administrative privilege delegation completed."
renameDC
Write-Good "Domain controller renamed."
AddADGroup
Write-Good "Group creation completed."
AddADUser
Write-Good "User creation completed"
ASREPRoasting
Write-Good "ASREP settings update completed."
kerberoasting
Write-Good "Kerberoastable service creation completed."
badAcls
Write-Good "ACL misconfigurations completed."
PSRemote
Write-Good "GPO configurations completed."
Set-WinRMPolicy
Write-Good "Domain-wide PowerShell Remoting GPO configuration completed."
Write-Good "Some changes require a restart to take effect. Restarting your domain controller in 30 seconds."
Start-Sleep -Seconds 30
Restart-Computer
}
