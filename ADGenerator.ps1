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
$Global:Accounting = "Accounting"

#Domain Information
$Global:Domain = "";

function AddADGroup {
Write-Good "Creating Domain Groups"
New-ADGroup -name $Global:Senior -GroupScope Global
Write-Info "Adding $Global:Senior to $Global:domain"
New-ADGroup -name $Global:ITAdmins -GroupScope Global
Write-Info "Adding $Global:ITAdmins to $Global:domain"
New-ADGroup -name $Global:Engineering -GroupScope Global
Write-Info "Adding $Global:Engineering to $Global:domain"
New-ADGroup -name $Global:Sales -GroupScope Global
Write-Info "Adding $Global:Sales to $Global:domain"
New-ADGroup -name $Global:Accounting -GroupScope Global
Write-Info "Adding $Global:Accounting to $Global:domain"
}

function AddADUser {
Write-Good "Creating Domain Users"
$firstname = "Aaron"
$lastname = "Adams"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Summer2021!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
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
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:ITAdmins Group"
Add-ADGroupMember -Identity $Global:ITAdmins -Members $samAccountName
$firstname = "Jillian"
$lastname = "Anthony"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "H1dD3nV4ll3y!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
Write-Info "Adding $samAccountName to $Global:Engineering Group"
Add-ADGroupMember -Identity $Global:Engineering -Members $samAccountName
$firstname = "Tabitha"
$lastname = "Carter"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "AhArGuY5Nm7U3!@"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
$firstname = "Megan"
$lastname = "Phillips"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "L4k3LiV3L0ve!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
$firstname = "Richard"
$lastname = "Smith"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Baseball123!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
$firstname = "Samantha"
$lastname = "Chisholm"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "@!#AuVtBiMQpO123"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
$firstname = "Margaret"
$lastname = "Seitz"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Password123!"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
$firstname = "Aaron"
$lastname = "Tarolli"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "Phi11i35@44"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
$firstname = "Zane"
$lastname = "Dickens"
$fullname = "{0} {1}" -f ($firstname, $lastname)
$SamAccountName = ("{0}.{1}" -f ($firstname.Substring(0,1), $lastname)).ToLower()
$principalname = "{0}.{1}" -f ($firstname.Substring(0,1), $lastname)
$password = "M0t0rH3Ad65^$#"
New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
Write-Info "$samAccountName added"
}

function ASREPRoasting {
$asrepUser = "a.tarolli"	
Write-Good "Modifying pre-authentication privileges"
Set-ADAccountControl -Identity $asrepUser -DoesNotRequirePreAuth 1
Write-Info "ASREP privileges granted to $asrepUser"
}

function kerberoasting {
$svc = "mssql_svc"
$spn = "mssqlserver"
$kerb_pass = "Password123!"
Write-Good "Adding Kerberoastable service account to domain"
New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $kerb_pass -AsPlainText -Force)
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
AD-AddACL -Source $SourceGroup.sid -Destination $DestinationGroup.DistinguishedName -Rights "GenericAll"
Write-Info "$Global:ITAdmins group granted GenericAll permissions for the Domain Admins group."
Write-Good "Adding misconfigured ACL rule for the $Global:Engineering group."	
$DestinationGroup = Get-ADGroup -Identity $Global:Engineering
$SourceGroup = Get-ADGroup -Identity $Global:ITAdmins
AD-AddACL -Source $SourceGroup.sid -Destination $DestinationGroup.DistinguishedName -Rights "GenericAll"
Write-Info "GenericAll rights granted to $Global:Engineering group for $Global:ITAdmins."
Write-Good "Adding misconfigured ACL rule for Margaret Seitz to the $Global:Engineering group."
$vulnAclUser = Get-ADUser -Identity "m.seitz"
AD-AddACL -Source $SourceGroup.sid -Destination $vulnAclUser.DistinguishedName -Rights "ExtendedRight"
Write-Info "ExtendedRight granted to m.seitz for the $Global:Engineering group."
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
}
