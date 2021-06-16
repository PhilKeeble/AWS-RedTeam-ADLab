configuration Lab {

    param
    (
        [Parameter(Mandatory)]
        [pscredential]$safemodeAdministratorCred,
        [Parameter(Mandatory)]
        [pscredential]$domainCred,
        [Parameter(Mandatory)]
        [string]$firstDomainName,
        [Parameter(Mandatory)]
        [string]$secondDomainName,
        [Parameter(Mandatory)]
        [pscredential]$firstDomainCred
    )

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node "First" {

        Computer NewName {
            Name = "First-DC"
        }
        
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        WindowsFeature ADDSTools {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }

        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }

        ADDomain CreateDC {
            DomainName = $firstDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1', '10.0.2.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }

            TestScript = {
                $zone = Get-DnsServerZone -Name $using:secondDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }

            SetScript = {
                $ForwardDomainName = $using:secondDomainName
                $IpAddresses = @("10.0.2.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }

            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADGroup DomainAdmin {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'regular.user'
        {
            Ensure     = 'Present'
            UserName   = 'regular.user'
            Password   = (New-Object System.Management.Automation.PSCredential("regular.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'dnsadmin.user'
        {
            Ensure     = 'Present'
            UserName   = 'dnsadmin.user'
            Password   = (New-Object System.Management.Automation.PSCredential("dnsadmin.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADGroup DnsAdmin {
            Ensure = "Present"
            GroupName = "DnsAdmins"
            MembersToInclude = "dnsadmin.user"
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]dnsadmin.user"
        }

        ADUser 'unconstrained.user'
        {
            Ensure     = 'Present'
            UserName   = 'unconstrained.user'
            Password   = (New-Object System.Management.Automation.PSCredential("unconstrained.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "unconstrained.user Unconstrained Delegation Set"
        {
            SetScript = {
                Set-ADAccountControl -Identity "unconstrained.user" -TrustedForDelegation $True
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "unconstrained.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]unconstrained.user"
        }

        ADUser 'constrained.user' 
        {
            Ensure     = 'Present'
            UserName   = 'constrained.user'
            Password   = (New-Object System.Management.Automation.PSCredential("constrained.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "constrained.user constrained Delegation Set"
        {
            SetScript = {
                $user = (Get-ADUser -Identity "constrained.user").DistinguishedName
                Set-ADObject -Identity $user -Add @{"msDS-AllowedToDelegateTo" = @("CIFS/First-DC","CIFS/First-DC.First.local","CIFS/First-DC.first.local/first.local")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "constrained.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]constrained.user"
        }

        ADComputer "Constrained.Computer" 
        {
            Ensure = "Present"
            ComputerName = "Suspicious-PC"
            Path = "CN=Computers,DC=first,DC=local"
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "Suspicious-PC constrained Delegation Set"
        {
            SetScript = {
                $comp = (Get-ADComputer -Identity "Suspicious-PC").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HTTP/First-DC","HTTP/First-DC.First.local","HTTP/First-DC.first.local/first.local")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "Suspicious-PC" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'userwrite.user'
        {
            Ensure     = 'Present'
            UserName   = 'userwrite.user'
            Password   = (New-Object System.Management.Automation.PSCredential("userwrite.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "userwrite.user Write Permissions on User Node"
        {
            SetScript = {
                $Destination = (Get-ADUser -Identity "constrained.user").DistinguishedName
                $Source = (Get-ADUser -Identity "userwrite.user").sid
                $Rights = "GenericWrite"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "userwrite.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]userwrite.user"
        }

        ADUser 'userall.user'
        {
            Ensure     = 'Present'
            UserName   = 'userall.user'
            Password   = (New-Object System.Management.Automation.PSCredential("userall.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "userall.user GenericAll Permissions on User Node"
        {
            SetScript = {
                $Destination = (Get-ADUser -Identity "userwrite.user").DistinguishedName
                $Source = (Get-ADUser -Identity "userall.user").sid
                $Rights = "GenericAll"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "userall.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]userall.user"
        }

        ADUser 'compwrite.user'
        {
            Ensure     = 'Present'
            UserName   = 'compwrite.user'
            Password   = (New-Object System.Management.Automation.PSCredential("compwrite.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "compwrite.user Write Permissions on Comp Node"
        {
            SetScript = {
                $Destination = (Get-ADComputer -Identity "First-DC").DistinguishedName
                $Source = (Get-ADUser -Identity "compwrite.user").sid
                $Rights = "GenericWrite"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "compwrite.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]compwrite.user"
        }

        ADUser "gpowrite.user"
        {
            Ensure     = 'Present'
            UserName   = 'gpowrite.user'
            Password   = (New-Object System.Management.Automation.PSCredential("gpowrite.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "gpowrite.user Write Permissions on GPO"
        {
            SetScript = {
                Set-GPPermission -Name "Default Domain Controllers Policy" -TargetName "gpowrite.user" -TargetType "User" -PermissionLevel "GpoEdit"
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "gpowrite.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]gpowrite.user"
        }

        ADUser 'lapsread.user'
        {
            Ensure     = 'Present'
            UserName   = 'lapsread.user'
            Password   = (New-Object System.Management.Automation.PSCredential("lapsread.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            Description = 'LAPS yet to be implemented'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'groupwrite.user'
        {
            Ensure     = 'Present'
            UserName   = 'groupwrite.user'
            Password   = (New-Object System.Management.Automation.PSCredential("groupwrite.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "groupwrite.user Write Permissions on Group"
        {
            SetScript = {
                $Destination = (Get-ADGroup -Identity "Domain Admins").DistinguishedName
                $Source = (Get-ADUser -Identity "groupwrite.user").sid
                $Rights = "GenericAll"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "groupwrite.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]groupwrite.user"
        }

        ADUser 'writedacldc.user'
        {
            Ensure     = 'Present'
            UserName   = 'writedacldc.user'
            Password   = (New-Object System.Management.Automation.PSCredential("writedacldc.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "writedacldc.user WriteDACL Permissions on DC"
        {
            SetScript = {
                $Destination = (Get-ADComputer -Identity "First-DC").DistinguishedName
                $Source = (Get-ADUser -Identity "writedacldc.user").sid
                $Rights = "WriteDACL"
                $ADObject = [ADSI]("LDAP://" + $Destination)
                $identity = $Source
                $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
                $type = [System.Security.AccessControl.AccessControlType] "Allow"
                $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
                $ADObject.psbase.commitchanges()
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "writedacldc.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]writedacldc.user"
        }

        ADUser 'readgmsa.user'
        {
            Ensure     = 'Present'
            UserName   = 'readgmsa.user'
            Password   = (New-Object System.Management.Automation.PSCredential("readgmsa.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            Description = 'GMSA yet to be implemented'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser 'clearpass.user'
        {
            Ensure     = 'Present'
            UserName   = 'clearpass.user'
            Password   = (New-Object System.Management.Automation.PSCredential("clearpass.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "clearpass.user Password in AD"
        {
            SetScript = {
                Set-ADUser -Identity "clearpass.user" -Description "Remember to remove this! Password@1"
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "clearpass.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]clearpass.user"
        }

        ADUser 'roast.user'
        {
            Ensure     = 'Present'
            UserName   = 'roast.user'
            Password   = (New-Object System.Management.Automation.PSCredential("roast.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            ServicePrincipalNames = "MSSQL/sql.first.local"
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        ADUser asrep
        {
            Ensure     = 'Present'
            UserName   = 'asrep.user'
            Password   = (New-Object System.Management.Automation.PSCredential("asrep.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'first.local'
            Path       = 'CN=Users,DC=first,DC=local'
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "asrep.user PreAuth Disable"
        {
            SetScript = {
                Set-ADAccountControl -Identity "asrep.user" -DoesNotRequirePreAuth $true
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADUser "asrep.user" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain", "[ADUser]asrep"
        }

        Script "User-Server-RDP"
        {
            SetScript = {
                Start-Sleep -Seconds 300
                Invoke-Command -ComputerName "User-Server" -Scriptblock {net localgroup "Remote Desktop Users" "first\domain users" /add}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "User-Server" ) } 
            }
            PsDscRunAsCredential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script "User-Server constrained Delegation Set"
        {
            SetScript = {
                $comp = (Get-ADComputer -Identity "User-Server").DistinguishedName
                Set-ADObject -Identity $comp -Add @{"msDS-AllowedToDelegateTo" = @("HOST/First-DC","HOST/First-DC.First.local","HOST/First-DC.first.local/first.local")}
            }
            TestScript = { 
                $false 
            }
            GetScript = { 
                @{ Result = (Get-ADComputer "User-Server" ) } 
            }
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }

        Script DisableSMBSign 
        {
            GetScript = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        Script DisableDefender
        {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }

            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }

            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
                $global:DSCMachineStatus = 1
            }
        }
    }

    Node "UserServer" {
        
        WaitForAll DC
        {
            ResourceName      = '[ADUser]asrep'
            NodeName          = 'First-DC'
            RetryIntervalSec  = 60
            RetryCount        = 15
        }
        
        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }
        
        User localuser {
            Ensure = "Present"
            UserName = "local-user"
            Password = $DomainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = "local-user"
            DependsOn = "[User]localuser"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn      = "[Group]Administrators"
        }

        Script DisableDefender
        {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }

            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }

            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
            }
        }

        Script DisableSMBSign 
        {
            GetScript = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            WaitForValidCredentials = $true
            WaitTimeout = 300
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        Computer JoinDomain {
            Name = "User-Server"
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            DependsOn = "[WaitForADDomain]waitFirstDomain"
        }
    }

    Node "Second" {

        Computer NewName {
            Name = "Second-DC"
        }
        
        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        WindowsFeature ADDSTools {
            Ensure = "Present"
            Name = "RSAT-ADDS"
        }

        FirewallProfile DisablePublic {
            Enabled = "False"
            Name   = "Public"
        }
        
        FirewallProfile DisablePrivate {
            Enabled = "False"
            Name   = "Private"
        }
        
        FirewallProfile DisableDomain {
            Enabled = "False"
            Name   = "Domain"
        }

        User AdminUser {
            Ensure = "Present"
            UserName = $domainCred.UserName
            Password = $domainCred
        }

        Group Administrators {
            GroupName = "Administrators"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[User]AdminUser"
        }
        
        ADDomain CreateDC {
            DomainName = $secondDomainName
            Credential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DatabasePath = 'C:\NTDS'
            LogPath = 'C:\NTDS'
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WaitForADDomain waitSecondDomain {
            DomainName = $secondDomainName
            DependsOn = "[ADDomain]CreateDC"
        }

        DnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1', '10.0.1.100'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $false
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        Script SetConditionalForwardedZone {
            GetScript = { return @{ } }

            TestScript = {
                $zone = Get-DnsServerZone -Name $using:firstDomainName -ErrorAction SilentlyContinue
                if ($zone -ne $null -and $zone.ZoneType -eq 'Forwarder') {
                    return $true
                }

                return $false
            }

            SetScript = {
                $ForwardDomainName = $using:firstDomainName
                $IpAddresses = @("10.0.1.100")
                Add-DnsServerConditionalForwarderZone -Name "$ForwardDomainName" -ReplicationScope "Domain" -MasterServers $IpAddresses
            }
        }

        ADGroup DomainAdmin {
            Ensure = "Present"
            GroupName = "Domain Admins"
            MembersToInclude = $domainCred.UserName
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'regular.user'
        {
            Ensure     = 'Present'
            UserName   = 'regular.user'
            Password   = (New-Object System.Management.Automation.PSCredential("regular.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'second.local'
            Path       = 'CN=Users,DC=second,DC=local'
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'roast.user'
        {
            Ensure     = 'Present'
            UserName   = 'roast.user'
            Password   = (New-Object System.Management.Automation.PSCredential("roast.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'second.local'
            Path       = 'CN=Users,DC=second,DC=local'
            ServicePrincipalNames = "MSSQL/sql.second.local"
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        ADUser 'asrep.user'
        {
            Ensure     = 'Present'
            UserName   = 'asrep.user'
            Password   = (New-Object System.Management.Automation.PSCredential("asrep.user", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force)))
            DomainName = 'second.local'
            Path       = 'CN=Users,DC=second,DC=local'
            DependsOn = "[WaitForADDomain]waitSecondDomain"
        }

        WaitForADDomain waitFirstDomain {
            DomainName = $firstDomainName
            Credential = $firstDomainCred
            WaitTimeout = 600
            RestartCount = 2
            DependsOn = "[Script]SetConditionalForwardedZone"
        }

        ADDomainTrust DomainTrust {
            TargetDomainName = $firstDomainName
            TargetCredential = $firstDomainCred
            TrustType = "External"
            TrustDirection = "Bidirectional"
            SourceDomainName = $secondDomainName
            DependsOn = "[WaitForADDomain]waitFirstDomain"
            Ensure = "Present"
        }

        Script DisableSMBSign 
        {
            GetScript = { 
                return @{ } 
            }

            TestScript = {
                $false
            }

            SetScript = {
                Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
            }
        }

        Script DisableDefender
        {
            GetScript = { 
                return @{ Result = (Get-Content C:\Windows\Temp\DefenderDisable.txt) } 
            }

            TestScript = {
                Test-Path "C:\Windows\Temp\DefenderDisable.txt"
            }

            SetScript = {
                Uninstall-WindowsFeature -Name Windows-Defender
                $sw = New-Object System.IO.StreamWriter("C:\Windows\Temp\DefenderDisable.txt")
                $sw.WriteLine("Defender has been uninstalled")
                $sw.Close()
                $global:DSCMachineStatus = 1
            }
        }
    }
}

$ConfigData = @{
    AllNodes = @(
        @{
            Nodename                    = "First"
            Role                        = "First DC"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        },
        @{
            Nodename                    = "UserServer"
            Role                        = "User Server"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
            PsDscAllowDomainUser        = $true
        },
        @{
            Nodename                    = "Second"
            Role                        = "Second DC"
            RetryCount                  = 0
            RetryIntervalSec            = 0
            PsDscAllowPlainTextPassword = $true
        }
    )
}

Lab -ConfigurationData $ConfigData `
    -firstDomainName "first.local" `
    -secondDomainName "second.local" `
    -domainCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -safemodeAdministratorCred (New-Object System.Management.Automation.PSCredential("admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) `
    -firstDomainCred (New-Object System.Management.Automation.PSCredential("first-admin", (ConvertTo-SecureString "DoesntMatter" -AsPlainText -Force))) 

