# AWS-RedTeam-ADLab

## Summary

This lab consists of 3 servers across 2 domains. It includes almost all pure AD attacks that I have exploited. The only edges in Bloodhound it doesnt yet have are LAPS and GMSA I believe. 

Once the setup steps are done you can just launch the lab using `terraform apply` and it will do it all for you. After applying you will need to give the lab about 35 mins. When you apply it will complete and tell you a timestamp. Take that timestamp, add 35 minutes onto it and wait that time. That will give it the time it needs to do all the setup. After 35 mins it will be good to go.

My blog post giving detailed setup information is here: https://philkeeble.com/automation/windows/activedirectory/AWS-RedTeam-ADLab-Setup/

## Attacks Covered 

* Kerberoasting
* ASRepRoasting
* Constrained Delegation (computer and user)
* Unconstrained Delegation 
* Resource Based Constrained Delegation
* Write ACL of user 
* Write ACL of computer
* WriteDACL over domain 
* Write ACL of group
* DnsAdmin members
* Write ACL of GPO
* Password in AD Attributes
* Cross domain trusts 
* SMBSigning disabled on all machines for relay attacks 
* Defender uninstalled so no need to worry about AV 
* Multiple machines so you can practise tunneling, double hop problem, etc
* All the default things like lateral movement, persistence, pass the hash, pass the ticket, golden tickets, silver tickets etc

## Machine Summary 

* First-DC = Domain Controller of the domain first.local (10.0.1.100)
* Second-DC = Domain Controller of the domain second.local (in a trust with first) (10.0.2.100)
* User-Server = Server to be the foothold on. Any domain user can RDP to this box (10.0.1.50)
* Attack-Server = Debian server set up with Covenent and Impacket for you to jump in and attack from (10.0.1.10)

## Setup
```
Terraform
Install terraform
Install aws cli
set up creds in aws cli 

DSC
Install-module -name activedirectorydsc
install-module -name networkingdsc 
install-module -name ComputerManagementDsc
install-module -name GroupPolicyDsc
With these you can use ". .\adlab.ps1" to make the MOF files 

S3
Create an S3 bucket for your account and replace the variable in terraform/vars.tf with your bucket name

Management IP 
Change the management IP variable in vars.tf to be your IP

Keys
Create an EC2 key pair, get public key from the pem with ssh-keygen -y -f /key.pem
Store the file ./terraform/keys/terraform-key.pub 
Update the file in the vars.tf to point to that public key (which will assign it to the created EC2 instances)
Can use this key pair to get the administrator default password from AWS

When its launched give it like half and hour and it should set up properly 
```

Debugging 
```
Logs are kept here C:\Windows\System32\Configuration\ConfigurationStatus on the targets for DSC 

The folder is owned by trusted installer so need to change owners to read or be system
```

Linux
```
Attack server has covenant and impacket on

port forward 7443
cd Covenant/Covenant 
sudo dotnet run
access in browser on localhost


For impackt you can run python3 psexec.py ... etc 
```
# Credits 

Massive credit to XPN with this project https://github.com/xpn/DemoLab. Almost all of the code I used is from this project and its blog post https://www.mdsec.co.uk/2020/04/designing-the-adversary-simulation-lab/. 

I have just taken that, made it less mass-spinup focused and added the vulnerabilties I would want in an AD lab. 
