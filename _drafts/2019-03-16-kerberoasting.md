---
title: "Kerberoasting"
date: 2019-03-15 08:02:44
author: "Pixis"
layout: post
permalink: /kerberoasting/
disqus_identifier: 0000-0000-0000-00aa
cover: assets/uploads/2019/02/kerberoasting.png
description: "With the help of previously discussed notions, we have everything in hand to explain the Kerberoasting attack principle, based on the TGS request and the SPN attributes of Active Directory accounts."
tags:
  - "Active Directory"
  - Windows
---

With the help of previously discussed notions, we have everything in hand to explain the **Kerberoasting** attack principle, based on the TGS request and the [SPN](/service-principal-name-spn) attributes of Active Directory accounts.

<!--more-->

## Principle

The article on how [kerberos works](/kerberos) helped to understand how a user requests a TGS from the domain controller. The [KRB_TGS_REP](/kerberos/#krb_tgs_rep) response is composed of two parts. The first part is the TGS whose content is encrypted with the secret of the requested service, and the second part is a session key which will be used between the user and the service. The whole is encrypted using the user's secret.

[![Ticket for the service](/assets/uploads/2018/05/tgsrep.png)](/assets/uploads/2018/05/tgsrep.png)

An Active Directory user can ask for a TGS for any service to the KDC. Indeed, it is not the role of the KDC to verify the rights of the requester. The only purpose of the KDC is to provide security information related to a user (via the [PAC](/kerberos-silver-golden-tickets/#pac)). It is the service who must verify the rights of the user by reading his PAC, a copy of which is provided in the TGS.

For example, TGS request can be made by specifying arbitrary [SPN](/service-principal-name-spn), if those [SPN](/service-principal-name-spn) are registered in the Active Directory, the KDC will provide a piece of information encrypted with the secret key of the account executing the service. With this information, the attacker can now try to recover the account's plaintext password via a brute-force attack.

Fortunately, most of the accounts that runs services are machine accounts (in the form `MACHINENAME$`) and their password are very long and completely random,so they're not really vulnerable to this type of attack. However, there are some services executed by accounts whose password have been chosen by a humans. It is those accounts that are much simpler to compromise  via brute-force attack, so it is those accounts which will be targeted by a **Kerberoast** attack.

In order to list those accounts, a LDAP filter can be used to extract user-type accounts with a non-empty `servicePrincipalName`. This filter is as follow :

```
&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)
```

Here is a simple PowerShell script allowing you to retrieve users with at least one [SPN](/service-principal-name-spn) :

```powershell
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$results = $search.Findall()
foreach($result in $results)
{
	$userEntry = $result.GetDirectoryEntry()
	Write-host "User : " $userEntry.name "(" $userEntry.distinguishedName ")"
	Write-host "SPNs"        
	foreach($SPN in $userEntry.servicePrincipalName)
	{
		$SPN       
	}
	Write-host ""
}
```

In the lab, a fake [SPN](/service-principal-name-spn) as been placed on the user "support account".

[![SPN on User](/assets/uploads/2019/03/SPNOnUser.png)](/assets/uploads/2019/03/SPNOnUser.png)

Thus, during our LDAP search, here is what we get :

[![SPN MapListpings](/assets/uploads/2019/03/SPNListUsersPowershell.png)](/assets/uploads/2019/03/SPNListUsersPowershell.png)

Of course, there is several tools to automate this task. I will mention here the tool [Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) by [@Harmj0y](https://twitter.com/harmj0y), which takes care of listing user accounts with one or more [SPN](/service-principal-name-spn), request some TGS for those accounts and extract the encrypted part in a format that can be cracked (by John for example).

```
Invoke-Kerberoast -domain adsec.local | Export-CSV -NoTypeInformation output.csv
john --session=Kerberoasting output.csv
```

We then hope to find password, which depends on the company's password policy for these accounts.

## Protection

To protect ourselves against this attack, we must avoid having [SPN](/service-principal-name-spn) on user accounts, in favor of machine accounts.

If it really is necessary, then we should use Microsoft's "Managed Service Accounts" (MSA) feature , which ensures that the account password is robust and changed regularly and automatically. To do so, simply add a service account (only via PowerShell) :

```powershell
New-ADServiceAccount sql-service
```

Then it has to be installed on the machine :

```powershell
Install-ADServiceAccount sql-service
```

Finally, this user must be assigned to the service.

[![Service account assignation](/assets/uploads/2019/02/set-account-service.png)](/assets/uploads/2019/02/set-account-service.png)

## Conclusion

The Kerberoast attack allow us to retrieve new accounts within an Active Directory for a lateral movement attempt. The compromised accounts can have higher privileges, which is sometimes the case on the machine hosting the service. It is then important from a defensive point of view to control the [SPN](/service-principal-name-spn) attribute of domain accounts to prevent accounts with weak password from being vulnerable to this attack.
