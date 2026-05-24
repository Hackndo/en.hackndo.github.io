---
title: "Unconstrained Delegation - Risks"
date: 2019-04-12 11:28:42
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /unconstrained-delegation-attack/
disqus_identifier: 0000-0000-0000-00ac
cover: assets/uploads/2019/04/unconstrained_admin.png
description: "This article shows how to abuse Unconstrained Delegation in order to retrieve a user's TGT, allowing us to authenticate against any service on their behalf."
tags:
  - "Active Directory"
  - Windows
translation:
  fr: 
---

Following the article on [Kerberos delegation](/constrained-unconstrained-delegation), we are now going to see how to abuse Unconstrained Delegation in order to retrieve a user's TGT, allowing us to authenticate against any service on their behalf.

<!--more-->


## Reminder: Unconstrained Delegation

As we saw in the article on [Kerberos delegation](/constrained-unconstrained-delegation), when an account has the "Unconstrained Delegation" flag (`ADS_UF_TRUSTED_FOR_DELEGATION`), if the authentication information of the user requesting a TGS for a service offered by this account can be relayed, then the domain controller will respond to the user with a [KRB_TGS_REQ](/kerberos/#krb_tgs_req) containing the usual information such as the TGS, but it will also include in its response **a copy of the user's TGT**, as well as a new associated session key.

[![Unconstrained Delegation](/assets/uploads/2019/02/cop_tgt.png)](/assets/uploads/2019/02/cop_tgt.png)


Concretely, the service account that will receive this TGS **will also have a copy of the user's TGT**, as well as a valid session key to use this TGT.

## Exploitation

This means that now, with this information, the service can request any TGS on behalf of the user. I repeat: it can request **any. TGS. on behalf of the user**. It can impersonate the user to authenticate against any service.

[![Unconstrained Delegation](/assets/uploads/2019/02/unconstrained_delegation_schema.png)](/assets/uploads/2019/02/unconstrained_delegation_schema.png)


As a result, if the user in question has administrative rights for certain tasks, the service that now has a copy of this user's TGT also has administrative rights for these tasks. For example, in this diagram, a user is a local administrator on a domain controller. This user connects to the compromised server that is set to "Unconstrained Delegation".

[![Unconstrained Delegation](/assets/uploads/2019/04/unconstrained_admin.png)](/assets/uploads/2019/04/unconstrained_admin.png)

The attacker now has a copy of this user's TGT and can impersonate them against the domain controller, thus becoming a local administrator of it.

Therefore, accounts with Unconstrained Delegation are primary targets for attackers, since once one of these accounts is compromised, all that remains is to wait for user authentications in order to be able to authenticate anywhere on their behalf. If a domain administrator authenticates against a service offered by this account, then the attacker has won, the domain is fully compromised.

## By example

We are going to present an example here that was performed in my lab, ADSEC. There is the machine `WEB-SERVER-01` which is set to "Unconstrained Delegation".

[![Unconstrained Delegation](/assets/uploads/2019/04/server_01_unconstrained.png)](/assets/uploads/2019/04/server_01_unconstrained.png)


It is possible to authenticate against this machine to use its network shares. Let's imagine that an attacker has managed to compromise this machine, and that they are a local administrator on it.

The attacker must then wait for a privileged user to connect to the machine. They will therefore monitor connections and inspect TGSs to see if a TGT is present in any of them. To do this, they use the tool [Rubeus](https://github.com/GhostPack/Rubeus) developed by [@Harmj0y](https://twitter.com/harmj0y). (Other tools exist such as [kekeo](https://github.com/gentilkiwi/kekeo/) by [@gentilkiwi](https://twitter.com/gentilkiwi) for example.)

```
.\Rubeus monitor /interval:5
```

[![Rubeus Monitor](/assets/uploads/2019/04/wait_for_connexion.png)](/assets/uploads/2019/04/wait_for_connexion.png)

It just so happens that at some point, the `support-account` account, a **domain administrator**, needs to check something on the hard drive of `WEB-SERVER-01`. To do this, they connect to the server's network share `\\WEB-SERVER-01\c$`.

[![Connexion from DA](/assets/uploads/2019/04/connexion_from_domain_admin.png)](/assets/uploads/2019/04/connexion_from_domain_admin.png)

This connection is detected by Rubeus, since a [4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624) (Successful logon) event is generated in the event log of `WEB-SERVER-01`. Since this machine is in "Unconstrained Delegation", the TGS sent by the domain administrator contains a copy of their TGT, a copy that will be extracted by Rubeus.

[![Connexion success on Rubeus](/assets/uploads/2019/04/connexion_success.png)](/assets/uploads/2019/04/connexion_success.png)

Now in possession of a domain administrator's TGT (base64 encoded in this capture), the attacker can request a TGS to use the LDAP service of the domain controller `DC-01`. Rubeus allows us to make this request.

```
.\Rubeus.exe asktgs /ticket:<base64 ticket> /service:ldap/dc-01.adsec.local /ptt
```

[![Get LDAP TGS](/assets/uploads/2019/04/get_ldap_tgs.png)](/assets/uploads/2019/04/get_ldap_tgs.png)

Everything works as expected, we can verify the presence of the TGS in memory, for the `support-account` user (since the attacker used their TGT), and for the LDAP service of the domain controller.

[![Get LDAP TGS](/assets/uploads/2019/04/get_ldap_tgs_success.png)](/assets/uploads/2019/04/get_ldap_tgs_success.png)


With this TGS, it is possible to ask the domain controller to synchronize with the attacker. Here, the attacker only requested to synchronize the `krbtgt` account in order to create a "Golden Ticket".


[![DCSync](/assets/uploads/2019/04/dc_sync.png)](/assets/uploads/2019/04/dc_sync.png)

With the NT hash of the `krbtgt` account, the attacker can do anything on Active Directory.

## Conclusion

This demonstration shows the immense impact that the compromise of a machine set to "Unconstrained Delegation" can have. This is why these machines must be monitored, but above all should be set to [Constrained Delegation](/constrained-unconstrained-delegation/#kerberos-constrained-delegation---kcd) in order to control the services to which they can connect when delegating authentication. In addition, sensitive accounts should have the "Account is sensitive and cannot be delegated" option enabled, which was not the case in the previous example.

[![DCSync](/assets/uploads/2019/04/account_sensitive.png)](/assets/uploads/2019/04/account_sensitive.png)

If the option is enabled for this account, then the domain controller will know that no service is allowed to relay this user's authentication information. Thus, regarding Unconstrained Delegation, the domain controller will not include a copy of the TGT when the TGS is requested.

There will still be a 4624 event on the server, but no copy of the TGT will be available.

[![DCSync](/assets/uploads/2019/04/no_ticket.png)](/assets/uploads/2019/04/no_ticket.png)

I hope you enjoyed this article. If you have any comments or questions, feel free to ask them here or on [Discord](https://discord.hackndo.com){:target="blank"}. You can always follow new article releases on my twitter [@hackanddo](https://twitter.com/HackAndDo){:target="blank"}.
