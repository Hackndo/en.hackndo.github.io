---
title: "Délégation Kerberos - Fonctionnement"
date: 2019-03-29 12:17:22
author: "Pixis"
layout: post
permalink: /constrained-unconstrained-delegation/
disqus_identifier: 0000-0000-0000-00ab
cover: assets/uploads/2019/02/impersonation.png
description: "Within an Active Directory, services can be used by users. Sometimes these services need to contact others, on behalf of the user, like a web service might need to contact a file server. In order to allow a service to access another service on behalf of the user, a solution has been implemented (introduced from Windows Server 2000) to meet this need : The Kerberos delegation."
tags:
  - "Active Directory"
  - Windows
---

Within an Active Directory, services can be used by users. Sometimes these services need to contact others, on behalf of the user, like a web service might need to contact a file server. In order to allow a service to access another service **on behalf of the user**, a solution has been implemented (introduced from Windows Server 2000) to meet this need : **The Kerberos delegation.**

<!--more-->

## Delegation principle

In order to understand the Kerberos delegation principle, let's take a concrete example. A machine hosts a Web service that, with a nice interface, allows a user to access his personal folder, hosted on a file server. We are in the following situation :

[![Actual state](/assets/uploads/2019/02/webfsuser.png)](/assets/uploads/2019/02/webfsuser.png)

The Web server is front-end, and it's this Web server that will fetch the information instead of the user on the file server in order to display the content of a file, for example.

However, the Web server does not know what belongs to the user on the file server. It is not his role to unpack the user's [PAC](/kerberos-silver-golden-tickets/#pac) to make a specific demand to the file server. This is where the **delegation**  comes in. This mechanism allows the Web server to take the user's place, and to authenticate on the user's behalf to the file server. Thus, from the file server's point of view, it is the user who make the request, and the file server will be able to check the rights of this user, then send back the information to which this account has access. This is how the Web server can then display this information in a nice interface.

[![Impersonation](/assets/uploads/2019/02/impersonation.png)](/assets/uploads/2019/02/impersonation.png)

## Constrained & Unconstrained Delegation

The ability to relay identifiers can be given to a machine or a service user, i.e. who has at least one [SPN](/service-principal-name-spn) attribute.

Today, there is three ways to authorize a machine or service account to take the place of a user to communicate with one or more other service(s) : The **Unconstrained Delegation**, the **Constrained Delegation** and the **Resource Based Constrained Delegation**.

### Kerberos Unconstrained Delegation - KUD

In the case of an **Unconstrained Delegation** (KUD), the server or the service account that is granted this right is able to pose as the user to communicate with **any services** on **any machine**.

It is historically the only choice there was when the delegation principle was introduced, but it has been completed by the principle of **Constrained Delegation**.

[![Unconstrained Delegation](/assets/uploads/2019/02/unconstrained_delegation_schema.png)](/assets/uploads/2019/02/unconstrained_delegation_schema.png)


Here is an example, in my lab, of a machine that is in **Unconstrained Delegation** :

[![Unconstrained Delegation](/assets/uploads/2019/02/unconstrained_delegation.png)](/assets/uploads/2019/02/unconstrained_delegation.png)

### Kerberos Constrained Delegation - KCD

If a machine or a service account got the **Constrained Delegation** (KCD) flag, a list of authorized services shall be associated to this right. For example, in the case of our Web server of the introduction, the machine hosting the Web server will have the **KCD** flag with the precision that this server can only relay the information to the `CIFS` service of the `SERVEUR01` server.

[![Constrained Delegation](/assets/uploads/2019/02/constrained_delegation_schema.png)](/assets/uploads/2019/02/constrained_delegation_schema.png)

So it's the server relaying the information of the user that own the information of the authorized ([SPN](/service-principal-name-spn)) services.

In other words, the front-end server will say "I'm allowed to authenticate as the user to this list of [SPN](/service-principal-name-spn) : [...]".

In my lab, the Web server is `WEB-SERVER-01` and the one with file sharing is `WEB-SERVER-02`. So here is what the list of services for which `WEB-SERVER-01` can pretend  to be the user looks like :

[![Delegation CIFS](/assets/uploads/2019/02/delegation_cifs.png)](/assets/uploads/2019/02/delegation_cifs.png)

**\<note\>**

As I understand it, the delegation status can only be applied to a machine or a service user (i.e. having at least one [SPN](/service-principal-name-spn) attribute).
- In the first case (Machine), that implies that **all** services hosted on the machine can relay the user information.
- In the second case (Service account), this means that regardless of the server on which the services executed by this service account are running, they -- these services -- will all have the ability to be delegated.

I find this behavior strange, I would have thought it was possible to decide that only a specific service on a specific machine could relay the user's information, but it seems to me, as it stands, that this granularity does not exist.

If my understanding is not correct, feel free to tell me in the comments or on [twitter](https://twitter.com/HackAndDo).

**\</note\>**

### Resource Based Kerberos Constrained Delegation - RBKCD

Finally, we have the **Resource Based Constrained Delegation** (RBKCD) case. Introduced with Windows Server 2012, this solution allows to overcome some problems related to the **KCD** (Responsibility, inter-domains delegation, ...). Without going into to much details, the delegation responsibility is moved. Whereas in **KCD**, it's at the delegating server level that the authorized [SPN](/service-principal-name-spn) are indicated, in the case of **RBKCD**, it's at the final services level that the list of services which can communicate with them by delegation are indicated. Thus, the diagram is as follows :

[![Resource Based Constrained Delegation](/assets/uploads/2019/02/resource_based_constrained_delegation_schema.png)](/assets/uploads/2019/02/resource_based_constrained_delegation_schema.png)

The responsibility is shifted, it's at the level of the server that receives the connections with delegation that the information of whether or not the delegation is accepted is found.

In other words, it's the end service that says "I allow this list of account [...] to authenticate to me on behalf of the user".

## Technical details

Now that the principle is understood (at least I hope so), let's go into a little more detail about this process. Concretely, how can a machine or an account can pretend to be a user with a service ? That's what we are going to see now. Details between every different techniques are relatively different, that's why each of them will be explained separately. Stay close on your seat, *it's gonna get dirty*.

### Kerberos Unconstrained Delegation - KUD

As we have seen it, in this case, the server or the service account can authenticate on behalf of the user to any other services. For this to be possible, two prerequisites are required :

* The first one is that the account that wants to delegate an authentication has the `ADS_UF_TRUSTED_FOR_DELEGATION` flag in [ADS_USER_FLAG_ENUM](https://docs.microsoft.com/en-us/windows/desktop/api/iads/ne-iads-ads_user_flag). In order to change this information, you need to have the `SeEnableDelegationPrivilege` right, which is usually only available for domain administrators. Here is how the flag is set on the account (machine or service account):

[![Unconstrained Delegation](/assets/uploads/2019/02/unconstrained_delegation.png)](/assets/uploads/2019/02/unconstrained_delegation.png)

* The second one is that the user account which will be relayed is effectively "relayable". To do this, you **must not** set the [ADS_UF_NOT_DELEGATED](https://docs.microsoft.com/en-us/windows/desktop/api/iads/ne-iads-ads_user_flag) flag. By default, no account on the AD has this flag set, so they are all "relayable".

Concretely, during exchanges with the domain controller as described in the [Kerberos in Active Directory](/kerberos) article, when the user ask for a TGS ([KRB_TGS_REQ](/kerberos/#krb_tgs_req)), he will specify the [SPN](/service-principal-name-spn) of the service he wants to use. It is at this point that the domain controller will look for the two prerequisites :

* Is the `ADS_UF_TRUSTED_FOR_DELEGATION` flag set in the attributes of the account associated to the [SPN](/service-principal-name-spn).
* Is the `ADS_UF_NOT_DELEGATED` flag **not** set for the requesting user.

If both prerequisites are met, then the domain controller will respond to the user with a [KRB_TGS_REQ](/kerberos/#krb_tgs_req) containing standard information, but it will also contains a **copy of the user's TGT** in his response, and a new associated session key.

[![TGT Copy](/assets/uploads/2019/02/cop_tgt.png)](/assets/uploads/2019/02/cop_tgt.png)

Once in possession of these elements, the user will continue the classic process by sending a request to the service ([KRB_AP_REQ](/kerberos/#krb_ap_req)) by sending the TGS and an authenticator. The service will be able to decrypt the content of the TGS, verify the user's identity by decrypting the authenticator, but above all it will be able to retrieve the copy of the TGT and the associated session key, in order to pretend to be the user at the domain controller.

[![TGT Memory](/assets/uploads/2019/02/tgt_memory.png)](/assets/uploads/2019/02/tgt_memory.png)

Now in possession of a copy of the user's TGT and a valid session key, the service can authenticate to any other service on the user's behalf by requesting the TGS from the domain controller, by providing this TGT and by encrypting an authenticator with the session key. It's the **Unconstrained Delegation** principle.

Here is a summary diagram :

[![Unconstrained Delegation Detailed](/assets/uploads/2019/02/unconstrained_delegation_detailed.png)](/assets/uploads/2019/02/unconstrained_delegation_detailed.png)


### Kerberos Constrained Delegation

For the **Constrained Delegation**, a list of [SPN](/service-principal-name-spn) or of authorized accounts will be provided to indicate the services/accounts accepted for the delegation. Therefore, the process is not the same. The service involved will not be in possession of the user's TGT, otherwise there is no way to control service's authentication. A different mechanism is used.

Let's consider the case where the user authenticate to `Service A` and then this `Service A` has to authenticate himself to `Service B` as the user.

The user makes a TGS request, then send it to `Service A`. Since this service needs to authenticate as the user to `Service B`, it will request a TGS to the KDC on behalf of the user. This request is governed by the [S4U2Proxy](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a) extension. To tell the domain controller it wants to authenticate on behalf of someone else, two attributes will be defined in the ticket request [KRB_TGS_REQ](/kerberos/#krb_tgs_req) :

* The field `additional-tickets`, usually empty, must contain the user's TGS (given that the `ADS_UF_NOT_DELEGATED` flag is **not** set for the requesting user. If that was the case, the user's TGS would not be `forwardable`, and the domain controller would not accept it in the rest of the processes)
* The [cname-in-addl-tkt](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/17b9af82-d45a-437d-a05c-79547fe969f5) flag, which should be set to indicate to the DC that it should not use the server information, but the ticket information in `additional-tickets`, i.e. the information of the user the server wants to pretend to be.

It is during this request that the domain controller, upon seeing this information, will verify that `Service A` has the right to authenticate to `Service B` on behalf of the user.

#### Constrained Delegation - Classique

In the classic **Constrained Delegation** case (so when the information is located in `Service A`), this information is found in the [msDS-AllowedToDelegateTo](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/86261ca1-154c-41fb-8e5f-c6446e77daaa) attribute **of the requesting object (account)**, thus of `Service A`, this attribute specifies the list of authorized [SPN](/service-principal-name-spn) for the delegation. For example here the `msDS-AllowedToDelegateTo` attribute will contain `cifs/WEB-SERVER-02`.

[![Delegation CIFS](/assets/uploads/2019/02/delegation_cifs.png)](/assets/uploads/2019/02/delegation_cifs.png)

If the targeted [SPN](/service-principal-name-spn) is present, then the KDC send back a valid TGS, with the name of the user, for the requested service. Here is a summary diagram :

[![Constrained Delegation Detailed](/assets/uploads/2019/02/constrained_delegation_schema_detailed.png)](/assets/uploads/2019/02/constrained_delegation_schema_detailed.png)


#### Constrained Delegation - Resource Based

This time, the KDC will look at the attributes of **Service B** (instead of `Service A`). It will check that the account associated with `Service A` is present in the [msDS-AllowedToActOnBehalfOfOtherIdentity](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/cea4ac11-a4b2-4f2d-84cc-aebb4a4ad405) attribute of the account linked to `Service B`.

[![Resource Based Constrained Delegation Detailed](/assets/uploads/2019/02/resource_based_constrained_delegation_schema_detailed.png)](/assets/uploads/2019/02/resource_based_constrained_delegation_schema_detailed.png)

As the diagram shows, the technical functioning is similar, however the responsibilities of each entity is radically different.

### Extension S4U2Self

If you are still there and you are not lost, you should have noticed that we haven't touched on the notion of protocol transition in this article. Indeed, in the explanation of constrained delegation, we assumed that `Service A` had a service ticket coming from `USER`, which was added in the `additional-tickets` field of the TGS request (**S4U2Proxy**). But sometimes the user may authenticate to the server in other ways than the Kerberos protocol (e.g. via NTLM, or even a Web form). In this case, the server is not in possession of the TGS sent by the user. Thus, `Service A` cannot fill the `additional-tickets` field as it did in the case described above.

That is why there is an extra step, possible through the [S4U2Self](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13) extension, that `Service A` must perform. This step allows it to obtain a TGS for a user **arbitrarily chose**. To do this, it makes a classic TGS request ([KRB_TGS_REQ](/kerberos/#krb_tgs_req)) except that instead of putting his own name in the `PA-FOR-USER` block (present in the pre-authentication part), it puts the name of a user **it chooses**.

Obviously, one would think that this is a very powerful and dangerous capability since in fact, for any services `S` and `T` for which there is a possible delegation from `S` to `T`, the `Service S` could pretend to be any user to `Service T`. Fortunately, this is not the case. Indeed, if the [ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION](https://docs.microsoft.com/en-us/windows/desktop/api/iads/ne-iads-ads_user_flag) is not set on the `Service S`'s associated object, then the ticket it retrieves is not *forwadable* and cannot be used for a classic constrained delegation. There is a special case for the Resource-Based Delegation, which we will discuss in another article.

In order for the account to have this flag set, it must be specified here in the GUI :

[![Drapeau S4U2Self](/assets/uploads/2019/02/s4u2self_gui.png)](/assets/uploads/2019/02/s4u2self_gui.png)

Be careful, the summary diagram is getting more complicated, but I hope it remains more or less clear.

[![S4U2Self](/assets/uploads/2019/02/s4u2self.png)](/assets/uploads/2019/02/s4u2self.png)

From experience, it is rare to find accounts within a domain that have this flag. However, if such account is compromised, then all services to which that account is entitled to authenticate via delegation will also be compromised, since the attacker can create service tickets on behalf of arbitrary users, such as administrators users of targeted services.

## Conclusion

I was thinking of doing an article that would describe the principle of Constrained and Unconstrained Delegation as well as associated attacks, however the explanations are much more dense than expected, so this article remains devoted to explanation. Associated attacks will be presented in other articles, which I will quote here, as they come out.

* [Unconstrained Delegation - Risks](/unconstrained-delegation-attack)

* [Resource-Based Constrained Delegation - Risks](/resource-based-constrained-delegation-attack)

If you have any questions or suggestions, do not hesitate, I'm all ears.

## Resources

Big thanks to them for their clear explanations.

* [S4U2Pwnage - Harmj0y](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
* [ADSecurity - Pyrotek3](http://adsecurity.org/)
* [Secrets d’authentification épisode II Kerberos contre-attaque - Aurélien Bordes](https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets_dauthentification_pisode_ii__kerberos_cont/SSTIC2014-Article-secrets_dauthentification_pisode_ii__kerberos_contre-attaque-bordes_2.pdf)
* [Wagging the dog - Edla Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
