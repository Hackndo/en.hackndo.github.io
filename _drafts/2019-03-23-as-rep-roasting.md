---
title: "AS_REP Roasting"
date: 2019-03-22 07:10:06
author: "Pixis"
layout: post
permalink: /kerberos-asrep-roasting/
redirect_from:
  - "/kerberos-asrep-toasting"
  - "/kerberos-asrep-toasting/"
disqus_identifier: 0000-0000-0000-00a8
cover: assets/uploads/2019/02/asreqroast_no_auth.png
description: "When asking for a TGT, by default, an user as to authenticate himself to the KDC in order to get a response. Sometimes, no authentication is asked before returning a TGT for specific account, allowing an attacker to abuse this configuration."
tags:
  - "Active Directory"
  - Windows
---
When asking for a TGT, by default, an user as to authenticate himself to the KDC in order to get a response. Sometimes, no authentication is asked before returning a TGT for specific account, allowing an attacker to abuse this configuration.

<!--more-->

## Preamble

When we talk about TGT it's often a language abuse, because you are talking about the [KRB_AS_REP](/kerberos/#krb_tgs_rep) which contain the TGT (encrypted by the KDC's secret) and the session key (encrypted with the user account secret).

So, in this article, the TGT notion will refer to the TGT contained in the [KRB_AS_REP](/kerberos/#krb_tgs_rep) response.

## Pre-authentication
When we talked about how [Kerberos works](https://beta.hackndo.com/kerberos), it was highlighted that during the first exchange ([KRB_AS_REQ](/kerberos/#krb_tgs_req) - [KRB_AS_REP](/kerberos/#krb_tgs_rep)), the client must first authenticate himself with the KDC, before obtaining a TGT. A part of the response of the KDC being encrypted with the client's account secret (the session key), it is important that this information is not accessible without previous authentication. Otherwise, anyone could ask for a TGT  for a given account, and try to decrypt the encrypted part of the response [KRB_AS_REP](/kerberos/#krb_tgs_rep) in order to recover the password of the targeted user.

[![KRB_AS_REP](/assets/uploads/2018/05/asrep.png)](/assets/uploads/2018/05/asrep.png)

That's why the user, in his [KRB_AS_REQ](/kerberos/#krb_tgs_req) request, must send an authenticator encrypted with his own secret in order for the KDC to decipher it and send back the [KRB_AS_REP](/kerberos/#krb_tgs_rep) if it is successful. If an attacker ask for a TGT with an account he does not have control over, he won't be able to encrypt the authenticator correctly, therefore the KDC will not return the desired information.

[![Authentication Required](/assets/uploads/2019/02/asreqroast_auth.png)](/assets/uploads/2019/02/asreqroast_auth.png)

This is the default behavior, it protects the accounts against this offline attack.

## KRB_AS_REP Roasting

However, for some strange reason (dark one though), it is possible to disable the pre-authentication prerequisite for one or more account(s).

[![Preauthentication Setting](/assets/uploads/2019/02/preauthsettings.png)](/assets/uploads/2019/02/preauthsettings.png)

For example in [this article](https://laurentschneider.com/wordpress/2014/01/the-long-long-route-to-kerberos.html), the author indicates that in order to benefit from SSO on a database hosted on a Unix server, he has to disable the pre-authentication for the user. It remains a very rare case, and even [cptjesus](https://twitter.com/cptjesus) and [Harmj0y](https://twitter.com/harmj0y) don't really have an answer.

> cptjesus > As far as why its disabled, I couldn't tell you

> Harmj0y > I honestly don’t really know why it would be disabled, just have heard from a people about the linux/“old” angle.

Anyway, if this option is disabled, anyone could ask for a TGT in the name of one of these accounts, without sending any authenticator, and the KDC will send back a [KRB_AS_REP](/kerberos/#krb_tgs_rep).

[![Authentication Required](/assets/uploads/2019/02/asreqroast_no_auth.png)](/assets/uploads/2019/02/asreqroast_no_auth.png)

This can be done with the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast) tool of [@Harmj0y](https://twitter.com/harmj0y).

[![ASREPRoast](/assets/uploads/2019/02/attackasrep.png)](/assets/uploads/2019/02/attackasrep.png)

Once in possession of the KDC response [KRB_AS_REP](/kerberos/#krb_tgs_rep), the attacker can try to find out the clear text of the victim's password  offline, by using John The Ripper with the `krb5tgs` mode for example.

## Conclusion

This technique, described in an [article](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) of [Harmj0y](https://twitter.com/harmj0y), is one of the many ways to retrieve a clear text password within an Active Directory environment. If any privileged accounts are set up so that they do not need a pre-authentication, an attacker could simply ask for a TGT for this account and try to recover offline the password of this account. With powerful machine, the cracking speed can be really huge. However, you should be aware that accounts without the necessary pre-authentication required are pretty rare. They can exist for historical reason, but [kerberoasting](/kerberoasting) is still more widespread.
