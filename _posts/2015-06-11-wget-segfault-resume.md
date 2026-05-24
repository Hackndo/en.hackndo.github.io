---
title: 'wget - segfault: Summary'
date: 2015-06-11
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /wget-segfault-resume/
disqus_identifier: 0000-0000-0000-0007
description: "A segfault in wget? Technical analysis of the why and how to propose a patch!"
cover: assets/uploads/2015/06/WGETSEGFAULT.jpg
tags:
  - "User Land"
  - Linux
translation:
  fr: 
---
Hi everyone, **winw** recently showed me something pretty cool. In a terminal, type the command

```bash
$ wget -r %3a
Segmentation fault
```

You'll get a segfault.

<!--more-->

This is all the more interesting since wget is a very widely used binary. Bugs like this are rare! We then wondered what we could do with it, and whether we could fix it. So we didn't stop there, and we looked for the cause of the problem.

## Debug environment

For that, we armed ourselves with the trusty old gdb, as well as the sources of the latest version of wget (1.16.3) available here:

<http://ftp.gnu.org/gnu/wget/wget-1.16.3.tar.gz>

First, we recompiled the binary to have a non-stripped version and thus have access to the symbols. In the wget sources folder:

```bash
$ ./configure --user-prefix=/home/hackndo/wget
$ make && sudo make install
```

## Reproducing the bug

Next we triggered the segfault in gdb and displayed the backtrace to find where the problem is:

```bash
gdb$ r -r %3a
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
-----------------------------------------------------------------------------------------------------------------------[regs]
RAX: 0x0000000000000006  RBX: 0x0000000000000000  RBP: 0x000000000065FFE0  RSP: 0x00007FFFFFFFDF10  o d I t s z a p c
RDI: 0x00000000FFFFFFFF  RSI: 0x00007FFFF7FF7000  RDX: 0x00007FFFF799CDF0  RCX: 0x00007FFFF76E59D0  RIP: 0x0000000000421ADB
R8 : 0x00007FFFF7FF7001  R9 : 0x00007FFFF7FE9700  R10: 0x0000000000000000  R11: 0x0000000000000246  R12: 0x000000000065FFB0
R13: 0x000000000065F950  R14: 0x00007FFFFFFFE05A  R15: 0x00007FFFFFFFE060
CS: 0033  DS: 0000  ES: 0000  FS: 0000  GS: 0000  SS: 002B
-----------------------------------------------------------------------------------------------------------------------
```

## Finding the cause

```bash
=> 0x421adb <getproxy+27>:  mov    esi,DWORD PTR [rbx+0x18]
   0x421ade <getproxy+30>:  mov    edi,0x44af12
   0x421ae3 <getproxy+35>:  xor    eax,eax
   0x421ae5 <getproxy+37>:  call   0x402f10 <printf@plt>
   0x421aea <getproxy+42>:  mov    rdi,QWORD PTR [rip+0x23b2bf]        # 0x65cdb0 <opt+304>
   0x421af1 <getproxy+49>:  mov    rsi,QWORD PTR [rbx+0x10]
   0x421af5 <getproxy+53>:  test   rdi,rdi
   0x421af8 <getproxy+56>:  je     0x421b03 <getproxy+67>
-----------------------------------------------------------------------------------------------------------------------------
0x0000000000421adb in getproxy ()
gdb$ bt
#0  0x0000000000421adb in getproxy ()
#1  0x00000000004226fa in retrieve_url ()
#2  0x00000000004204a0 in retrieve_tree ()
#3  0x0000000000404168 in main ()
```

The segfault occurs in the `getproxy` function located in **retr.c**:

```c
getproxy (struct url *u)
```

After some research, we notice that the `u` pointer to a `url` structure is a null pointer, and therefore at the line:

```c
if (no_proxy_match (u->host, (const char **)opt.no_proxy))
```

the attempt to access the `host` field of the structure causes the segfault.

Great, we have isolated the cause of the segfault. However, how is it that the `u` pointer passed to `getproxy` is null? Let's go back up the backtrace a bit.
  
In `retrieve_url`, still in the same file:

```c
uerr_t retrieve_url (struct url * orig_parsed, const char *origurl, char **file,
char **newloc, const char *refurl, int *dt, bool recursive,
struct iri *iri, bool register_status)
```

We see the call to `getproxy`:

```c
proxy = getproxy (u);
```

And we see above that `u` is defined like this:

```c
struct url *u = orig_parsed
```

By placing a breakpoint at the entry of the `retrieve_url` function, we realize that the `orig_parsed` parameter is already a null pointer. We continue and go one more level up the backtrace, to look at the `retrieve_tree` function located in the file `recur.c`:

```c
uerr_t retrieve_tree (struct url *start_url_parsed, struct iri *pi)
```

We see the call to the `retrieve_url` function here:

```c
status = retrieve_url (url_parsed, url, &file, &redirected, referer,
&dt, false, i, true);
```

We said that the `url_parsed` parameter was null. This pointer is defined one line above:

```c
struct url *url_parsed = url_parse (url, &url_err, i, true);
```

This time, none of the parameters passed to `url_parse` are null. So this function returns a null pointer. By placing a breakpoint right after the call to this function, we can see what is in `url_err`: the number 8.
  
Error code 8 is defined in the file `url.c` (which contains the `url_parse` function):

```c
#define PE_INVALID_IPV6_ADDRESS         8
```

Indeed, in the `url_parse` function, we have the following check:

```c
/* Check if the IPv6 address is valid. */
if (!is_valid_ipv6_address(host_b, host_e))
{
    error_code = PE_INVALID_IPV6_ADDRESS;
    goto error;
}

/* Continue parsing after the closing ']'. */
```

Recall that the argument we passed to wget was `-r %3a`, where `%3a` is the ASCII code for `:`. Upstream, wget detected our `:` and therefore considered it as an IPv6 address. Since it is invalid, `is_valid_ipv6_address()` returns `false`, and we have the error code. Everything is fine and is going as planned by the developers at this point.

The mistake is in the file `recur.c` with these lines:

```c
struct url *url_parsed = url_parse (url, &url_err, i, true);
status = retrieve_url (url_parsed, url, &file, &redirected, referer,
&dt, false, i, true);
```

There is no check made on the return of the `url_parse` function, and the `url_parsed` pointer is used without checking whether it is null or not.
  
So, logically, we get a segfault. From our point of view, this oversight does not allow any exploitation, but it was an interesting analysis. A fix is to check that the `url_parse` function returned a non-null pointer, in the following way:

```c
struct url *url_parsed = url_parse (url, &url_err, i, true);

if (!url_parsed)
{
    char *error = url_error (url, url_err);
    logprintf (LOG_NOTQUIET, "%s: %s.\n",url, error);
    xfree (error);
    inform_exit_status (URLERROR);
}
else
{
    status = retrieve_url (url_parsed, url, &file, &redirected, referer,
    &dt, false, i, true);
    // [...]
```

We also submitted a fix to GNU. We'll see if it gets accepted!

This issue does not exist if the `-r` parameter is omitted, since this missing check is only in the `recur.c` file, and nowhere else.

## Fixing the bug

We sent a fix that was accepted and [is merged into the master branch](https://savannah.gnu.org/bugs/?45289#comment5){:target="blank"}! There you go, a little contribution to the free software world, it feels good :)
</content>
</invoke>