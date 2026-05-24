---
title: "Calling conventions"
date: 2018-05-20 21:35:33
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /conventions-d-appel/
disqus_identifier: 0000-0000-0000-00a1
cover: assets/uploads/2018/05/conventions-d-appel.png
description: "Here is an article that is not really technical, not really complicated, and for which you can find documentation pretty much everywhere, but it's the kind of information that I read one day, that I forget a few weeks later, so that I want to summarize in my own words once and for all"
tags:
  - Misc
translation:
  fr: 
---


Here is an article that is not really technical, not really complicated, and for which you can find documentation pretty much everywhere, but it's the kind of information that I read one day, that I forget a few weeks later, so that I want to summarize in my own words once and for all. Let's then (re)discover calling conventions in the x86 world.

<!--more-->

## Introduction

When a program is compiled (i.e. when the high-level code used by the programmer is translated into machine code), there are different conventions for function calls. Some decide that the calling function takes its responsibilities by cleaning up the stack after a function call (CDECL, FASTCALL).

Others, however, make the functions responsible by asking them to take care of their memory space, and to clean everything up when they are finished (STDCALL).

There are also different ways to pass arguments to a function, via the stack or via the registers.

So here is an article that clarifies all these points, allowing everyone to have a quick summary of the different calling conventions.

It is therefore necessary to split this article in two. A first historical part that lists the main calling conventions for 32-bit architectures, then a second one that presents the default convention on 64-bit architectures.

## 32 bits

In 32-bit architectures, there are a few registers available, and a few existing calling conventions. Here are the main ones.


### CDECL (Standard C Calling Convention)

This convention is the one used by default by most C/C++ compilers.

Here, it is the calling function that cleans the stack for the function it is going to call.

```nasm
caller:
    push    3        ; Use of 4 bytes on the stack
    push    2        ; Use of 4 bytes on the stack
    push    1        ; Use of 4 bytes on the stack
    call    callee   ; Function call
    add     esp, 0xc ; The space that had been allocated on the stack for the variables (12 bytes) is cleaned up
```

### STDCALL (Standard Call)

The arguments are pushed onto the stack before the function call, and the called function is responsible for cleaning up the stack, so that when the function is finished and the program resumes its execution after the function call, the stack appears not to have been modified.

There is therefore a prologue and an epilogue in each function to manage the construction and destruction of the stack necessary for the proper functioning of this function.

When the called function ends, there will be a call to the return instruction with an argument passed to it, an argument corresponding to the number of bytes to free at the time of return to the calling function.

```nasm
caller:
    push    3
    push    2
    push    1
    call callee
```
```nasm
callee:
    push ebp
    mov ebp, esp
    ...
    mov esp, ebp
    pop ebp
    return 0xc       ; Because there are 3 arguments of 4 bytes to free, so 12 bytes
```

### FASTCALL (Fast Calling Convention)

In this calling convention, arguments are no longer pushed onto the stack, but stored in registers. However, in a 32-bit architecture, only 2 registers can be used for this convention. If there are more than two arguments to pass to the function, the following ones will be pushed onto the stack, as in the two calling conventions seen previously.

Furthermore, it is the called function that is responsible for cleaning up the stack.

This convention is theoretically faster to execute because it reduces the number of instruction cycles.

```nasm
caller:
    mov edx, 3
    mov ecx, 2
    call callee
```
```nasm
callee:
    push ebp
    mov ebp, esp
    ...
    mov esp, ebp
    pop ebp
    return
```

## 64 bits

Following the arrival of 8 new registers in 64-bit architectures (r8 to r15), it is the FASTCALL convention that has become the default one. It then makes it possible to pass 4 arguments via the registers, instead of 2 as for 32-bit architectures.

If there are more than 4 arguments, the following ones are pushed onto the stack.

The registers used are, in order, `rcx`, `rdx`, `r8` and `r9`.

```nasm
caller:
    mov r9, 4
    mov r8, 3
    mov rdx, 2
    mov rcx, 1
    call callee
```


## Summary

Here are the two summary tables that allow you to have a quick view of the different calling conventions covered in this article

### 32 bits

| Convention  | Argument passing             | Stack cleanup responsibility    |
| ----------- |:----------------------------:|:-------------------------------:|
| CDECL       | Pushed onto the stack        | Calling function                |
| STDCALL     | Pushed onto the stack        | Called function                 |
| FASTCALL    | 2 registers then on the stack| Called function                 |

### 64 bits

| Convention  | Argument passing             | Stack cleanup responsibility    |
| ----------- |:----------------------------:|:-------------------------------:|
| FASTCALL    | 4 registers then on the stack| Called function                 |


I hope this article on calling conventions, clarifying things while remaining concise and going to the essentials, will allow you to quickly find the information you are looking for on this subject.
