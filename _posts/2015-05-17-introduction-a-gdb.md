---
title: Introduction to gdb
date: 2015-05-17
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /introduction-to-gdb/
redirect_from:
  - "/introduction-a-gdb/"
  - "/introduction-a-gdb"
disqus_identifier: 0000-0000-0000-0009
description: "GDB is an extremely powerful tool. Here is an article that introduces it with a hands-on application."
cover: assets/uploads/2015/05/gdb_visual.jpg
tags:
    - Linux
translation:
  fr: https://beta.hackndo.com/introduction-a-gdb/
---

Let the programmer who has never put `printf`, `var_dump`, `echo`, `print`, `System.out`, `console.log`, `cout` all over their code to find out where a bug came from come forward. Let the programmer who has never torn their hair out over a program that crashed violently without warning throw the first stone (It's an expression, eh!). Fortunately, there is a plethora of debuggers, free or not, one of which is particularly well known, the GNU debugger named **GDB** (GNU Project Debugger), which we are going to introduce in this introduction.

<!--more-->

Briefly, a debugger allows you to launch a program, place breakpoints at certain locations, sometimes under certain conditions, execute the instructions step by step, study and modify the memory (RAM, Registers)... In short, all the essential tools to be able to properly study the behavior of a program.

GDB is portable (cross-platform), so the commands we are going to see here can be performed on all OSes provided GDB is installed, and the examples taken here have been done on Linux. It is a very powerful tool, with many features that would be difficult to list and explain exhaustively, which is why we will see here what seemed to me to be the most important (... among the features I know. If you know others or tips to speed up/simplify things, do not hesitate to let me know in the comments, I will integrate them into this article).

# Launching

There are different ways to launch gdb and load a binary into a gdb session, here are some useful commands

## Outside of gdb

To launch gdb, nothing could be simpler. In a shell/terminal/console, run the following command

```bash
$ gdb

(gdb)
```

This command launches a gdb session. For now, no program is loaded in gdb. But already, we can do things that will be useful to us throughout our debugging. To get the list of available commands, just run the **help** command

```bash
(gdb) help
List of classes of commands:

aliases -- Aliases of other commands
breakpoints -- Making program stop at certain points
data -- Examining data
files -- Specifying and examining files
internals -- Maintenance commands
obscure -- Obscure features
running -- Running the program
stack -- Examining the stack
status -- Status inquiries
support -- Support facilities
tracepoints -- Tracing of program execution without stopping the program
user-defined -- User-defined commands

Type "help" followed by a class name for a list of commands in that class.
Type "help all" for the list of all commands.
Type "help" followed by command name for full documentation.
Type "apropos word" to search for commands related to "word".
Command name abbreviations are allowed if unambiguous.
(gdb)
```

Here are other commands:

```bash
# Load the "binary" binary into gdb
gdb binary

# Load the "binary" binary with the arguments "args..."
gdb --args <binary> <args...>

# Launch gdb which then attaches to the PID process with the symbols of the "binary" binary
gdb --pid <PID> --symbols <binary>
```

## Inside gdb

```bash
# Send the arguments to the binary that is going to be launched
(gdb) set args <args...>

# Launch the binary
(gdb) run

# Launch the binary, and send it a stream in stdin
(gdb) r < <(perl -e 'print "A"x5')

# Kill the running binary
(gdb) kill
```

# Calculations

Before dealing with the binaries, gdb allows to perform very simple calculations, in different most used bases (binary, octal, hex, decimal) and even to display the characters corresponding to the ASCII values.

```bash
# We can display the variables in different formats, as follows: p/<format>
# The most used formats are
# c    Character
# f    Float
# o    Octal
# s    String
# t    Binary
# x    Hexadecimal

(gdb) p 10+12
$1 = 22
(gdb) p/x 10+12
$2 = 0x16
(gdb) p 0x10
$3 = 16
(gdb) p 0x10 + 10
$4 = 26
(gdb) p/x 0x10 + 10
$5 = 0x1a
(gdb) p/t 12
$6 = 1100
```

# Information

Some necessary information when you have loaded a binary and you are debugging it

```bash
#disassemble: Returns the assembly code corresponding to the hexadecimal instructions of the binary
(gdb) disas my_function

#info registers: Returns the information of the registers at time t
(gdb) i r

#info breakpoints: Lists the breakpoints and their states
(gdb) i b
```

# Display

## Syntax

As explained in the article on [assembly basics](/assembly-basics/), there are two syntaxes to read assembly: AT&T and Intel. To switch from one to the other, here's how to do it:

### AT&T

```bash
(gdb) set disassembly-flavor att
(gdb) disass main
Dump of assembler code for function main:
   0x080483f2 <+0>:    push   %ebp
   0x080483f3 <+1>:    mov    %esp,%ebp
   ...
End of assembler dump.
```

### Intel

```bash
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
0x080483f2 <+0>:    push   ebp
0x080483f3 <+1>:    mov    ebp,esp
...
End of assembler dump.
```

## Debug

During a debug phase, it can be useful to have at hand the machine code that is executing as well as the state of the various registers.


_Note however that if you use these windows, you will no longer be able to use the up arrow to go back in your history, since the up and down arrows are used to scroll up and down in the window displaying the assembly code._

```bash
# Opens two console windows.
# One displays the assembly code
(gdb) layout asm
# The other displays the state of the registers.
(gdb) layout regs
# If a register changes when we move forward an instruction, it is highlighted.
```

Here is an example of the rendering:

```bash
┌──Register group: general─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│eax            0xbff73ef4       -1074315532         ecx            0x86c2e41d       -2034047971         edx            0x1      1                           ebx            0xb76f0ff4       -1217458188           │
│esp            0xbff73e40       0xbff73e40          ebp            0xbff73e48       0xbff73e48          esi            0x0      0                           edi            0x0      0                             │
│eip            0x8048826        0x8048826 <main+6>  eflags         0x282    [ SF IF ]                   cs             0x23     35                          ss             0x2b     43                            │
│ds             0x2b     43                          es             0x2b     43                          fs             0x0      0                           gs             0x63     99                            │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
│                                                                                                                                                                                                                  │
   ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
B+ │0x8048823 <main+3>      and    esp,0xfffffff0                                                                                                                                                                  │
  >│0x8048826 <main+6>      sub    esp,0x150                                                                                                                                                                       │
   │0x804882c <main+12>     mov    eax,0x80487fc                                                                                                                                                                   │
   │0x8048831 <main+17>     mov    DWORD PTR [esp+0x4],eax                                                                                                                                                         │
   │0x8048835 <main+21>     mov    DWORD PTR [esp],0x11                                                                                                                                                            │
   │0x804883c <main+28>     call   0x8048510 <signal@plt>                                                                                                                                                          │
   │0x8048841 <main+33>     mov    DWORD PTR [esp+0x8],0x0                                                                                                                                                         │
   │0x8048849 <main+41>     mov    DWORD PTR [esp+0x4],0x1                                                                                                                                                         │
   │0x8048851 <main+49>     mov    DWORD PTR [esp],0x2                                                                                                                                                             │
   │0x8048858 <main+56>     call   0x80485b0 <socket@plt>                                                                                                                                                          │
   │0x804885d <main+61>     mov    DWORD PTR [esp+0x13c],eax                                                                                                                                                       │
   │0x8048864 <main+68>     cmp    DWORD PTR [esp+0x13c],0x0                                                                                                                                                       │
   │0x804886c <main+76>     jns    0x8048886 <main+102>                                                                                                                                                            │
   │0x804886e <main+78>     mov    DWORD PTR [esp],0x8048ad2                                                                                                                                                       │
   │0x8048875 <main+85>     call   0x8048590 <perror@plt>                                                                                                                                                          │
   │0x804887a <main+90>     mov    DWORD PTR [esp],0x1                                                                                                                                                             │
   │0x8048881 <main+97>     call   0x8048610 <exit@plt>                                                                                                                                                            │
   └───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
child process 20368 In: main                                                                                                                                                               Line: ??   PC: 0x8048826
(gdb) ni
```

# Breakpoints

Breakpoints are extremely powerful. They allow to pause the execution of the program when they are encountered. This makes it possible to study the memory at a very precise moment, when it interests us. Indeed, there are often millions of instructions executed before the call of the function that interests us, so putting a breakpoint in the right place saves **a lot** of time.

## Without conditions

```bash
(gdb) break main
Breakpoint 1 at 0x80483f8
(gdb) break *0x08048400
Breakpoint 2 at 0x8048400
(gdb) delete 1
(gdb) i b
Num     Type           Disp Enb Address    What
2       breakpoint     keep y   0x08048400 <main+14>
(gdb) disable 2
(gdb) enable 2
(gdb) i b
Num     Type           Disp Enb Address    What
2       breakpoint     keep n   0x08048400 <main+14>
(gdb) delete breakpoints
Delete all breakpoints? (y or n) y
```

## With conditions

Take the following C program:

```c
#include <stdio.h>

int main(void) {
    for (int i=0; i<10; i++) {
        printf("%s\n", "Loop ...");
    }
}
```

After compilation, we load it into gdb, and disassemble it

```bash
$ gcc boucle.c -std=c99 -m32 -o boucle
$ gdb boucle
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x0804840c <+0>:     push   ebp
   0x0804840d <+1>:     mov    ebp,esp
   0x0804840f <+3>:     and    esp,0xfffffff0
   0x08048412 <+6>:     sub    esp,0x20
   0x08048415 <+9>:     mov    DWORD PTR [esp+0x1c],0x0
   0x0804841d <+17>:    jmp    0x8048430 <main+36>
   0x0804841f <+19>:    mov    DWORD PTR [esp],0x80484d0
   0x08048426 <+26>:    call   0x80482f0 <puts@plt>
   0x0804842b <+31>:    add    DWORD PTR [esp+0x1c],0x1
   0x08048430 <+36>:    cmp    DWORD PTR [esp+0x1c],0x9
   0x08048435 <+41>:    jle    0x804841f <main+19>
   0x08048437 <+43>:    mov    eax,0x0
   0x0804843c <+48>:    leave
   0x0804843d <+49>:    ret
End of assembler dump.
```

On line `+31`, we see the counter of our program incrementing. Here, the loop is repeated 10 times, but it is possible that it is repeated millions of times. However, we only want to see the comparison on line `+36` for the last iteration of the loop. For that, we are going to set a conditional breakpoint: We will only break on it if the content of `esp+0x1c` equals 10 (so `0xa`)

```bash
(gdb) b *0x08048430 if *(int*)($esp+0x1c) == 0xa
Breakpoint 1 at 0x8048430
(gdb) r
Starting program: /home/betezed/blog/exemples/boucle
Loop ...
Loop ...
Loop ...
Loop ...
Loop ...
Loop ...
Loop ...
Loop ...
Loop ...
Loop ...

Breakpoint 1, 0x08048430 in main ()
(gdb) x/x $esp+0x1c
0xbffff39c:    0x0000000a
```

Which could have been done in the following way as well:

```bash
(gdb) b *0x08048430
Breakpoint 1 at 0x8048430
(gdb) cond 1 *(int*)($esp+0x1c) == 0xa
```

And to remove the conditions on a breakpoint:

```bash
(gdb) cond 1
Breakpoint 1 now unconditional.
```

# Step by step

```bash
# nexti: Move forward one (or <step>) instruction(s), and if it's a call, the call is executed
# until its return.
(gdb) ni <step>
# stepi: Move forward one (or <step>) instruction(s), entering into the calls
(gdb) si <step>
# continue: Continue until the next breakpoint
(gdb) c
```

# Functions

It is possible to define functions within gdb, allowing to simplify the repetition of a set of commands, or to loop until a condition is verified. For this, you have to run the `define <my_function>` command then indicate the desired instructions, and finish with `end`. As examples are always worth more than fine words:

```bash
(gdb) define init_my_params
Type commands for definition of "init_my_params".
End with a line saying just "end".
>set disassembly-flavor intel
>break main
>r
>i r
>x/24xw $esp
>end
(gdb) init_my_params
Breakpoint 1 at 0x804840f

Breakpoint 1, 0x0804840f in main ()
eax            0xbffff454    -1073744812
ecx            0xe97a4d24    -377860828
edx            0x1    1
ebx            0xb7fcfff4    -1208156172
esp            0xbffff3a8    0xbffff3a8
ebp            0xbffff3a8    0xbffff3a8
esi            0x0    0
edi            0x0    0
eip            0x804840f    0x804840f <main+3>
eflags         0x246    [ PF ZF IF ]
cs             0x23    35
ss             0x2b    43
ds             0x2b    43
es             0x2b    43
fs             0x0    0
gs             0x63    99
0xbffff3a8:    0xbffff428    0xb7e85e46    0x00000001    0xbffff454
0xbffff3b8:    0xbffff45c    0xb7fd4000    0x08048320    0xffffffff
0xbffff3c8:    0xb7ffeff4    0x08048252    0x00000001    0xbffff410
0xbffff3d8:    0xb7ff06d6    0xb7fffad0    0xb7fd42e8    0xb7fcfff4
0xbffff3e8:    0x00000000    0x00000000    0xbffff428    0xc6213b34
0xbffff3f8:    0xe97a4d24    0x00000000    0x00000000    0x00000000
(gdb)
```

It is possible to use control structures, such as

```c
> if <condition>
>     commands...
> end
> while <condition>
>     commands...
> end
```

# .gdbinit

Of course, with all this information, you can create your own little gdb environment that satisfies your needs and preferences, but you obviously won't type all the commands every time. It is very tedious to have to type, every time gdb is launched, the commands to change syntax, to break on the main function, to disassemble the binary, to study the stack, if that's what you want to do every time you open gdb (but feel free to choose what you want)

For this, you just need to create a `.gdbinit` file in the same folder from which you launch gdb, and in this file, you put line by line the commands you wish to launch. For example:

```bash
$ cat .gdbinit
# To always have the intel syntax
set disassembly-flavor intel

# So that during a fork, gdb follows the child process, rather than the parent process
set follow-fork-mode child

# If you know that you have to launch gdb several times for the binary you
# are debugging, and the first 9 iterations of a loop
# don't matter to you, might as well break right at the moment that interests you
b *0x8048705 if *(int*)($esp+0x10) == 0xa

# And launch the binary
r

# Then, we often want to use these two functions at the same time
# Might as well group them in the same function!
define display_layouts
layout asm
layout regs
end
$ 
```

And finally, know that if you have your `.gdbinit`, but you don't want to use it for your next gdb session, just pass the `-nx` argument to gdb to tell it to ignore this file.

```bash
$ gdb <binary> -nx
```

There you have it, with this introduction to gdb, you should be able to use it and take advantage of its power. There are still a lot of things missing, I am aware of that, and I will add functions that seem relevant to me, whether by discovering them myself, or through your comments!

# To go further...

If you feel that gdb is too dull, that it lacks colors, features, know that many initiatives exist in the open source world to make your life more pleasant, by providing you with remarkably comprehensive and useful `.gdbinit` files. (_Thanks to yaap for the links_) We can mention, among others:\`

* [peda](https://github.com/longld/peda){:target="blank"}
* [dotgdb](https://github.com/dholm/dotgdb){:target="blank"}

Do not hesitate to install them, and modify them according to your needs, you have (almost) all the keys in hand to understand how they work. Note however that these tools are not free of bugs or unexpected behaviors. Use them with discernment, do not hesitate to be a good critic!

Happy reversing 😉
