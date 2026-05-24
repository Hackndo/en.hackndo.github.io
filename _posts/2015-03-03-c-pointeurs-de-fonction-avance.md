---
title: 'C function pointers'
date: 2015-03-03
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /c-pointeurs-de-fonction/
disqus_identifier: 0000-0000-0000-000C
description: "Here is a quick memo about function pointers."
cover: assets/uploads/2015/03/shellcode.jpg
tags:
    - Misc
translation:
  fr: 
---
Here is a quick memo about function pointers. As a reminder, a pointer is a variable that contains the memory address of a piece of data. The data can be an int, a float, an array, etc. But it can also be the address of a function. But what does the address of a function mean?

<!--more-->

## How does it work?

When a program is compiled, the code is actually transformed into machine instructions that the processor can understand. This code is stored on the hard drive. Once the program is executed, the code is copied into the machine's RAM, and only then will it be executed. It is therefore written in RAM, in the segment we call the **_text_ segment**. The instructions are read one after the other by default. But sometimes there can be instructions that explicitly ask the processor to jump to a particular memory cell, especially when calling a function (with the `call` instruction). This address (called the entry point or _Entry Point_) which contains the first instruction of the function, is what we call **the address of the function**.

Here is a diagram of a portion of the _text_ segment of the RAM allocated to the executable:

[![img_54f50475e7615](/assets/uploads/2015/03/img_54f50475e7615.png)](/assets/uploads/2015/03/img_54f50475e7615.png)

So I was saying that a pointer could contain the address of a function. How do we declare that?

```c
int (*ptr)(float, int);
```

In fact, this declaration is composed of three parts. The first one **int** means that the return value of the function that will be pointed to must be of type int. Then **ptr** is the name of the pointer. Finally **float, int** represents the types of arguments that must be taken as parameters by the function that will be pointed to.


[![img_54f577a2f3431](/assets/uploads/2015/03/img_54f577a2f3431.png)](/assets/uploads/2015/03/img_54f577a2f3431.png)


Thus:

```c
int myFunction(float f, int i); // ptr will be able to point to this function
void myOtherFunction();         // ptr will not be able to point to this function
```

However, for now, `ptr` doesn't point to anything at all. It needs to be given the address of the function. How to do that? Well, quite simply like this:

```c
int myFunction(float f, int i);
int (*ptr)(float, int);
ptr = &myFunction;
/*
 * Or ptr = myFunction because myFunction, without the parentheses ()
 * already represents the address of the function.
 * &myFunction == myFunction => true
 */

```

To execute the function, it is then enough to dereference the pointer, which will give the value of the function, and to pass it the necessary arguments:

```c
int myFunction(float f, int i);
int (*ptr)(float, int);
ptr = myFunction;
int retour = (*ptr)(2.0, 3);

```

`retour` will then contain the return value of the `myFunction` function, pointed to by `ptr`.

## Temporary and anonymous
  
We can also define a "temporary anonymous" pointer to a function on a single line, as follows:

```c
(int(*)(float, int))myFunc;
```

I call it anonymous because it has no name (unlike the declaration of `ptr` in the previous example) and since it has no name, we won't be able to use it on the next line, which is why I qualify it as temporary.
  
And to execute it on the same line, all we have to do is dereference it again and pass it the arguments:

```c
(*(int(*)(float, int))myFunc)(2.0, 4);
```

If you have followed along well, this temporary anonymous pointer is actually equal to... the address of the function! And to convince yourself, the following code:

```c
if (myFunc == (int(*)(float, int))myFunc) {
    printf("The two elements are similar.\n");
    printf("They both contain the address of myFunc.");
}
```

There you have it, a brief reminder about function pointers, and an explanation of a somewhat particular syntax like that of the last example.
