---
title: "Use After Free"
date: 2019-02-24 11:02:38
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /use-after-free/
disqus_identifier: 0000-0000-0000-00a4
cover: assets/uploads/2019/02/uafbanner.png
description: "Today, we are going to discover together a new memory area, the heap, while detailing a vulnerability that is relatively common in recent programs, called use-after-free."
tags:
  - Linux
  - "User Land"
translation:
  fr: 
---

We've looked at various vulnerabilities that involved the stack as a result of overflows ([Buffer Overflow](/buffer-overflow/), [Ret2Libc](/return-to-libc/), [ROP](/return-oriented-programming)). Today, we are going to discover together a new memory area, the heap, while detailing a vulnerability that is relatively common in recent programs, called "use-after-free".

<!--more-->

## The Heap

Unlike the stack, whose operation was explained in [this article](/stack-introduction/), the *heap* is a memory area used for dynamic allocations. To that end, any memory space in the *heap* can be used at any time. There is no longer any notion of push or pop. Any block can be allocated or freed at any time.

We understand quite intuitively that this system is much more flexible, but in return, it is slower and more complex, since we need to keep track of the memory's state in order to know whether a block is allocated or not.

But then, how do we allocate memory, or how do we free it, and what really happens?

## Malloc/Free

Here we are going to talk about two functions, `malloc()` and `free()`, although there are others (`calloc()` for example). The principle remains the same.

### Malloc

The `malloc()` function asks the OS to allocate a memory block of a certain size. If this allocation is possible, then `malloc()` will return a pointer to the beginning of this block.

[![Malloc](/assets/uploads/2019/02/malloc.png)](/assets/uploads/2019/02/malloc.png)


In C, here is what the diagram above represents.

```c
char *pointer;
pointer = malloc(32);
# According to the diagram above, the value of "pointer" will be 0x55e700000010
```

So the OS will find 32 available bytes, and return the address of this memory block, which here will be assigned to the variable `pointer`. The developer can then use this memory space to store information, for example a string, as follows:

```c
strncpy(pointer, "Hello World!", 13);
```

The characters `['H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\x00']` will be placed in the memory area allocated by `malloc()`.

### Free

Once the allocated memory is no longer used, you must remember to free it using the `free()` function.

```c
// This memory area is no longer needed
free(pointer);
```

In this state, the `pointer` variable still contains the address of the memory area previously used, except that it is no longer allocated. If a new allocation is requested, there are chances that this memory area will be reused. In that case, `pointer` will point to this newly allocated area, but whose data has nothing to do with the previous one. To avoid ending up in this state, you must also remember to reset the pointer.

```c
pointer = NULL;
```

Here is a small example program showing these different actions.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv) {
        // Two pointers are declared and initialized to NULL
        char *pointerA = NULL;
        char *pointerB = NULL;

        // A memory area is going to be allocated, and the first pointer will point to it
        pointerA = malloc(16);
        printf("The variable pointerA points to %p\n", pointerA);

        // We add data to this memory area
        strncpy(pointerA, "Hello World!", 12);
        printf("Here is what is at address %p, pointed to by pointerA: %s\n", pointerA, pointerA);

        // We no longer need pointerA, so we are going to free the memory area
        free(pointerA);
        pointerA = NULL;
        printf("The memory area has been freed!\n");

        /*
         *   [...]
         */

        // Later in the program, we need a new memory area.
        pointerB = malloc(16);
        printf("The variable pointerB points to %p\n", pointerB);
        // Then we free it
        free(pointerB);
        pointerB = NULL;
        return 0;
}
```

Once compiled, this code gives the following output:

```
The variable pointerA points to 0x55e703641010
Here is what is at address 0x55e703641010, pointed to by pointerA: Hello World!
The memory area has been freed!
The variable pointerB points to 0x55e703641010
```

We notice an important thing: after freeing the memory block pointed to by `pointerA`, when the new allocation is performed, the same address is used (`0x55f8d82d1010`) and assigned to `pointerB`, since this memory block was again free. 

## Use-After-Free

### The mistake

When everything is done correctly, there is no real possible exploitation. Programmers can however make two mistakes:

* Either they forget to **free the memory**: in this case, the program will exhibit a memory leak since it will never free the allocated memory. It's not a security issue, but it's still bad practice.
* Or they forget to **reset a pointer** after freeing the memory: in this case, if the pointer is later used for any reason, it will point to an uninitialized memory area, or even reused for other purposes, which can crash the program but can also be exploited.

It's in this second case that we call the exploitation "Use after free", since we use a pointer after it has been freed, without it having been reset.

### Example

Here is a little piece of program that presents a potential danger. The comments should be explicit enough to understand what's going on.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv) {
        // Two pointers, admin and firstname, that have nothing to do with each other in the code
        char *admin = NULL;
        char *firstname = NULL;

        // By default, the user running this program is not administrator. That's it.
        admin = malloc(32);
        admin[0] = 0;

        /*
         * Some code, some code, some code [...]
         */

        // At some point in the code, the memory area of admin is freed, but the admin variable is not reset!
        free(admin);

        /*
         * And more code [...]
         */

        // And then another memory allocation is made.
        // Except since admin was freed, this new memory area reuses that space!
        firstname = malloc(32);
        strncpy(firstname, "pixis", 5);

        /*
         * Still more code [...]
         */
        
        // Here, admin still points to the initial memory area, which has been reused by "firstname".
        // So admin[0] is "p", admin[1] is "i", etc.
        // Thus, according to this check, we are administrator!
        if (admin == NULL || admin[0] == 0) {
                printf("This section is forbidden!\n");
                return -1;
        }
        
        printf("Super secret admin area!\n");

        /*
         * And then some code [...]
         */

        free(firstname);
        firstname = NULL;
        return 0;
}
```

Which, when executed, gives:

```
Super secret admin area!
```
This example clearly shows the problem of using a pointer after it has been freed. 

This is obviously a somewhat trivial example, only meant to illustrate the use-after-free behavior, but this vulnerability can be found in programs that handle object creation and deletion, authentication, ...

If for example a structure of this kind is manipulated:

```c
struct user {
    int id;
    char *name;
    int isAdmin;
}
```

It is enough for an instance to be allocated then deleted, and following this, for another allocation to overwrite this memory area so that the offset corresponding to "isAdmin" is set to 1, so that the next time the object is used, the user is considered an administrator.

## Conclusion

During a CTF, I created a vulnerable challenge that had to be exploited using this technique. Here it is:

```c
/**
 * Filename: uaf.c
 * Author: pixis
 * Description: Pown challenge
 * Usage: ./uaf
 * Compilation: gcc -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro -o uaf uaf.c
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_SIZE   16

typedef struct player {
  char name[MAX_NAME_SIZE];
  int64_t isAdmin;
} player_t;

char *game_title=NULL;

/* 
Prevent double free
*/
int is_player_freed=1;
int is_title_freed=1;


int main(int Count, char *Strings[])
{   
    char line[128];
    player_t *player = NULL;
    while(1) {
        printf(
            "  _______ _    _ ______    _____          __  __ ______ \n"
            " |__   __| |  | |  ____|  / ____|   /\\   |  \\/  |  ____|\n"
            "    | |  | |__| | |__    | |  __   /  \\  | \\  / | |__   \n"
            "    | |  |  __  |  __|   | | |_ | / /\\ \\ | |\\/| |  __|  \n"
            "    | |  | |  | | |____  | |__| |/ ____ \\| |  | | |____ \n"
            "    |_|  |_|  |_|______|  \\_____/_/    \\_\\_|  |_|______|\n"
            "                                                        \n"
            "                                                        \n"
            "\n"
            "Game information\n"
            "----------------\n"
            "\tPlayer name\t-->\t%s\n"
            "\tGame title\t-->\t%s\n"
            "\n"
            "Commands\n"
            "--------\n"
            "\tset <Player name>\t-\tSet player's name\n"
            "\ttitle <Game title>\t-\tSet game's title\n"
            "\tdel\t\t\t-\tDelete player's name\n"
            "\tlogin\t\t\t-\t[ADMIN AREA] Login into the game\n"
            "\texit\t\t\t-\tExit :(\n"
            "\n"
            "> ",
            player == NULL ? "(Not set)" : player->name, game_title == NULL ? "(Not set)" : game_title);

        if (fgets(line, sizeof(line), stdin) == NULL) break;


        if (strncmp(line, "set ", 4) == 0) {
            if (strlen(line + 4) > 1 && strlen(line + 4) <= MAX_NAME_SIZE) {
                // Free old player if set
                if (player != NULL && is_player_freed == 0) {
                    free(player);
                    is_player_freed = 1;
                }
                player = malloc(sizeof(player_t));
                
                // Fresh new player
                memset(player, 0, sizeof(player_t));
                
                is_player_freed = 0;
                
                // Replace trailing \n with \0
                strncpy(player->name, line + 4, strlen(line+4)-1);
                player->name[strlen(line+4)] = 0;

                // You're not admin, duh.
                player->isAdmin = 0;
            } else {
                printf("Maximum name size is %d characters\n", MAX_NAME_SIZE-1);
            }
        }

        if (strncmp(line, "title ", 6) == 0) {
            // Free old title if set
            if (game_title != NULL && is_title_freed == 0) {
                free(game_title);
                is_title_freed = 1;
            }

            game_title = strndup(line+6, strlen(line+6)-1);
            is_title_freed = 0;
        }

        if (strncmp(line, "del", 3) == 0) {
            // Free player if set
            if (player != NULL && is_player_freed == 0) {
                free(player);
                is_player_freed = 1;
            }
        }

        if (strncmp(line, "login", 5) == 0) {
            // If you're admin, go get your cookie !
            if (player != NULL) {
                printf("%s\n", player->isAdmin == 0 ? "Nop" : "Well done, you're administrator !");
            }
        }

        if (strncmp(line, "exit", 4) == 0) {
            // Exit nicely without memory leaks
            if (player != NULL && is_player_freed == 0) {
                free(player);
            }
            if (game_title != NULL && is_title_freed == 0) {
                free(game_title);
            }
            
            // I'm quite polite.
            printf("'k Bye !\n");

            return EXIT_SUCCESS;
        }
    }
    return EXIT_SUCCESS;
}
```

This article should give you all the necessary tools to understand memory management during the allocation and freeing of memory areas in this program with a view to exploiting it.

I hope this article helps you understand the mechanisms inherent to this vulnerability; don't hesitate to share your examples of vulnerable programs or exploitations of the provided program.
</content>
</invoke>