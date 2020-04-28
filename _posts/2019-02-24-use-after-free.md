# Use after Free

Previously, we addressed various vulnerabilities which exploit the stack following overflows (Buffer Overflow, Ret2Libc, ROP). Today, we’re going to discover a new memory area, the Heap, by introducing a relatively common vulnerability, called “use-after-free”.

## The Heap

Unlike the stack whose operation is explained in [this article][https://beta.hackndo.com], the heap is a memory area used for dynamic allocation. To do this, any memory area in the heap can be used at any time. There is no more stacking or unstacking notion. Any block can be allocated, or freed, at any time.

Intuitively, we understand that this system is a lot more flexible, but in return slower and more complex, since we need to keep a ( memory state ou record of the memory ) to find out if a block is allocated or not.

But then, how do we allocate memory, or how do we free it, and what actually happens ?

## Malloc/Free

We will talk about two functions, `malloc()` and `free()`, although there are other (`calloc()` for example). The principle is the same.

### Malloc

The malloc function asks the OS for allocating a memory block of a certain size. If this allocation is possible, then `malloc()` returns a pointer to the beginning of the block.

In C, there is what the diagram above looks like :

~~~
char *pointer;
pointer = malloc(32);
# According to the diagram above, the value of "pointer" will be 0x55e700000010
~~~

The operating system will find out 32 available bytes, and returns this memory block’s address which will be affected to the `pointer` variable.The developer can then use this memory area to store data, such as a string, as follows :

~~~
strncpy(pointer, "Hello World!", 13);
~~~

The characters `['H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\x00']` will be put in the memory area allocated by `malloc()`.

### Free

Once the allocated memory is no longer used, we should consider freeing it thanks to `free()`.

~~~
// This memory area is no longer useful
free(pointer);
~~~

In this state, the `pointer` variable still contains the address of the memory zone, although it is no longer allocated. If a new allocation is requested, there is a chance that this memory area will be reused. In this case, pointer will point to this newly allocated area, but whose data are no longer relevant. To avoid this state, we also need to reset the pointer.

~~~
pointer = NULL;
~~~

Here is a small example program that shows these actions.

~~~
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv) {
        // Two pointers are declared and initialized at NULL
        char *pointerA = NULL;
        char *pointerB = NULL;

        // A memory area will be allocated, and the first pointer will point to it
        pointerA = malloc(16);
        printf("The pointerA variable point to %p\n", pointerA);

        // We add data in this memory area
        strncpy(pointerA, "Hello World!", 12);
        printf("Here is what’s on the address %p, pointed out by pointerA : %s\n", pointerA, pointerA);

        // We no longer need pointerA, we will free the memory area
        free(pointerA);
        pointerA = NULL;
        printf("The memory area has been freed !\n");

        /*
         *   [...]
         */

        // Later in the program, we need a new memory zone
        pointerB = malloc(16);
        printf("The pointerB variable point to %p\n", pointerB);
        // Then we free it
        free(pointerB);
        pointerB = NULL;
        return 0;
}
~~~

Once compiled, this code gives the following input :

~~~
The pointerA variable point to 0x55e703641010
Here is what’s on the address 0x55e703641010, pointed out by pointerA : Hello World!
The memory area has been freed !
The pointerB variable point to 0x55e703641010
~~~

We notice an important thing : after the freeing of the memory area pointed out by pointerA, during the new allocation, the same address is used (0x55e703641010) and affected to pointerB, since the memory area is freed again.

## Use-After-Free

### The mistake

When everything is done properly, there is no possible exploitation. Two mistakes may then be commit by programmers.

* Either they forget to free the memory : In this case, there is a memory leak in the program since he’ll never free the allocated memory. That’s not a security issue, but a bad practice.
* Or they forget to reset the pointer after freeing the memory : In this case, if the pointer is used later for any reason, he will point to a uninitialized memory area, or even reused for other reasons, which can cause the program to crash, but also can be exploited.

It’s in this second case that we call the exploitation “Use after free”, since we use a pointer after he was freed, without it has been reset.

### Example

Here’s a little piece of code which is potentially dangerous. The comments should be enoughly explicits to understand what happens.

~~~
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv) {
        // Two pointers admin et name, that have nothing to do with each other in the code
        char *admin = NULL;
        char *name= NULL;

        // By default, the user who launches the program is not admin. That’s all.
        admin = malloc(32);
        admin[0] = 0;

        /*
         * Code, code, code [...]
         */

        // At one point, in the code, the memory area is freed, but the admin variable isn’t reset !
        free(admin);

        /*
         * Code again [...]
         */

        // Then another memory allocation is done
        // Except that as admin  Sauf que comme admin a été libéré, cette nouvelle zone mémoire réutilise cet espace !
        name = malloc(32);
        strncpy(name, "pixis", 5);

        /*
         * Code again and again [...]
         */
        
        // Here, admin still point to the initial memory area, which is reused by “name”
        // So, admin[0] has a value of "p", admin[1] has a value of "i", and so on
        // Thus, according to this verification, we are administrator !
        if (admin == NULL || admin[0] == 0) {
                printf("This is a forbidden section !\n");
                return -1;
        }
        
        printf("Super secret administration zone !\n");

        /*
         * Then code [...]
         */

        free(name);
        name = NULL;
        return 0;
}
~~~

Which, upon execution, gives :

~~~
Super secret administration zone !
~~~

This example clearly shows the problem of using a pointer after it has been freed.

This is obviously a trivial example, which only illustrate the use-after-free behavior, but this vulnerability can be found in programs which manage the creating and deletion of objects, the authentification…

If, for instance, a structure like this is used :

~~~
struct user {
    int id;
    char *name;
    int isAdmin;
}
~~~

If an instance is allocated then deleted, and that following this, another allocation overwrites this memory area by making the offset corresponding to “isAdmin” equals to 1, then next time the object is used, the user will be considered as an administrator.

## Conclusion

For a CTF, I created a challenge that had to be exploited using this technique. Here it is :

~~~
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
~~~

This article should give you everything you need to understand the memory management when allocating and freeing up memory areas in this program in order to exploit it.

I hope this article helps you to understand the mechanisms within this vulnerability, don’t hesitate to share your examples of vulnerable programs, or exploits of the provided program.
