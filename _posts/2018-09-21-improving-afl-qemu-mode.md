---
layout: post
title: Improving AFL's QEMU mode performance
description: Block chaining to the rescue.
comments: true
---

I'm a big fan of [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/).
It's a robust and effective coverage-guided fuzzer, and it supports a QEMU mode to fuzz closed-source binaries.
QEMU mode, however, comes with a significant performance price.
Can we make it better?

# QEMU's block translation

Before starting, let's go over some QEMU basics.
QEMU's goal is to emulate a _target_ on top of a _host_, where the two can have different architectures.
The naive way would be writing an interpreter for the target's instruction set and compiling it for the host.
That's, obviously, going to be slow.
A smarter approach is just-in-time compilation: translate the target's code to native host instructions, and execute at native speed.
This is exactly what QEMU does.

Translating directly from target to host does not scale well, as one would need translators for all (target, host) tuples.
Like any problem in computer science, we can solve this by introducing an indirection layer: the _Tiny Code Generator_, or TCG for friends.
A TCG _frontend_ lifts native target instructions into an architecture-independent intermediate representation (IR).
A TCG _backend_ then lowers the IR into native host instructions.
Want to add a new target architecture?
Just write a frontend.
New host architecture?
Add a backend.
Easy.
The translation is done on-the-fly during emulation at the basic block level.
Since translation is expensive, translated blocks (TBs) are saved in the _TCG cache_, from which they can be fetched if they are executed again.

When you're doing this kind of translation, you have to keep in mind that the memory layout of the translated code does not necessarily match the original code.
Therefore, you have to fix up references to memory addresses.
Let's consider the control-flow instruction that terminates a block.
If it's a direct jump, the destination address is known, so it can be immediately fixed up and the jump translated into a native jump to the successor, resulting in zero runtime overhead.
QEMU calls this _block chaining_.
In case of an indirect jump, we can't determine the destination at translation time (even if we were to do analysis, it's an undecidable problem).
So we translate the jump to a call back into QEMU's core, which will translate the destination block if it hasn't already been translated and transfer control to it, thus resuming emulation.
Clearly, this has a performance price.

# AFL's QEMU instrumentation

AFL, being a coverage-guided fuzzer, needs a tracing instrumentation to collect information about the program's control flow.
I won't go into the raw details here, check out the [AFL technical whitepaper](http://lcamtuf.coredump.cx/afl/technical_details.txt) if you want to know how it works under the hood.
If you have the program's source code, you can recompile it using AFL's instrumenting compiler, which will add a small snippet to the beginning of every basic block.
When you only have a binary, you can use AFL's QEMU mode: the binary runs within a patched QEMU that collects coverage information and delivers it to AFL.

AFL's QEMU patches work as follows.
The `qemu_mode/patches/afl-qemu-cpu-inl.h` file contains the actual implementation, which has two main components: the forkserver and the tracing instrumentation.
The forkserver is AFL's way to optimize out initialization overhead.
Since the forkserver starts before the program is executed, children would always have an empty TCG cache.
Therefore, there's a mechanism by which children inform the parent of newly translated blocks, so that the parent can translate the block in its own cache for future children.
The forkserver is not really relevant for this post, so let's stop here.

The instrumentation hooks into `accel/tcg/cpu-exec.c` in the QEMU core.
Specifically, the patch inserts a snippet into `cpu_tb_exec`, which is called every time a TB is executed by the emulator.
The patch calls `afl_maybe_log`, which checks whether the block is within the traced bounds and, if it is, traces the control flow transfer into AFL's edge map.

There's a problem, though: jumps in chained blocks will not call back into the emulator, therefore, we won't go through `cpu_tb_exec`.
AFL solves this is by _disabling chaining_:

```c
/* Workaround for a QEMU stability glitch. */
setenv("QEMU_LOG", "nochain", 1);
```

Indeed, with `cpu_tb_exec` instrumentation, you'll get low stability if you don't disable chaining.
But that's because you're not tracing direct jumps at all, so I wouldn't call it a "glitch".
Anyway, disabling chaining is a pretty big performance hit.
Can we figure out a way to bring it back?

# TCG instrumentation

My idea was to move the instrumentation into the translated code by injecting a snippet of TCG IR at the beginning of every TB.
This way, the instrumentation becomes part of the emulated program, so we don't need to go back into the emulator at every block, and we can re-enable chaining.

This is `afl_maybe_log` from the original `qemu_mode/patches/afl-qemu-cpu-inl.h`:

```c
/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(abi_ulong cur_loc) {

  static __thread abi_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;

}
```

Everything that depends on `cur_loc` can be done at translation time, as `cur_loc` is the address of the current block.
Basically, we just need to generate TCG IR for the last two lines.
So I wrote this:

```c
/* Generates TCG code for AFL's tracing instrumentation. */
static void afl_gen_trace(target_ulong cur_loc)
{
  static __thread target_ulong prev_loc;
  TCGv index, count, new_prev_loc;
  TCGv_ptr prev_loc_ptr, count_ptr;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  /* index = prev_loc ^ cur_loc */
  prev_loc_ptr = tcg_const_ptr(&prev_loc);
  index = tcg_temp_new();
  tcg_gen_ld_tl(index, prev_loc_ptr, 0);
  tcg_gen_xori_tl(index, index, cur_loc);

  /* afl_area_ptr[index]++ */
  count_ptr = tcg_const_ptr(afl_area_ptr);
  tcg_gen_add_ptr(count_ptr, count_ptr, TCGV_NAT_TO_PTR(index));
  count = tcg_temp_new();
  tcg_gen_ld8u_tl(count, count_ptr, 0);
  tcg_gen_addi_tl(count, count, 1);
  tcg_gen_st8_tl(count, count_ptr, 0);

  /* prev_loc = cur_loc >> 1 */
  new_prev_loc = tcg_const_tl(cur_loc >> 1);
  tcg_gen_st_tl(new_prev_loc, prev_loc_ptr, 0);
}
```

This needs to be called before translating each block.
TB IR generation happens in `tb_gen_code` (`accel/tcg/translate-all.c`), which calls the target frontend's `gen_intermediate_code` function:

```c
tcg_ctx.cpu = ENV_GET_CPU(env);
gen_intermediate_code(cpu, tb);
tcg_ctx.cpu = NULL;
```

Let's hook it to insert our IR before each block:

```
tcg_ctx.cpu = ENV_GET_CPU(env);
afl_gen_trace(pc);
gen_intermediate_code(cpu, tb);
tcg_ctx.cpu = NULL;
```

Now we can remove the `setenv("QEMU_LOG", "nochain", 1)` from AFL (`afl-analyze.c`, `afl-fuzz.c`, `afl-showmap.c`, `afl-tmin.c`) and test it out.

# Results

I did not have time to perform very thorough testing, but I'm measuring speeds between 1.5x and 3x on 32-bit and 64-bit x86 targets.
That's a 50-200% speedup!
Path count and `afl-showmap` seem to confirm that it's indeed tracing correctly, so I'm pretty confident it is working as intended.

# Try it out!

The TCG instrumentation is included in [my AFL fork](https://github.com/abiondo/afl).
Build and run QEMU mode as usual.
My fork also includes a patch for the `memfd_create` build error when compiling with GNU libc >= 2.27, so it should build easily on any Linux system.
If you test it and have better performance comparisons, issues, or any question, please leave a comment!