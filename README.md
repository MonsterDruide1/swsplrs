# swsplrs - swspl, but in Rust.

This program should eventually be able to split NSO binaries into multiple object files.

This is a rewrite and continuation of shibbo's [swspl](https://github.com/shibbo/swspl).

## Problem Description

For decompiling projects like [OdysseyDecomp](https://github.com/MonsterDruide1/OdysseyDecomp), we would like to verify `.o` files independently, to ensure that our efforts so far are correct including function order, storage location (.data/.rodata/.bss/...) and actual data being stored. This requires reconstructing `.o` files from the compiled `.nso` binary.

Well, should be easy - just find the "split points" within each section, cut it and splice the different sections in the same object file, and that's it, right?

... no. As the final binary is expected to be loaded as a whole, references within the file are stored based on their offset within the entire file. Imagine the following binary layout:

| Section | Offset | Size |
|---|---|---|
.text|0x0|0x123000
.data|0x123000|0x30000

Now imagine the first data entry being a pointer to the second data entry: It would just contain the value `0x123008` (assuming `sizeof(void*) == 64/8`). However, when cutting away a large chunk of the `.text` section, the `.data` section moves upwards accordingly, so the value stored there does not point to the correct `.data` entry anymore - which means the result is useless.

So, to correctly account for moving the data around in the binary, we must make it relocatable first - by finding and resolving all references, replacing them with names instead of offsets, and finally re-assembling everything into new object files.

### References everywhere

Finding "all" references sounds simple, but ... what is a reference, how do we identify it and how can we resolve it?

There are three major categories we have to worry about: Relocations, Instructions and Data. Maybe more, but I just did those three so far.

#### Relocations

To be fair, I don't fully understand what is going on here either. Something about the `.got` and `.got.plt` sections along with `.rela.plt` and `.rela.dyn`, but that one was straight-forward, with good-looking result, so I didn't look into it further.

#### Instructions

When instructions want to access some value from `.data`, `.rodata` or `.bss`, it always follows a similar pattern:

```asm
ADRP X19, #target_offset@PAGE
LDR X19, [X19, #target_offset@PAGEOFF]
```

At least it would be nice if it consistently followed that pattern. Spoiler: It does not.

ARM64-Instructions always have a length of 4 bytes, which is not enough to encode the entire offset for the data we want to access, along with what to do with it/where it should be stored. Instead, this is handled in two instructions:
1. `ADRP` writes `imm`, left-shifted by 12 bits (corresponds to the page address = 4KB)
2. The actual instruction (`LDR`, `STR`, `ADD`, ...) encodes an additional `imm`, filling the lower 12 bits to form the final access

This pattern is used so commonly, that ARM established a pseudo-instruction consisting of `ADRP`+`ADD` to form the full address of any reference: `ADRL`.

At the moment, these "secondary" instructions are implemented, which should be preceded by a `ADRP` to form the full reference:
`[add, ldr, str, ldrh, strh, ldrb, strb, ldrsh]`

However, thanks to optimizations, those two instructions might not stay immediately next to each other. Also, the same `ADRP` might be used for multiple loads from the same page. They might drift so far apart so that they end up in different basic blocks, and one particularly annoying example in SMO puts the `ADRP` before the loop header, loads something with it, re-uses the same register, and finally prepares another `ADRP` before restarting the loop - which is an absolute nightmare when trying to figure out if something is supposed to be a load from memory or from the binary.

To analyze this, I'm taking an approach similar to Live-variable analysis, mixed with local-global optimization:
1. **Discovery**: Disassemble the entire binary top-to-bottom, to find individual basic blocks. Note that a basic block ends when any branch happens, except for link branches, as those return back to the same location while keeping registers mostly the same (except scratch registers). Also, already-discovered basic blocks can be "split", if there is a branch to some specific offset within this block from somewhere else.
2. **Local**: Next, analyze individual blocks by again disassembling the entire binary top-to-bottom. For each block, collect the following information:
    - possible blocks following after this one (already collected in step 1)
    - which registers contain `ADRP`-defined values at the end of this block
    - which registers got overwritten during this block
    - which registers are used for potential binary-lookups
3. **Global**: Iterate over all `ADRP`-defined values in all blocks, and "push" them through the following blocks until they get destroyed or we reached the end of the function (no local branches). Note that `BL`s and `BLR`s are not considered for carrying over `ADRP`s, and `BR`s are also ignored because those cannot consistently be statically analyzed. If any of the potential binary-lookups aligns with the `ADRP` value currently propagated, it is resolved as actual reference. If a local branch to an already-checked basic block is detected (loop), no further recursion is done.

#### Data

Not implemented yet.
