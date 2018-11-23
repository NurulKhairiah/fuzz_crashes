# XED Fuzzing
---

This program we are fuzzing is a 64 bit ELF executable which is not stripped.
Thankfully.

```
cexplr@cExplr ~/Desktop/githubFuzz/xed_fuzz/out_20181114_04_30_10/crash $ file ../../xed-func 

../../xed-func: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped
```

I am not entirely sure about what this program does. So let's check out the version number and it's help menu

```
cexplr@cExplr ~/Desktop/githubFuzz/xed_fuzz/out_20181114_04_30_10/crash $ ../../xed-func --version
Copyright (C) 2017, Intel Corporation. All rights reserved.
XED version: [v10.0-190-g139a117]

Usage: ../../xed-func [options]
One of the following is required:
	-i input_file             (decode elf-format file)
	-ir raw_input_file        (decode a raw unformatted binary file)
	-ih hex_input_file        (decode a raw unformatted ASCII hex file)
	-d hex-string             (decode one instruction, must be last)
	-F prefix		  (decode ascii hex bytes after prefix)
				  (running in filter mode from stdin)
	-ide input_file           (decode/encode file)
	-e instruction            (encode, must be last)
	-ie file-to-assemble      (assemble the contents of the file)
	-de hex-string            (decode-then-encode, must be last)

Optional arguments:

	-v N          (0=quiet, 1=errors, 2=useful-info, 3=trace,
	               5=very verbose)
	-xv N         (XED engine verbosity, 0...99)

	-chip-check CHIP   (count instructions that are not valid for CHIP)
	-chip-check-list   (list the valid chips)

	-s section    (target section for file disassembly,
	               PECOFF and ELF formats only)

	-n N          (number of instructions to decode. Default 100M,
	               accepts K/M/G qualifiers)
 
	-b addr       (Base address offset, for DLLs/shared libraries.
	               Use 0x for hex addresses)
	-as addr      (Address to start disassembling.
	               Use 0x for hex addresses)
	-ae addr      (Address to end   disassembling.
	               Use 0x for hex addresses)
	-no-resync    (Disable symbol-based resynchronization algorithm
	               for disassembly)
	-ast          (Show the AVX/SSE transition classfication)
	-histo        (Histogram decode times)

	-I            (Intel syntax for disassembly)
	-A            (ATT SYSV syntax for disassembly)
	-isa-set      (Emit the XED "ISA set" in dissasembly)
	-xml          (XML formatting)
	-uc           (upper case hex formatting)
	-nwm          (Format AVX512 without curly braces for writemasks, include k0)
	-emit         (Output __emit statements for the Intel compiler)
	-S file       Read symbol table in "nm" format from file
	-dot FN       (Emit a register dependence graph file in dot format.
	               Best used with -as ADDR -ae ADDR to limit graph size.)

	-r            (for REAL_16 mode, 16b addressing (20b addresses),
	               16b default data size)
	-16           (for LEGACY_16 mode, 16b addressing,
	               16b default data size)
	-32           (for LEGACY_32 mode, 32b addressing,
	               32b default data size -- default)
	-64           (for LONG_64 mode w/64b addressing
	               Optional on windows/linux)
	-mpx          (Turn on MPX mode for disassembly, default is off)
	-s32          (32b stack addressing, default, not in LONG_64 mode)
	-s16          (16b stack addressing, not in LONG_64 mode)
	-set OP VAL   (Set a XED operand to some integer value)

```

We will be fuzzing with the following parameters.

```
xed-func -xv 0 -v -0 -i <ELF File>
```

Using the Nanyang Technological University's In house fuzzing tool ( as described in the README.md of the repository ), we get the out_20181114_04_30_10 folder which I did for strings_fuzz. 

---

Analysis so far:
-	[crash_1/crash_1_w01_000001.md](crash_1/1_xed_crash_w01_000010)