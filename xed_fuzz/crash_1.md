# Crash #1
---

I select a random payload for the crash
from the `out_20181114_04_30_10/crash directory`. Since 10 is a nice number, I choose `w01_000010,sig:11,Havoc:20061:26112,src:w00_000000`.

The fuzzer will fuzz xed-func with the following parameters.

```
./xed-func -xv 0 -v 0 -i <ELF file>
```

What this does is that it turns off all verbosity and allow for an input ELF file to analyze and decode ELF-file format

An example flow of intended usage:

```
cexplr@cExplr ~/Desktop/githubFuzz/xed_fuzz $ ./xed-func -xv 0 -v 0 -i ./xed-func 
# Found dynamic strtab: 5 offset 838 size 1eb
# Found strtab: 39 offset 11a48f0 size 12271b
# Found dynamic symtab: 4 offset 2e0 size 558
# Found symtab: 38 offset 110f850 size 950a0
# SECTION 10                     .init addr 401070 offset 1070 size 26
# end of text section.
# Errors: 0
# SECTION 11                      .plt addr 401090 offset 1090 size 848
# end of text section.
# Errors: 0
# SECTION 12                  .plt.got addr 4013e0 offset 13e0 size 8
# end of text section.
# Errors: 0
# SECTION 13                     .text addr 4013f0 offset 13f0 size 3792594
# end of text section.
# Errors: 0
# SECTION 14                     .fini addr 79f2c4 offset 39f2c4 size 9
# end of text section.
# Errors: 0
#XED3 DECODE STATS
#Total DECODE cycles:        521852536
#Total instructions DECODE: 768700
#Total tail DECODE cycles:        522064002
#Total tail instructions DECODE: 768750
#Total cycles/instruction DECODE: 678.88
#Total tail cycles/instruction DECODE: 679.11
#XED3 ENCODE STATS
#Total ENCODE cycles:        0
#Total instructions ENCODE: 0
#Total tail ENCODE cycles:        0
#Total tail instructions ENCODE: 0
#Total cycles/instruction ENCODE: -nan
#Total tail cycles/instruction ENCODE: -nan
# Total Errors: 0
```

This indeed shows the breakdown of the ELF file like its sections size, offsets and more. This can be confirmed with the readelf command

```
cexplr@cExplr ~/Desktop/githubFuzz/xed_fuzz $ readelf -S ./xed-func
```

---
## Looking at the payload for this crash

Lets first run the program with the payload

```
cexplr@cExplr ~/Desktop/githubFuzz/xed_fuzz $ ./xed-func -xv 0 -v 0 -i  out_20181114_04_30_10/crash/w01_000010\,sig\:11\,Havoc\:20061\:26112\,src\:w00_000000 
# Found dynamic symtab: 12 offset 0 size 3909091328
Segmentation fault
```

It shows segmentation fault is encountered. Seems like
Let's file the payload.

```
cexplr@cExplr ~/Desktop/githubFuzz/xed_fuzz $ file out_20181114_04_30_10/crash/w01_000010\,sig\:11\,Havoc\:20061\:26112\,src\:w00_000000 
out_20181114_04_30_10/crash/w01_000010,sig:11,Havoc:20061:26112,src:w00_000000: ERROR: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked error reading (Invalid argument)
```

We can now see that it is corrupted in such a way that there is difficulty in determining providing linking details of libraries. This suggest a little lightly that error in file formatting might cause a crash.

Investigating onward, lets use GDB to give us the backtrace.

```
gdb-peda$ file ./xed-func
...
gdb-peda$ run -xv 0 -v 0 -i out_20181114_04_30_10/crash/w01_000010,sig:11,Havoc:20061:26112,src:w00_000000 Starting program: /home/cexplr/Desktop/githubFuzz/xed_fuzz/xed-func -xv 0 -v 0 -i out_20181114_04_30_10/crash/w01_000010,sig:11,Havoc:20061:26112,src:w00_000000
.
.
Stopped reason: SIGSEGV
process_elf32 (fi=0x7fffffffc3c8, start=0x7ffff7ff7000, length=0x594, symbol_table=0x7fffffffc260)
    at xed-disas-elf.c:345
345	xed-disas-elf.c: No such file or directory.
.
.
#0  process_elf32 (fi=0x7fffffffc3c8, start=0x7ffff7ff7000, length=0x594, symbol_table=0x7fffffffc260)
    at xed-disas-elf.c:345
#1  0x0000000000413bc6 in xed_disas_elf (fi=<optimized out>) at xed-disas-elf.c:703
#2  0x00000000004044b4 in main (argc=<optimized out>, argc@entry=0x7, argv=0x400000004, 
    argv@entry=0x7fffffffdc68) at xed.c:841
#3  0x00007ffff7a2d830 in __libc_start_main (main=0x4014f0 <main>, argc=0x7, argv=0x7fffffffdc68, 
    init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc58)
    at ../csu/libc-start.c:291
#4  0x0000000000401419 in _start ()
```