## Case 1 - Malformed ELF

I tried to create a text.txt file with 

``` echo 'Hello World'>text.txt``` and used it as an argument of strings and it does print it out successfully before aborting.

``` 
cexplr@cExplr  ~/Desktop/test-strings-fot/out_20181120_12_17_11/crash  ../../strings text.txt     
Hello World
```

I then used strace command to see what system calls are being called.

```
 cexplr@cExplr  ~/Desktop/test-strings-fot/out_20181120_12_17_11/crash  strace ../../strings  text.txt
execve("../../strings", ["../../strings", "text.txt"], [/* 57 vars */]) = 0
brk(NULL)                               = 0x1174000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=140546, ...}) = 0
mmap(NULL, 140546, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd4c198c000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fd4c198b000
mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fd4c13c0000
mprotect(0x7fd4c1580000, 2097152, PROT_NONE) = 0
mmap(0x7fd4c1780000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1c0000) = 0x7fd4c1780000
mmap(0x7fd4c1786000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fd4c1786000
close(3)                                = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fd4c198a000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fd4c1989000
arch_prctl(ARCH_SET_FS, 0x7fd4c198a700) = 0
mprotect(0x7fd4c1780000, 16384, PROT_READ) = 0
mprotect(0x6f6000, 4096, PROT_READ)     = 0
mprotect(0x7fd4c19af000, 4096, PROT_READ) = 0
munmap(0x7fd4c198c000, 140546)          = 0
write(199, "\232\2\0\0", 4)             = -1 EBADF (Bad file descriptor)
brk(NULL)                               = 0x1174000
brk(0x1195000)                          = 0x1195000
open("/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=2981280, ...}) = 0
mmap(NULL, 2981280, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd4c10e8000
close(3)                                = 0
open("/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=26258, ...}) = 0
mmap(NULL, 26258, PROT_READ, MAP_SHARED, 3, 0) = 0x7fd4c19a8000
close(3)                                = 0
stat("text.txt", {st_mode=S_IFREG|0664, st_size=12, ...}) = 0
open("text.txt", O_RDONLY)              = 3
fstat(3, {st_mode=S_IFREG|0664, st_size=12, ...}) = 0
read(3, "Hello World\n", 4096)          = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
lseek(3, 12, SEEK_SET)                  = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
read(3, "", 4096)                       = 0
lseek(3, 0, SEEK_SET)                   = 0
read(3, "Hello World\n", 4096)          = 12
lseek(3, 12, SEEK_SET)                  = 12
lseek(3, 12, SEEK_SET)                  = 12
lseek(3, 12, SEEK_SET)                  = 12
close(3)                                = 0
open("text.txt", O_RDONLY)              = 3
fstat(3, {st_mode=S_IFREG|0664, st_size=12, ...}) = 0
read(3, "Hello World\n", 4096)          = 12
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
write(1, "Hello World\n", 12Hello World
)           = 12
read(3, "", 4096)                       = 0
close(3)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++

```

I have also tried it with a binary file since challenges in CTF challenges requires just a string command to find an easy flag. I tried to string the string binary also and there were no errors.

On the contrary, we have the input `w01_000014,sig:11,Havoc:1770:18304,src:w00_000000` under the crash directory. This apparently is a file.

```
docker@fffb77539f24:~/test-strings-fot$ file  out_20181121_04_03_22/crash/w01_000010\,sig\:11\,Havoc\:1936\:18304\,src\:w00_000000 
out_20181121_04_03_22/crash/w01_000010,sig:11,Havoc:1936:18304,src:w00_000000: ERROR: ELF 32-bit LSB executable, SPARC32PLUS, total store ordering, (SYSV) error reading (Invalid argument)
```

Turns out a file was generated with errors and that it is a 32 bit one.


Let first run this program against this input file.
```
docker@fffb77539f24:~/test-strings-fot$ ./strings out_20181121_04_03_22/crash/w01_000010\,sig\:11\,Havoc\:1936\:18304\,src\:w00_000000 
Segmentation fault (core dumped)
```
Here there is proof of a crash. SIGSEGV here usually mean that the program is trying to access memory that is not intended and is protected against.

Let's try to disassemble the binary file. Before that, let file it

```
docker@fffb77539f24:~/test-strings-fot$ file strings 
strings: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped
```

Here the program is an ELF type file executable, 64 bits and dynamically linked with external libraries and also all the debugging symbols are not stripped away meaning that disassembling with GDB will be pleasant.

With that in mind, we can go on with GDB analysis.

We first fire up GDB and set file as strings then run it with the input file

```
(gdb) file strings
Reading symbols from strings...done.

(gdb) r out_20181121_04_03_22/crash/w01_000010,sig:11,Havoc:1936:18304,src:w00_000000 
Starting program: /home/docker/test-strings-fot/strings out_20181121_04_03_22/crash/w01_000010,sig:11,Havoc:1936:18304,src:w00_000000

Program received signal SIGSEGV, Segmentation fault.
0x000000000040f8ee in bfd_hash_lookup (table=0x71c0f0, string=0x0, create=1, copy=0) at ../../bfd/hash.c:374
374	../../bfd/hash.c: No such file or directory.
(gdb) 
```

There seem to be a fault and a No such file or directory is being message is being printed out. 

Let's attempt a backtrace by typing `where` or `backtrace` or `bt` in short.

```
gdb-peda$ where
#0  0x0000000000431c39 in bfd_section_from_shdr (abfd=0x71e180, shindex=0x3) at ../../bfd/elf.c:1657
#1  0x0000000000477dbb in bfd_elf32_object_p (abfd=0x71e180) at ../../bfd/elfcode.h:689
#2  0x0000000000408d91 in bfd_check_format_matches (abfd=0x71e180, format=<optimized out>, matching=0x0) at ../../bfd/format.c:228
#3  0x000000000040298f in strings_object_file (file=<optimized out>) at ../../binutils/strings.c:350
#4  strings_file (file=<optimized out>) at ../../binutils/strings.c:380
#5  main (argc=argc@entry=0x2, argv=argv@entry=0x7fffffffdde8) at ../../binutils/strings.c:298
#6  0x00007ffff7a2d830 in __libc_start_main (main=0x402020 <main>, argc=0x2, argv=0x7fffffffdde8, init=<optimized out>, 
    fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffddd8) at ../csu/libc-start.c:291
#7  0x0000000000401f49 in _start ()
```
 Here in frame #1, we see that there is an error with bfd_section_from_shdr. BFD is a utility that has muliple purposes. It includes:
 
    -  Identifying executables and core files
      + Identify variety of file types
    -  Access to sections of files
      + Parses file header to determine names, virtual addresses, sizes, etc
    -  Specialized core file supports
    -  Locating the symbol information
      
      + Helps determine where to find symbopl information  

  For more information about Binary File Descriptors, checkout [https://docs.freebsd.org/info/gdbint/gdbint.info.BFD_support_for_GDB.html](https://docs.freebsd.org/info/gdbint/gdbint.info.BFD_support_for_GDB.html)

and [https://www.slac.stanford.edu/comp/unix/package/rtems/doc/html/bfd/bfd.info.BFD_front_end.html](https://www.slac.stanford.edu/comp/unix/package/rtems/doc/html/bfd/bfd.info.BFD_front_end.html)

One thing to note is that the lower the number of frame number, the more recent the execution. With BFD trying to determine the number of section headers which is counted by index. Naturally, this also mean that the string table index must not exceed the total size. This makes sense because accessing item outside an array will cause unintended and even unauthorized accessing of memory. 

Example:

```c
int arr1[3]={0,0,0};
int x = arr1[3];  //ERROR!!
```

Since the program gives a segfault, we can most likely determine that NX bit is set to protect the binary.

To check, we use the command checksec

```
 cexplr@cExplr  ~/Desktop/test-strings-fot  checksec ./strings                                           
[*] '/home/cexplr/Desktop/SCSE/test-strings-fot/strings'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Indeed NX bit is set! 

Let's see what is happening at the header information of this ELF file.

Also, we can see that the file is corrupted.
```
 cexplr@cExplr ~/Desktop/test-strings-fot  readelf -h  out_20181116_07_01_18/crash/w01_000010,sig:11,Havoc:956:18304,src:w00_000000

ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 1e 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8048074
  Start of program headers:          52 (bytes into file)
  Start of section headers:          164 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         2
  Size of section headers:           40 (bytes)
  Number of section headers:         2      # INDEX MUST NEVER EXCEED THIS!!!!
  Section header string table index: 3 <corrupt: out of range>  # CULPRIT IS HERE
```

This proves that the file is malformed and thus gives trouble to the strings program in determining the file type. This is most likely due to the fact that there is no error checking to make sure that section header table index is smaller than the total number of section headers.

I have found similar troubles and that version of strings has since been patched.
It can be found here
[https://sourceware.org/bugzilla/attachment.cgi?id=10814&action=diff](https://sourceware.org/bugzilla/attachment.cgi?id=10814&action=diff).

Thus this error is caused by strings program trying to determine the type of file which leads to it trying to access memory outside of the intended space. Since header of ELF is used to determine the structure of the ELF file, section header string table index outside of range misleads strings into thinking that the file provided is correct and thus offsets the rest of the file inappropriately.

This also suggests that we can falsely flip some bits in the header and it may cause memory access violation.

#### Input : Malformed ELF file

Tried the files we have collected so far on the current version of strings and thankfully and sadly (grade wise), we were not able to reproduce the results. We did with a script.

```
for i in *;do strings $i; if [[ $(strings $i) == *"Seg"* ]]; then echo "OHHHHSHIT"; sleep 5; fi; done
```

and to check if their exit code is not zero

```
for i in *; do ../../strings $i; if ! [[ $? == "0" ]]; then echo "SOMETHING IS WRONG HERE";sleep 0.9 ;fi; done
```
---
