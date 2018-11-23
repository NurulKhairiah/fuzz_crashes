# Crash #2
---

## Overview

#### Input : Malformed ELF which contains corrupted information of ELF with also the wrong magic number.
While it is able to determine what section names there are, it is not able to be given the memory most likely because the section offset are wrong and modified. This causes the program to give a wrong and possible and even wrong and impossible memory offset pointing to memory space outside the allowable range.

---
## Looking at payload, crash and backtrace

As we can see from the analysis of [crash_1](../crash_1/1_xed_crash_w01_000010), the intended usage with the `-xv 0 -v 0 -i <ELF>` should decode the ELF file like this.

```
cexplr@cExplr ~/Desktop/githubFuzz/xed_fuzz $ ./xed-func -xv 0 -v 0 -i hello 
# Found dynamic strtab: 6 offset 318 size 3f
# Found strtab: 30 offset 16b8 size 215
# Found dynamic symtab: 5 offset 2b8 size 60
# Found symtab: 29 offset 1070 size 648
# SECTION 11                     .init addr 4003c8 offset 3c8 size 26
# end of text section.
# Errors: 0
# SECTION 12                      .plt addr 4003f0 offset 3f0 size 48
# end of text section.
# Errors: 0
# SECTION 13                  .plt.got addr 400420 offset 420 size 8
# end of text section.
# Errors: 0
# SECTION 14                     .text addr 400430 offset 430 size 386
# end of text section.
# Errors: 0
# SECTION 15                     .fini addr 4005b4 offset 5b4 size 9
# end of text section.
# Errors: 0
#XED3 DECODE STATS
#Total DECODE cycles:        80338
#Total instructions DECODE: 88
#Total tail DECODE cycles:        450170
#Total tail instructions DECODE: 138
#Total cycles/instruction DECODE: 912.93
#Total tail cycles/instruction DECODE: 3262.10
#XED3 ENCODE STATS
#Total ENCODE cycles:        0
#Total instructions ENCODE: 0
#Total tail ENCODE cycles:        0
#Total tail instructions ENCODE: 0
#Total cycles/instruction ENCODE: -nan
#Total tail cycles/instruction ENCODE: -nan
# Total Errors: 0
```

With [w01_000200,sig:11,Havoc:18125:19648,src:w01_018631](w01_000200,sig:11,Havoc:18125:19648,src:w01_018631), it crashes the program. 

Let's see what this file is about.

```
gdb-peda$ shell file w01_000200,sig:11,Havoc:18125:19648,src:w01_018631 
w01_000200,sig:11,Havoc:18125:19648,src:w01_018631: data
```

Also like the first crash, we can see that it is a data file and when we put it into a hexeditor, the ELF magic number is wrong too. As expected, it does not stop the program from exiting which is also the same as the first crash that we analyzed and that is because the e_machine byte is compared and not the magic number.

Using GDB as per the first crash analysis,

```Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x7fffffffc528 --> 0x400000001 
RCX: 0x0 
RDX: 0xba4bb0 --> 0x0 
RSI: 0x7fffffffc528 --> 0x400000001 
RDI: 0x7fffffffc528 --> 0x400000001 
RBP: 0x0 
RSP: 0x7fffffffb190 --> 0x0 
RIP: 0x408ac1 (<xed_disas_test+1041>:	cmp    BYTE PTR [r13+rcx*1+0x0],0x0)
R8 : 0xfffffffffffffffc 
R9 : 0x0 
R10: 0x0 
R11: 0x246 
R12: 0xfffffffffffffffc 
R13: 0x7f7ff7ff7000 
R14: 0x0 
R15: 0xe9ffffff
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x408ab3 <xed_disas_test+1027>:	inc    BYTE PTR [rdx+rcx*1]
   0x408ab6 <xed_disas_test+1030>:	mov    DWORD PTR fs:[r12],0x2f7c
   0x408abf <xed_disas_test+1039>:	mov    ecx,eax
=> 0x408ac1 <xed_disas_test+1041>:	cmp    BYTE PTR [r13+rcx*1+0x0],0x0
   0x408ac7 <xed_disas_test+1047>:	jne    0x408b40 <xed_disas_test+1168>
   0x408ac9 <xed_disas_test+1049>:	inc    eax
   0x408acb <xed_disas_test+1051>:	movsxd rcx,DWORD PTR fs:[r12]
   0x408ad0 <xed_disas_test+1056>:	mov    rdx,QWORD PTR [rip+0x7869e9]        # 0xb8f4c0 <__fot_area_ptr>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffb190 --> 0x0 
0008| 0x7fffffffb198 --> 0x1 
0016| 0x7fffffffb1a0 --> 0x7fffffffc528 --> 0x400000001 
0024| 0x7fffffffb1a8 --> 0x27e00000000 
0032| 0x7fffffffb1b0 --> 0x814 
0040| 0x7fffffffb1b8 --> 0x0 
0048| 0x7fffffffb1c0 --> 0x0 
0056| 0x7fffffffb1c8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000408ac1 in all_zeros (len=<optimized out>, p=<optimized out>) at xed-examples-util.c:861
861	xed-examples-util.c: No such file or directory.
gdb-peda$ where
#0  0x0000000000408ac1 in all_zeros (len=<optimized out>, p=<optimized out>) at xed-examples-util.c:861
#1  xed_disas_test (di=<optimized out>) at xed-examples-util.c:1185
#2  0x000000000041261e in disas_test64 (fi=0x7fffffffc528, start=0x7ffff7ff7000, offset=0x0, symbol_table=0x7fffffffc3c0, length=<optimized out>, size=<optimized out>, runtime_vaddr=<optimized out>) at xed-disas-elf.c:308
#3  process_elf64 (fi=0x7fffffffc528, start=0x7ffff7ff7000, length=<optimized out>, symbol_table=0x7fffffffc3c0) at xed-disas-elf.c:452
#4  0x0000000000413296 in xed_disas_elf (fi=<optimized out>) at xed-disas-elf.c:699
#5  0x00000000004044b4 in main (argc=<optimized out>, argc@entry=0x7, argv=0x400000004, argv@entry=0x7fffffffddc8) at xed.c:841
#6  0x00007ffff7a2d830 in __libc_start_main (main=0x4014f0 <main>, argc=0x7, argv=0x7fffffffddc8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffddb8) at ../csu/libc-start.c:291
#7  0x0000000000401419 in _start ()
gdb-peda$ 
```

---

## Crash Analysis

Recall from the first crash that when it is compared to 0x2, it is a x64 ELF type file and if 0x3E, it is a x86 ELF type. Now the program thinks that this input file is a 64 bit file which should immediately terminate but does not.

Comparing the number of lines of code for for analyzing x86 and x64, there are way lot more of awesome and interesting things that is happening. I do not understand the details of the implementation however, we can try to make some smart guesses. 

To help me, I used radare2 in this case. It will take a while to load and analyze the symbols but it wont take longer than 5 mins.

I am using this also because there are  helper lines to help me see where the jumps instruction will jump to if condition is true or for any unconditional jumps. Typing VV command for a shorter function can help you visually see the control flow.

```
 r2 -d ../xed-func
> aaa
> s sym.xed_disas_elf


and optionally

> VVV
```

I also referenced a little with a version of the xed_disas_elf function at [https://github.com/intelxed/xed/blob/master/examples/xed-disas-elf.c#L223](https://github.com/intelxed/xed/blob/master/examples/xed-disas-elf.c#L223) in an attempt to help me understand a little better and it will be easier to see what are some of the differences from this version to the current updated version.

The source code MAY NOT TOTALLY BE MATCHING SINCE THEY OF DIFFERNET VERSION

```c
void
process_elf64(xed_disas_info_t* fi,
              void* start,
	      unsigned int length,
              xed_symbol_table_t* symbol_table)
{
    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*) start;
    Elf64_Off shoff = elf_hdr->e_shoff;  // section hdr table offset
    Elf64_Shdr* shp = (Elf64_Shdr*) ((char*)start + shoff);
    Elf64_Half sect_strings  = elf_hdr->e_shstrndx;
    Elf64_Half nsect = elf_hdr->e_shnum;
    unsigned char* hard_limit = (unsigned char*)start + length;
    unsigned int i;
    xed_bool_t text = 0;

    if (CLIENT_VERBOSE1) 
        printf("# sections %d\n" , nsect);
    
    if ((void*)shp < start)
        return;

    for( i=0;i<nsect;i++)  {
        char* name = 0;
        
        if (range_check(shp+i,sizeof(Elf64_Shdr), start, hard_limit))
            break;
        if (range_check(shp+sect_strings,sizeof(Elf64_Shdr), start, hard_limit))
            break;
        
        name = lookup64(shp[i].sh_name, start, length,
                        shp[sect_strings].sh_offset);
        
        text = 0;
        if (shp[i].sh_type == SHT_PROGBITS) {
            if (fi->target_section) {
                if (name && strcmp(fi->target_section, name)==0) 
                    text = 1;
            }
            else if (shp[i].sh_flags & SHF_EXECINSTR)
                text = 1;
        }

        if (text) {
            if (fi->xml_format == 0) {
                printf("# SECTION " XED_FMT_U " ", i);
                printf("%25s ", name);
                printf("addr " XED_FMT_LX " ",
                       XED_STATIC_CAST(xed_uint64_t,shp[i].sh_addr)); 
                printf("offset " XED_FMT_LX " ",
                       XED_STATIC_CAST(xed_uint64_t,shp[i].sh_offset));
                printf("size " XED_FMT_LU "\n", 
                       XED_STATIC_CAST(xed_uint64_t,shp[i].sh_size));
            }
            xst_set_current_table(symbol_table,i);
            disas_test64(fi, 
                         start, length, shp[i].sh_offset, shp[i].sh_size, 
                         shp[i].sh_addr, symbol_table);
        }
    }
}

```
As I loop through, I realised that there are two loops going on which when i stepped side by side, there are quite a number of sections which is denoted by `nsect` variable which acts like a counter for the two loops. 

After the two loops, the process_elf64 function is invoked 

```
process_elf64 (fi=0x7fffffffc528, start=0x7ffff7ff7000, length=0x617, symbol_table=0x7fffffffc3c0)
```

Verbosity is checked as well as some variables are intiialized.

The line with code 
```c
if ((void*)shp < start)
        return;
```

is probably 

```
R15: 0x7ffff7ff7617 --> 0x0
...
...
[-------------------------------------code-------------------------------------]
   0x41236c <process_elf64+300>:	lea    rax,[r13+r12*1+0x40]
   0x412371 <process_elf64+305>:	cmp    r15,rax
   0x412374 <process_elf64+308>:	jb     0x41265a <process_elf64+1050>
```

and the chunk of printf statements are found from `0x004124ee` to `0x0041256d` as shown below

```
| |||||:|   0x004124ee      bf3a107a00     mov edi, str.SECTION__u     ; 0x7a103a ; "# SECTION %u "
| |||||:|   0x004124f3      31c0           xor eax, eax
| |||||:|   0x004124f5      89ee           mov esi, ebp
| |||||:|   0x004124f7      e8a4ecfeff     call sym.imp.printf         ; int printf(const char *format)
| |||||:|   0x004124fc      bffb0f7a00     mov edi, str.25s            ; 0x7a0ffb ; "%25s "
| |||||:|   0x00412501      31c0           xor eax, eax
| |||||:|   0x00412503      4889de         mov rsi, rbx
| |||||:|   0x00412506      e895ecfeff     call sym.imp.printf         ; /media/lyk/data1/moowd/xed/fot-func/examples/xed-disas-elf.c:191 ; int printf(const char *format)
| |||||:|   0x0041250b      4889eb         mov rbx, rbp
| |||||:|   0x0041250e      48c1e306       shl rbx, 6
| |||||:|   0x00412512      488b442408     mov rax, qword [local_8h]   ; [0x8:8]=-1 ; 8
| |||||:|   0x00412517      488d441810     lea rax, [rax + rbx + 0x10] ; 16
| |||||:|   0x0041251c      4889442428     mov qword [local_28h], rax
| |||||:|   0x00412521      4b8b742510     mov rsi, qword [r13 + r12 + 0x10] ; [0x10:8]=-1 ; 16
| |||||:|   0x00412526      bf01107a00     mov edi, str.addr__lx       ; /media/lyk/data1/moowd/xed/fot-func/examples/xed-disas-elf.c:193 ; 0x7a1001 ; "addr %lx "
| |||||:|   0x0041252b      31c0           xor eax, eax
| |||||:|   0x0041252d      e86eecfeff     call sym.imp.printf         ; int printf(const char *format)
| |||||:|   0x00412532      488b442408     mov rax, qword [local_8h]   ; [0x8:8]=-1 ; 8
| |||||:|   0x00412537      488d441818     lea rax, [rax + rbx + 0x18] ; 24
| |||||:|   0x0041253c      4889442420     mov qword [local_20h], rax
| |||||:|   0x00412541      4b8b742518     mov rsi, qword [r13 + r12 + 0x18] ; [0x18:8]=-1 ; 24
| |||||:|   0x00412546      bf0b107a00     mov edi, 0x7a100b           ; /media/lyk/data1/moowd/xed/fot-func/examples/xed-disas-elf.c:195
| |||||:|   0x0041254b      31c0           xor eax, eax
| |||||:|   0x0041254d      e84eecfeff     call sym.imp.printf         ; int printf(const char *format)
| |||||:|   0x00412552      488b442408     mov rax, qword [local_8h]   ; [0x8:8]=-1 ; 8
| |||||:|   0x00412557      488d441820     lea rax, [rax + rbx + 0x20] ; 32
| |||||:|   0x0041255c      4889442418     mov qword [local_18h], rax
| |||||:|   0x00412561      4b8b742520     mov rsi, qword [r13 + r12 + 0x20] ; [0x20:8]=-1 ; 32
| |||||:|   0x00412566      bf48107a00     mov edi, str.size__lu       ; 0x7a1048 ; "size %lu\n"
| |||||:|   0x0041256b      31c0           xor eax, eax
| |||||:|   0x0041256d      e82eecfeff     call sym.imp.printf         ; int printf(const char *format)
```

After the printing, xst_set_current_table is called followed by disas_test64 of which there were seemingly no problems
Also, when we try to breakpoint at where we crash, we find that it is in a loo. So till we crash, we will continue to execute.

```

THIS IS THE LOG OF THE VALUE OF ADDRESS THAT THE PROGRAM IS ATTEMPTING TO ACCESS

b *0x4123b2

gdb-peda$ x/wx $r13+$r12+0x4

gdb-peda$ c       till we crash


0x7ffff7ff7008:	0x0080b4b4
0x7ffff7ff7048:	0x00000c08
0x7ffff7ff7088:	0x6f6c6c65
0x7ffff7ff70c8:	0x00000000
0x7ffff7ff7108:	0x00040028
0x7ffff7ff7148:	0x00000001
0x7ffff7ff7188:	0x20003400
0x7ffff7ff71c8:	0x00000001
0x7ffff7ff7208:	0x20003400
0x7ffff7ff7248:	0x00000001

THEN WHEN CRASH ...

gdb-peda$ x/wx $r13+$r12+0x4
0x7f7ff7ff7000:	Cannot access memory at address 0x7f7ff7ff7000
```

It crashes on the 11th one and referencing the source code, most likely the nsect was stated however it is trying to access the corrupted part where the "expected" section is located at. 

Now, process_elf64 has 2 loops of which the two loops has the same loop conditions. Also the crash happened on the second one. So as I stepped through, I counted that the first loop iterated 24 times while the second only 10 or 11. This means that somewhere down in the code as shown below, it is trying to reference to a violated memory address pointing to `0x7f7ff7ff7000`. This is the reason why it crashes. As for the format and how to craft the payload. I have not enough time to determine and reproduce one. It will be interesting for future work.

---


#### Input : Malformed ELF which contains corrupted information of ELF with also the wrong magic number.

While it is able to determine what section names there are, it is not able to be given the memory most likely because the section offset are wrong and modified. This causes the program to give a wrong and possible and even wrong and impossible memory offset pointing to memory space outside the allowable range.

---