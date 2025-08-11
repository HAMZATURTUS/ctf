# Esrever

Category: Reverse Eng

Difficulty: Easy

## Source

```bash
> ls
Esrever
> file Esrever
Esrever: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a82793bc74731a748ca4c3ac2f43d0355f65d3c2, for GNU/Linux 3.2.0, not stripped
```

[source](https://drive.google.com/file/d/1ReuWtPv4Bs23h15nZKLD00Q9dC82qxEl/view?usp=sharing)

Running Esrever:

```bash
> ./Esrever 
Tell me which Wonder of the world are you looking to uncover its' secrets?petra
Do you know the secret phrase?no
I cannot reveal it!
```

The program requests two inputs, one after asking "Tell me which Wonder of the world are you looking to uncover its' secrets?" and the other after asking "Do you know the secret phrase?". Given the wrong input, it outputs "I cannot reveal it!"

## Solution

Ltrace is a tool that can run executables and display information about any functions called from shared libraries, most notably: strcmp(). This is useful for debugging programs with weak password checkers such as this one, as we are about to find out.

Running Esrever using ltrace:

```bash
> ltrace ./Esrever
printf("Tell me which Wonder of the worl"...)    = 74
__isoc99_scanf(0x556709c7e053, 0x7ffca29b35d0, 0, 0Tell me which Wonder of the world are you looking to uncover its' secrets?petra
) = 1
printf("Do you know the secret phrase?")         = 30
__isoc99_scanf(0x556709c7e053, 0x7ffca29b3590, 0, 0Do you know the secret phrase?no
) = 1
strcmp("no", "r3v34L_7h3_hiDd3n_TunN3l5")        = -4
puts("I cannot reveal it!"I cannot reveal it!
)                      = 20
+++ exited (status 0) +++
```

According to one of the strcmp(), the secret phrase is "r3v34L_7h3_hiDd3n_TunN3l5"

```bash
> ltrace ./Esrever
printf("Tell me which Wonder of the worl"...)    = 74
__isoc99_scanf(0x559250799053, 0x7fff46ffc420, 0, 0Tell me which Wonder of the world are you looking to uncover its' secrets?petra
) = 1
printf("Do you know the secret phrase?")         = 30
__isoc99_scanf(0x559250799053, 0x7fff46ffc3e0, 0, 0Do you know the secret phrase?r3v34L_7h3_hiDd3n_TunN3l5
) = 1
strcmp("r3v34L_7h3_hiDd3n_TunN3l5", "r3v34L_7h3_hiDd3n_TunN3l5") = 0
strcmp("petra", "P37R4")                         = 32
puts("I cannot reveal it!"I cannot reveal it!
)                      = 20
+++ exited (status 0) +++
```

The program was looking for us to have "P37R4" as the first input.

```bash
> ltrace ./Esrever
printf("Tell me which Wonder of the worl"...)    = 74
__isoc99_scanf(0x55d8148aa053, 0x7ffd2bd1dfb0, 0, 0Tell me which Wonder of the world are you looking to uncover its' secrets?P37R4
) = 1
printf("Do you know the secret phrase?")         = 30
__isoc99_scanf(0x55d8148aa053, 0x7ffd2bd1df70, 0, 0Do you know the secret phrase?r3v34L_7h3_hiDd3n_TunN3l5
) = 1
strcmp("r3v34L_7h3_hiDd3n_TunN3l5", "r3v34L_7h3_hiDd3n_TunN3l5") = 0
strcmp("P37R4", "P37R4")                         = 0
puts("The secret tunnel lies within - "...The secret tunnel lies within - NCSC{<Wonder_Name>:<Secret_Phrase>}
)      = 68
+++ exited (status 0) +++
```

Nice and easy

## Flag

```
NCSC{P37R4:r3v34L_7h3_hiDd3n_TunN3l5}
```
