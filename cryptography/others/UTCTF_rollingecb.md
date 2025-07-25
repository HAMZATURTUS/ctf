# UTCTF - Rolling ECB

Category: Cryptography

Difficulty: Medium

## Source:
<img width="448" height="471" alt="image" src="https://github.com/user-attachments/assets/a67bbbe1-120b-4534-8f20-29f2b19626e5" />

### main.py:
```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = open("/src/key", "rb").read()
secret = open("/src/flag.txt", "r").read()
cipher = AES.new(key, AES.MODE_ECB)

while 1:
    print('Enter text to be encrypted: ', end='')
    x = input()
    chksum = sum(ord(c) for c in x) % (len(x)+1)
    pt = x[:chksum] + secret + x[chksum:]
    ct = cipher.encrypt(pad(pt.encode('utf-8'), AES.block_size))
    print(hex(int.from_bytes(ct, byteorder='big')))
```
The challenge is a server that takes an input, runs it through some loop to get a value (chksum). The input string is split into two segments, where the first segment is made of the first chksum characters, and the second is made of the remaining. The flag is placed in between the segments to form the plaintext which is then encrypted by AES_ECB.

```python
input = 'my_plaintext'
chksum = 10
pt = 'my_plainte' + secret + 'xt'

ct = #pt encrypted by AES_ECB
```

## Analysis
AES_ECB is a block cipher where the plaintext is split into evenly sized blocks and run through an encryption using a key

<img width="570" height="232" alt="image" src="https://github.com/user-attachments/assets/5419375b-bb60-4d29-a172-9cd1430265da" />

We can immediately find the block size used by the server:
```py
from Crypto.Cipher import AES

print(AES.block_size) # 16
```
So the plaintext is split into blocks of 16 characters/bytes, and each block is encrypted separately to form a ciphertext, which in this case is given as hex.

```bash
$ nc challenge.utctf.live 7150
Enter text to be encrypted: hello
0xd32a4d241b2166ca5986d3cfb1908786a52a4086d8d695b254085c8a27e12179e0600050fc1a915d62d709e73e7efbac
Enter text to be encrypted: hi
0x7cc2b8f1ee7c0880b0bd4a10c449270d3426dfafc22fbc13caf362d67d2e224790c6d0978743466482ec5a0002046659
Enter text to be encrypted: abc
0x71607444663f212fdf8323286afd98163426dfafc22fbc13caf362d67d2e22475c0d2d66b1b9786ba9b0157fe233254e
Enter text to be encrypted:
```
If we encrypt two identical blocks, they will come out the same in the ciphertext
```bash
$ nc challenge.utctf.live 7150
Enter text to be encrypted: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0xb30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e13bc320fda1bd11f609c0822cda8006b0eef6a828b3df3a3dcb469fa40fd87fca602009c48a7a687a5367657baac6570cb30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1a401cf212691593c4cd6af5b43d0d94a
Enter text to be encrypted:
```
```
b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1
```
Appears more than once in the output. This is because the server has encrypted several blocks, each made of 16 ‘a’s. The other blocks have either been contaminated by the flag or the padding.
Note that the block is made of 32 characters instead of 16. This is because hex represents each byte as 2 digits.

## Solution:
If the server decided that chksum of some input = 15, then the first block would be made of that input with the last letter being the first letter of the flag
```
assuming the flag is flag{test_flag}
pt = XXXXXXXXXXXXXXXf lag{test_flag}XX
	     block 1            block 2
```
Give the server the right input, and it will encrypt a block of 15 already known bytes + the first letter of the flag.  With this encrypted block, we can try to get the server to encrypt:
```
XXXXXXXXXXXXXXXa
XXXXXXXXXXXXXXXb
XXXXXXXXXXXXXXXc
...
```
Until the first block of the ciphertext it returns is equivalent to the first block that we already know contains one byte from the flag. 

To do this for the first character, we can create a payload to send to the server. We just need a string where chksum = 15. This can be done without brute force

```py
def get_num(x):
    chksum = sum((c) for c in x) % (len(x)+1)
    return chksum

# find how far away from 15 the payload is
pl = b'Z' * 15
g = get_num(pl)
diff = g - 15

# replace the first character to get the right chksum value
pl = pl[1:]
add = ord('Z') - diff
pl = bytes([add]) + pl
```

Now, pl can be sent to the server. It will give back a ciphertext (in hex) where the first 32 characters represent the encrypted pl + one character from the flag.

Let’s save this block, and the pl. We need everything about the first block of the plaintext to stay the same, apart from the character we’re trying out.

To find the first character of the flag, we need to send a bunch of blocks where chksum = 16 so that the server can encrypt the whole block and we can find out if it’s the same as the block we saved earlier.

The same offset trick used to make the first pl or a simple brute force can be used to get the new payload we want.

```py
from pwn import *

r = remote('challenge.utctf.live', 7150) # connect to the server

def get_num(x):
    chksum = sum((c) for c in x) % (len(x)+1)
    return chksum

pl = b'Z' * 15
g = get_num(pl)
diff = g - 15
    
pl = pl[1:]
add = ord('Z') - diff
pl = bytes([add]) + pl

print(pl, get_num(pl)) # debugging

r.recv() # 'Enter text to be encrypted: '
r.sendline(pl)

block = (r.recvline()[2:]) # remove 0x
block = block[:32] # take first block

# brute force the character
for j in range(ord('!'), 128): # server crashed when non printable characters were given to it
    pl2 = pl + bytes([j])
    
    if(get_num(pl2) != 16): # brute force to get the right chksum
        for k in range(ord('!'), 128):
            if(get_num(pl2 + bytes([k])) == 16):
                pl2 += bytes([k])
                break
    
    r.recv() # 'Enter text to be encrypted: '
    r.sendline(pl2) # pl + character to brute force
    
    compare_block = r.recvline()[2:]
    compare_block = compare_block[:32]
    
    if(block == compare_block):
        character = bytes([j])
        print("found", character)
        break

```
```bash
[+] Opening connection to challenge.utctf.live on port 7150: Done
b'cZZZZZZZZZZZZZZ' 15
found b'u'
[*] Closed connection to challenge.utctf.live port 7150
```

Just like that, the first character of the flag was found by brute force. To find the rest, we can put all this into a loop where the chksum of the first payload gets smaller by 1 byte for each iteration

```py
r = remote('challenge.utctf.live', 7150)

def get_num(x):
    chksum = sum((c) for c in x) % (len(x)+1)
    return chksum


found = b''

for i in range(15, -1, -1):
    pl = b'Z' * i
    g = get_num(pl)
    diff = g - i
        
    pl = pl[1:]
    add = ord('Z') - diff
    pl = bytes([add]) + pl

    print(pl, get_num(pl)) # debugging

    r.recv() # 'Enter text to be encrypted: '
    r.sendline(pl)

    block = (r.recvline()[2:]) # remove 0x
    block = block[:32] # take first block

    # brute force the character
    for j in range(ord('!'), 128):
        pl2 = pl + found + bytes([j])
        
        if(get_num(pl2) != 16): # brute force to get the right chksum
            for k in range(ord('!'), 128):
                if(get_num(pl2 + bytes([k])) == 16):
                    pl2 += bytes([k])
                    break
        
        assert(get_num(pl2) == 16)
        
        r.recv() # 'Enter text to be encrypted: '
        r.sendline(pl2) # pl + character to brute force
        
        compare_block = r.recvline()[2:]
        compare_block = compare_block[:32]
        
        if(block == compare_block):
            character = bytes([j])
            found += character
            print("found", found)
            break
```
```
Notice the differences between the block in the loop and the block we had earlier.
A new variable (found) was needed so that the character that is being brute forced always ends up at the end of the payload

found = 'u'
pl = 'XXXXXXXXXXXXXX'

server encrypts XXXXXXXXXXXXXX + 2 characters of the flag. One of which we already know is 'u'

pl2 = 'pl' + found + (character to try)
```
```bash
found b'utflag{st0p_'
b'[ZZ' 3
found b'utflag{st0p_r'
b'\\Z' 2
found b'utflag{st0p_r0'
b'[' 1
found b'utflag{st0p_r0l'
b'Z' 0
[*] Closed connection to challenge.utctf.live port 7150
```

It stopped at i = 0. This is because it didn't find a valid payload it could send with a chksum of 0.

Since the flag is longer than 1 block, we can modify the code to “pad away” the first block and do all the work we’ve been doing on the second block instead. This will give us the room we need to find the remaining characters:

```py
r = remote('challenge.utctf.live', 7150)

def get_num(x):
    chksum = sum((c) for c in x) % (len(x)+1)
    return chksum


found = b'utflag{st0p_r0l'

for i in range(16, 0, -1):
    pl = b'Z' * i
    g = get_num(pl)
    diff = g - i
        
    pl = pl[1:]
    add = ord('Z') - diff
    pl = bytes([add]) + pl

    print(pl, get_num(pl)) # debugging

    r.recv() # 'Enter text to be encrypted: '
    r.sendline(pl)

    block = (r.recvline()[2:]) # remove 0x
    block = block[32:] # remove first block
    block = block[:32] # take second block

    # brute force the character
    for j in range(ord('!'), 128):
        pl2 = pl + found + bytes([j])
        
        if(get_num(pl2) != 32): # new chksum must be 32 characters
            for k in range(ord('!'), 128):
                if(get_num(pl2 + bytes([k])) == 32):
                    pl2 += bytes([k])
                    break
        
        assert(get_num(pl2) == 32)
        
        #print(pl2)
        
        r.recv() # 'Enter text to be encrypted: '
        r.sendline(pl2) # pl + character to brute force
        
        compare_block = r.recvline()[2:]
        compare_block = compare_block[32:]
        compare_block = compare_block[:32]
        
        if(block == compare_block):
            character = bytes([j])
            found += character
            print("found", found)
            break

r.close()
```
```
pl = 'XXXXXXXXXXXXXXXX'
server encrypts: XXXXXXXXXXXXXXXX utflag{st0p_r0l?
                     block 1          block 2
now the second block contains the character we're brute forcing

found l
pl = 'XXXXXXXXXXXXXXX'
server encrypts XXXXXXXXXXXXXXXu tflag{st0p_roll?
```
```bash
found b'utflag{st0p_r0ll1ng_y0ur_0wn_'
b'\\Z' 2
found b'utflag{st0p_r0ll1ng_y0ur_0wn_c'
b'[' 1
found b'utflag{st0p_r0ll1ng_y0ur_0wn_cr'
[*] Closed connection to challenge.utctf.live port 7150
```

Again, stopped at i = 0. The code can be rewritten to work on the third block to find the rest of the flag, or the whole thing can be automated without rewriting anything:
```py
from pwn import *
r = remote('challenge.utctf.live', 7150)

def get_num(x):
    
    chksum = sum((c) for c in x) % (len(x)+1)
    return chksum


found = b''


cut = [2, 34, 66]
check = [16, 32, 48]

for c in range(3):
    
    start = 16
    if c == 0: start = 15
    for i in range(start, 0, -1):
        pl = b'Z' * i
        g = get_num(pl)
        diff = g - i
            
        pl = pl[1:]
        add = ord('Z') - diff
        pl = bytes([add]) + pl

        print(pl, get_num(pl)) # debugging

        r.recv() # 'Enter text to be encrypted: '
        r.sendline(pl)

        block = (r.recvline()[cut[c]:]) 
        block = block[:32]

        # brute force the character
        for j in range(ord('!'), 128):
            pl2 = pl + found + bytes([j])
            
            if(get_num(pl2) != check[c]):
                for k in range(ord('!'), 128):
                    if(get_num(pl2 + bytes([k])) == check[c]):
                        pl2 += bytes([k])
                        break
            
            assert(get_num(pl2) == check[c])
            
            #print(pl2)
            
            r.recv() # 'Enter text to be encrypted: '
            r.sendline(pl2) # pl + character to brute force
            
            compare_block = r.recvline()[cut[c]:]
            compare_block = compare_block[:32]
            
            if(block == compare_block):
                character = bytes([j])
                found += character
                print("found", found)
                break

r.close()
```

## Flag
```
utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!!}
```
As the flag states, this attack involves rolling your own known plaintext to get the target letter in the right place so that it’s easy to brute force.
