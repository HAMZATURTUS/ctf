# for this challenge, we connect to a server that runs:

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

'''

it takes an input text, splits it up into two segments, the length of those segments determined by some function, then inserts the flag between them. the final thing is encrypted using some key by AES ECB

pt = segment1 + flag + segment2

since AES ECB is a block cipher, this shouldnt be too hard

connecting to the server:

$ nc challenge.utctf.live 7150
Enter text to be encrypted: hello
0xd32a4d241b2166ca5986d3cfb1908786a52a4086d8d695b254085c8a27e12179e0600050fc1a915d62d709e73e7efbac
Enter text to be encrypted: hi
0x7cc2b8f1ee7c0880b0bd4a10c449270d3426dfafc22fbc13caf362d67d2e224790c6d0978743466482ec5a0002046659
Enter text to be encrypted: abc
0x71607444663f212fdf8323286afd98163426dfafc22fbc13caf362d67d2e22475c0d2d66b1b9786ba9b0157fe233254e
Enter text to be encrypted:

runs as expected

the interesting thing about this challenge is that the server does not stop asking for inputs, so a brute force attack is possible

at this point it should be obvious that finding the key is impossible as the only way to do that is to either brute force the 16 or 8 byte key or to understand the inner workings of AES ECB which is equally painful

the server uses the same key, so if we encrypt 16 'a's for example and do that twice we would get the same value:

$ nc challenge.utctf.live 7150
Enter text to be encrypted: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0xb30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e13bc320fda1bd11f609c0822cda8006b0eef6a828b3df3a3dcb469fa40fd87fca602009c48a7a687a5367657baac6570cb30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1a401cf212691593c4cd6af5b43d0d94a
Enter text to be encrypted:

b30f4d846cd009c8f5b892b534e647e1b30f4d846cd009c8f5b892b534e647e1 is repeated in the output of the server

this is expected, because we have encrypted several blocks of a + the flag + several blocks of a.

interestingly, the last block is not identical to the first, that must be due to the padding.


one way to get the flag is to send 15 'a's to the server, that way the first block would be made of (15 a's + 1 letter from the flag), then we can try sending (15 'a' + brute force this byte) until we get the same ciphertext we got when we encrypted 15 a's and the first byte of the flag.

one problem, the input i send gets pushed through a function so that it can be split into two segments, THEN it will be joined with the flag and encrypted
so sending 15 a's might not yield expected results.

in order to bypass this issue, i filled my first payload with 15 Z's, and calculated the chksum value myself. then i made the script change the first letter of the payload so that the chksum value would be equal to my goal value (15)

'''

def get_num(x):
    
    chksum = sum((c) for c in x) % (len(x)+1)
    return chksum

pl = b'Z' * 15
g = get_num(pl)
diff = g - 15
    
pl = pl[1:]
add = ord('Z') - diff
pl = bytes([add]) + pl

'''

cool, now i can send this to the server and get the encrypted version of (pl + first character of the flag) in return.
to find this first character, i have to brute force j in (pl + j). as soon as i get a block identical to the block i got when i first sent pl, id have gotten the first character of the flag

one more time, we reached the issue of the chksum function, which may not send the correct plaintext to the encryption function of the server.
i cant change the first byte of the new payload this time, the first 15 bytes must be identical to the first payload i sent
to bypass this, i added a new character to the end of the payload and brute forced its value to get the target chksum (16)

'''

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
    
    if(get_num(pl2) != 16):
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
    

'''

running this we get:
[+] Opening connection to challenge.utctf.live on port 7150: Done
b'cZZZZZZZZZZZZZZ' 15
found b'u'
[*] Closed connection to challenge.utctf.live port 7150

cool, we found the first letter of the flag. now we want to automate this process for the other letters

everytime we find a letter, the first payload will have to shrink by one character so that pl2 can be (pl + found parts of flag + character to brute force)

'''

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
        
        if(get_num(pl2) != 16):
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

'''
found b'utflag{st0p_'
b'[ZZ' 3
found b'utflag{st0p_r'
b'\\Z' 2
found b'utflag{st0p_r0'
b'[' 1
found b'utflag{st0p_r0l'
b'Z' 0
[*] Closed connection to challenge.utctf.live port 7150

it's working pretty well, albeit a bit slow, but it seems to have gotten stuck at i = 0.

we can rerun the code with our new flag and use the second block of the ciphertexts instead of the first this time.

so we can do

16 * 'Z' + 15 bytes of found flag + byte to brute force

'''

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
        
        if(get_num(pl2) != 32):
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

'''

found b'utflag{st0p_r0ll1'
b'hZZZZZZZZZZZZZ' 14
found b'utflag{st0p_r0ll1n'
b'_ZZZZZZZZZZZZ' 13
Traceback (most recent call last):

it's working but occasionally stops from an eof error, probably from the server being overwhelmed

if i keep rerunning the file and updating found to the new found flag and the starting value of the first loop, i can build up until i get the full flag

found b'utflag{st0p_r0ll1ng_y0ur_0wn_'
b'\\Z' 2
found b'utflag{st0p_r0ll1ng_y0ur_0wn_c'
b'[' 1
found b'utflag{st0p_r0ll1ng_y0ur_0wn_cr'
[*] Closed connection to challenge.utctf.live port 7150

once again, stopped at 0. so we can rewrite the code to take from the third block
the whole first, second, third block thing can definitely be automated but the server crashes so often that it's not even worth it to try to do something like that when you're going to monitor the program anyway

found b'utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!'
b'_ZZZZZZZZZZ' 11
found b'utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!!'
b'[ZZZZZZZZZ' 10
found b'utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!!}'
b'cZZZZZZZZ' 9
b'bZZZZZZZ' 8

very nice.



'''
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

'''
a fully automated solution to this challenge looks something like this but theres so much interaction with the server that an (n^2) brute force where n is 100 at most ends up taking around 10 minutes

found b'utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!!'
b'[ZZZZZZZZZ' 10
found b'utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!!}'
b'cZZZZZZZZ' 9
b'bZZZZZZZ' 8
b'[ZZZZZZ' 7
Traceback (most recent call last):

it works nicely, only missing an if b'}' in found -> finish

'''
