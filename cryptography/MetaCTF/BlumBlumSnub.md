# MetaCTF - BlumBlumSnub
### Author: Saleh Elnaji

Category: Cryptography

Difficulty: Medium

## Source
```bash
> ls
BlumBlumSnub.py
```
### BlumBlumSnub.py
```python
from Crypto.Util.number import *
from pwn import xor
import uuid
from hashlib import sha256
import os

print(f'FOR SECURITY REASONS (NOT A HINT I SWEAR) : {sha256(uuid.uuid4().bytes).hexdigest()}')  

FLAG = os.getenv("FLAG", "METACTF{FAKE_FLAG}")

class BlumBlumSnub:
    def __init__(self, p: int, q: int, seed: int = None):
        self.p = p
        self.q = q
        self.m = p * q
        self.state = seed if seed is not None else getRandomInteger(512)

    def next(self) -> int:
        self.state = (self.state * self.state) % self.m
        return self.state 
    
    def get_hint(self) -> bytes:
        x = getRandomInteger(1)
        if x == 0:
            return long_to_bytes(self.next() % self.p)
        else:
            return long_to_bytes(self.next() % self.q)
    
p = getPrime(512)
q = p + 1
while not isPrime(q):
    q += 1

blum_blum_shub = BlumBlumSnub(p, q)

def get_flag():
    return xor(FLAG.encode(), long_to_bytes(blum_blum_shub.next())[:len(FLAG)])

ct = get_flag()

for i in range(3):
    blum_blum_shub.next()

banner = """
      /`·.¸
     /¸...¸`:·
 ¸.·´  ¸   `·.¸.·´)
: © ):´;      ¸  {
 `·.¸ `·  ¸.·´\`·¸)
     `\\´´\¸.·´
     
Welcome to Aqaba!
"""
menu = """
1. Get hint
2. Snub
"""


def main():
    print(banner)
    print(f"n: {blum_blum_shub.m}")
    print(f'ct: {ct.hex()}')
    while True:
        print(menu)
        choice = input("Choose an option: ")
        if choice == '1':
            random_bytes = blum_blum_shub.get_hint()
            print(f"Hint: {random_bytes.hex()}")
        elif choice == '2':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")
            
if __name__ == "__main__":
    main()
```

Connecting to the server:

```bash
  `·.¸ `·  ¸.·´\`·¸)
FOR SECURITY REASONS (NOT A HINT I SWEAR) : de569ae4e9471872314f0970dc43a877829a44617da8ff1f6aa67477fa566fc1

      /`·.¸
     /¸...¸`:·
 ¸.·´  ¸   `·.¸.·´)
: © ):´;      ¸  {
 `·.¸ `·  ¸.·´\`·¸)
     `\´´\¸.·´
     
Welcome to Aqaba!

n: 52004979879787872904572830981193648623735649824909880379954617345102421835108325670268618239977932041523265473373333191743304900780154863819258072421637308289293327206386301324203822902642469116895460154056270469303515396889079704619978145241651376091666171601904244784368845645846480534814716708180605790013
ct: 4f2b8d495ccecdd4f60f2cd9a573030a0d7c086df12766fff9ae2d1e7d1ce39198c634029a2979fe086851709b86dab00bd6be

1. Get hint
2. Snub

Choose an option: 1
Hint: 7567ad08ccd803cae284fd6f25a1052e9434fb99f540b85d484b1fbda40d450af34b1b25cdc3e4e38de03d62a51663ec96a12fe8f5a896a97b1510625f2879ed

1. Get hint
2. Snub

Choose an option: 1
Hint: 24039c326e63f9080e788bffa1c802623e739e3450cc1a1f72389ffd26a0086851fde2c9c345545fe687658dbca78ff6bda371b8b4ebe6585e39aa69a48365f1

1. Get hint
2. Snub

Choose an option: 1
Hint: 4900fd820808932971d176c87ec33b31284a05794ea4939f3c8a9d6b8d8a1bd5a9497abd184875872fe3dbc141285574203d872b0f97032da2806700c5de176d

1. Get hint
2. Snub

Choose an option: 1
Hint: 8038c7cb2a8c1e3110607014c42a6e3ece7e162f7e635a5380413fb69aaa2839236615b55310d1c91feef1eec020f5729d862694d496bbb105c9744f228825

1. Get hint
2. Snub

Choose an option: 1
Hint: 35c15b545bbeb502670fb57a13131132a62e14e35ffad4c481543db782f00591ee7a89a7063daad18870a012583c2f226c3d6427932f01759e079f63481e4abf

1. Get hint
2. Snub

Choose an option: 2
Exiting...
```

## Analysis

Get hint refers to the "state" in the BlumBlumSnub class. Each time get hint is called the state is squared modulus n.

Recovering the original random state is essential to finding the flag as we only have the value of the flag xored with the second state.

Let's visualise what the server does to the state since randomly generating and make a link between that and the hints we have:

```
state1 = Random state generated
state2 = blum_blum_shub.next() called in get_flag(), used as the encryption key in the xor
state3 = blum_blum_shub.next() called in for loop (i = 0)
state4 = blum_blum_shub.next() called in for loop (i = 1)
state5 = blum_blum_shub.next() called in for loop (i = 2)
state6 = get_hint() called if user inputs 1
...

each state that isnt state1 is equal to the previous state squared mod n.
```

One way to go back to state2 from state6 is by finding the square root mod n 4 times. But that is impossible since state6 is not given to us mod n. get_hint() chooses between returning state6 mod p or mod q, which are significantly smaller than n.

## Solution

In order to go back to state2, we need a state whos value we have mod n. We can use the Chinese Remainder Theorem to do so:

```
Example:

state6 -> state7 (mod q)
We do not know this for a fact, but assume that state7 was given mod q. It does not matter which factor is used as the modulus for state6.

state6 ^ 2 = state7
state6 ^ 2 mod p = state7 mod p

Now we have state7 mod q and state7 mod p. Chinese remainder theorem can find the value of state7 mod p*q or state7 mod n
```

### BlumBlumSnub.py

```py
p = getPrime(512)
q = p + 1
while not isPrime(q):
    q += 1
```

Finding p and q is easy since the server generates them to be super close numbers and they can be found with n alone using Fermat's factorization theorem:

```py

from sympy import factorint

n = 52004979879787872904572830981193648623735649824909880379954617345102421835108325670268618239977932041523265473373333191743304900780154863819258072421637308289293327206386301324203822902642469116895460154056270469303515396889079704619978145241651376091666171601904244784368845645846480534814716708180605790013
print(factorint(n)) # factorint supports Fermat's theorem

```

Now to find out whether state8 is given mod p or mod q:
```py
p = 7211447835198412700542918326570472574272752200259726587383273063377874640396499754932730539637947032410568842705491180172832757909954653511151966727281117
q = 7211447835198412700542918326570472574272752200259726587383273063377874640396499754932730539637947032410568842705491180172832757909954653511151966727281889

#output from gethint()
state = [0x7567ad08ccd803cae284fd6f25a1052e9434fb99f540b85d484b1fbda40d450af34b1b25cdc3e4e38de03d62a51663ec96a12fe8f5a896a97b1510625f2879ed, 0x24039c326e63f9080e788bffa1c802623e739e3450cc1a1f72389ffd26a0086851fde2c9c345545fe687658dbca78ff6bda371b8b4ebe6585e39aa69a48365f1, 0x4900fd820808932971d176c87ec33b31284a05794ea4939f3c8a9d6b8d8a1bd5a9497abd184875872fe3dbc141285574203d872b0f97032da2806700c5de176d, 0x8038c7cb2a8c1e3110607014c42a6e3ece7e162f7e635a5380413fb69aaa2839236615b55310d1c91feef1eec020f5729d862694d496bbb105c9744f228825, 0x35c15b545bbeb502670fb57a13131132a62e14e35ffad4c481543db782f00591ee7a89a7063daad18870a012583c2f226c3d6427932f01759e079f63481e4abf]


print(pow(state[0], 4, p) == state[2]) # (state[0] ^ 2) = state[1] -> state[1] ^ 2 mod p == state[2], printed False
print(pow(state[0], 4, q) == state[2]) # (state[0] ^ 2) = state[1] -> state[1] ^ 2 mod q == state[2], printed True -> state8 is given as mod q

# this test printed two falses when testing state7, so state8 has been used instead.

```

State[2] is given modulus q. Now to use it and state[2] mod p to generate state[2] mod n

```py
state8_mod_p = pow(state[1], 2, p)
state8_mod_q = state[2]

from sympy.ntheory.modular import crt

state8_mod_n, n = crt([p, q], [state8_mod_p, state8_mod_q])
```

Now that we finally have state8 mod n, we need to go back to state2

```
state1
state2 (used as the encryption key)
state3
state4
state5
state6
state7
state8

state(i + 1) = state(i)^2 mod n
```

```py
from sympy.ntheory import sqrt_mod

possible_sqroots = [state8_mod_n] # put it into a list

for i in range(6): # iterate from state8 -> state2
    possible_sqroots2 = []

    for state in possible_sqroots:
        x = sqrt_mod(state, n, all_roots=True) # returns a list of possible square roots
        possible_sqroots2 += x

    possible_sqroots = possible_sqroots2 # continue the loop
```

Given a list of all possible keys, we can simply try to decrypt with each one and find which plaintext contains the string "CTF".

### solve.py
```py
from sympy import factorint

n = 52004979879787872904572830981193648623735649824909880379954617345102421835108325670268618239977932041523265473373333191743304900780154863819258072421637308289293327206386301324203822902642469116895460154056270469303515396889079704619978145241651376091666171601904244784368845645846480534814716708180605790013
#print(factorint(n))


p = 7211447835198412700542918326570472574272752200259726587383273063377874640396499754932730539637947032410568842705491180172832757909954653511151966727281117
q = 7211447835198412700542918326570472574272752200259726587383273063377874640396499754932730539637947032410568842705491180172832757909954653511151966727281889


#output from gethint()
state = [0x7567ad08ccd803cae284fd6f25a1052e9434fb99f540b85d484b1fbda40d450af34b1b25cdc3e4e38de03d62a51663ec96a12fe8f5a896a97b1510625f2879ed, 0x24039c326e63f9080e788bffa1c802623e739e3450cc1a1f72389ffd26a0086851fde2c9c345545fe687658dbca78ff6bda371b8b4ebe6585e39aa69a48365f1, 0x4900fd820808932971d176c87ec33b31284a05794ea4939f3c8a9d6b8d8a1bd5a9497abd184875872fe3dbc141285574203d872b0f97032da2806700c5de176d, 0x8038c7cb2a8c1e3110607014c42a6e3ece7e162f7e635a5380413fb69aaa2839236615b55310d1c91feef1eec020f5729d862694d496bbb105c9744f228825, 0x35c15b545bbeb502670fb57a13131132a62e14e35ffad4c481543db782f00591ee7a89a7063daad18870a012583c2f226c3d6427932f01759e079f63481e4abf]


#print(pow(state[0], 4, p) == state[2]) # (state[0] ^ 2) = state[1] -> state[1] ^ 2 mod p == state[2], printed False
#print(pow(state[0], 4, q) == state[2]) # (state[0] ^ 2) = state[1] -> state[1] ^ 2 mod q == state[2], printed True -> state8 is given as mod q

state8_mod_p = pow(state[1], 2, p)
state8_mod_q = state[2]


from sympy.ntheory.modular import crt

state8_mod_n, n = crt([p, q], [state8_mod_p, state8_mod_q])


from sympy.ntheory import sqrt_mod

possible_sqroots = [state8_mod_n] # put it into a list

for i in range(6): # iterate from state8 -> state2
    possible_sqroots2 = []

    for state in possible_sqroots:
        x = sqrt_mod(state, n, all_roots=True) # returns a list of possible square roots
        possible_sqroots2 += x

    possible_sqroots = possible_sqroots2 # continue the loop


from pwn import *
from Crypto.Util.number import long_to_bytes

ct = bytes.fromhex('4f2b8d495ccecdd4f60f2cd9a573030a0d7c086df12766fff9ae2d1e7d1ce39198c634029a2979fe086851709b86dab00bd6be')

# one of the values in possible_sqroots is the encryption key
for possible_key in possible_sqroots:
    possible_flag = xor(ct, long_to_bytes(possible_key)[:len(ct)])# line taken from BlumBlumSnub.py
    if b'CTF' in possible_flag:
        print(possible_flag)
```

### Flag
```
METACTF{l0mb4rd_4nd_ham0or_h4t3_d3adlines_muyp6e8s}
```
