# MetaCTF - BlumBlumSnub
### Author: Saleh Elnaji

Category: Cryptography

Difficulty: Medium

## Source:
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

## Analysis:

Get hint refers to the "state" in the BlumBlumSnub class. Each time get hint is called the state is squared modulus n.

Recovering the original random state is essential to finding the flag as we have the value of the flag xored with the state.

Let's visualise what the server does to the state since randomly generating and make a link between that and the hints we have:

```
state1 = Random state generated
state2 = blum_blum_shub.next() called in get_flag(), used as the encryption key in the xor
state3 = blum_blum_shub.next() called in for loop (i = 0)
state4 = blum_blum_shub.next() called in for loop (i = 1)
state5 = blum_blum_shub.next() called in for loop (i = 2)
state6 = get_hint() called if user inputs 1

each state that isnt state1 is equal to the previous state squared mod n.
```


One way to go back to state2 from state6 is by finding the square root mod n 4 times. But that is impossible since state6 is not given to us mod n. get_hint() chooses between returning state6 mod p or mod q, which are significantly smaller than n.

In order to go back to state2, we need a state whos value we have mod n. We can use the Chinese Remainder Theorem to do so:

```
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

n = 60761075864951778151843175586891297199106292331778578013793830262848283588702813151713942487284865190370283582771344734150007458900396815633421697214921142554682849558212946889044091844348762923703298098818126598992986952727995034644855451141126964674177555221511389616511433062976086877728614231987782747763
print(factorint(n)) # factorint supports Fermat's theorem

```

