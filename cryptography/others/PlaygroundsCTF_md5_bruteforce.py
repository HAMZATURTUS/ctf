'''
CHALLENGE SOURCE:
'''

import secrets, random, hashlib
print("".join([ hashlib.md5(str((x << 7 ) ^ secrets.random_secret_number).encode()).hexdigest() for x in secrets.flag ]))
#99f2e803248f5923faccd5b74eeac9fdd1fe9485be324217b5d180d04dfcb87f2df9c7c23d39de0710ec45bb2348a2870f0e3fa24833955ae7be0fc6ff2540f89cca8d684240e24dd459f2d439fae30c45fa9beaa3d9ea2ad7a09cd68b6a33aeabe24565b93dbc1d1dda3429adcc926c0c2ecd5cb4ba7dae4f84402c5ebe87f566a18289224fcaca68694426ede468a05638b0be1bce3838bca75e14cfe0818ffcc4103fcaf40d4720096ea4ed0fa2a7b241600bbbbc8cfbba760be3f23083bcd8c3fc67def99b7b61593abe7920f3c0790303191a1deaa93200d05f786405ee4315fce0913a690ba14db3bd46a1c89ab241600bbbbc8cfbba760be3f23083bc45fa9beaa3d9ea2ad7a09cd68b6a33ae4dd3479a7d8a13e22518a22202f4da7b4f2663dcc42d6c7746733d2c9bcb669db6ac971e55bee482346a196c2a82365ad21f9fc127b9849fddfaf59354916108d8c3fc67def99b7b61593abe7920f3c051b2395680b833ec1f7b1a44a0bafe05348bd749ca9ee5f03b04b8a2f0befc79fcc4103fcaf40d4720096ea4ed0fa2a7d21f9fc127b9849fddfaf5935491610814a2750f09d061e1744e376eeaae46088bdb666d756911879b3f77e93d945da30f0e3fa24833955ae7be0fc6ff2540f8d21f9fc127b9849fddfaf59354916108b4a2d301ddc8a3e8c500551900bdffd44dd3479a7d8a13e22518a22202f4da7b638c5071774c3ddd8b600c3fe1b137890f0e3fa24833955ae7be0fc6ff2540f831bbeb867c695411485ebf8a2f748b6b

'''
important : 
format flag : PlayGroundsCTF{}
'''


'''


to decrypt the cipher, we need to understand what the encryption file does

for each character, the file will:
1. left shift the ASCII value by 7 bits
2. XOR the value by a secret random number (SRN)
3. convert the new number into a string and encode it to bytes
4. convert the bytes value into md5 hash format



so to decrypt we have to work with each character separately, we can start by splitting the ciphertext into blocks of 32: each block representing a character in the flag

to find the secret random number, we have to start with the first character, which we already know will be a 'P'. we follow the steps shown above except for step 2, which we will have to brute force.

the code left shifts the ASCII value of 'P' by 7 bits. now we have to try to XOR 'P' with every number between 1 and K and whichever value gives us the cipher after following steps 3 and 4, will be the secret number.

I chose K to be 50000 because the ASCII of 'P' is 13 bits and I figured that the secret number's value would not be far off as the final XOR will have to be a similar value to P so I chose a value that was 16 bits long.

'''
compare = "99f2e803248f5923faccd5b74eeac9fd"

data = ord('P')


print(data << 7)
data <<= 7

for srn in range(1, 50000):
    n = data ^ srn
    n = str(n).encode()
    n = hashlib.md5(n).hexdigest()
    if n == compare:
        print(srn)
        print(n)
        break

'''

now that we have the secret number, we can brute force the remaining characters by trying every possible character from chr(1) to chr(256) and concluding that a character is part of the flag if the hash that i got by trying its value matched the hash of the cipher text.


'''



c = "99f2e803248f5923faccd5b74eeac9fdd1fe9485be324217b5d180d04dfcb87f2df9c7c23d39de0710ec45bb2348a2870f0e3fa24833955ae7be0fc6ff2540f89cca8d684240e24dd459f2d439fae30c45fa9beaa3d9ea2ad7a09cd68b6a33aeabe24565b93dbc1d1dda3429adcc926c0c2ecd5cb4ba7dae4f84402c5ebe87f566a18289224fcaca68694426ede468a05638b0be1bce3838bca75e14cfe0818ffcc4103fcaf40d4720096ea4ed0fa2a7b241600bbbbc8cfbba760be3f23083bcd8c3fc67def99b7b61593abe7920f3c0790303191a1deaa93200d05f786405ee4315fce0913a690ba14db3bd46a1c89ab241600bbbbc8cfbba760be3f23083bc45fa9beaa3d9ea2ad7a09cd68b6a33ae4dd3479a7d8a13e22518a22202f4da7b4f2663dcc42d6c7746733d2c9bcb669db6ac971e55bee482346a196c2a82365ad21f9fc127b9849fddfaf59354916108d8c3fc67def99b7b61593abe7920f3c051b2395680b833ec1f7b1a44a0bafe05348bd749ca9ee5f03b04b8a2f0befc79fcc4103fcaf40d4720096ea4ed0fa2a7d21f9fc127b9849fddfaf5935491610814a2750f09d061e1744e376eeaae46088bdb666d756911879b3f77e93d945da30f0e3fa24833955ae7be0fc6ff2540f8d21f9fc127b9849fddfaf59354916108b4a2d301ddc8a3e8c500551900bdffd44dd3479a7d8a13e22518a22202f4da7b638c5071774c3ddd8b600c3fe1b137890f0e3fa24833955ae7be0fc6ff2540f831bbeb867c695411485ebf8a2f748b6b"

c_list = [c[i:i+32] for i in range(0, len(c), 32)]

srn = 32768

f = ""
i = 0
for compare in c_list:
    for x in range(1, 256):
        n = x << 7
        n ^= srn
        n = hashlib.md5(str(n).encode()).hexdigest()
        if(n == compare):
            i += 1
            f += chr(x)
            break

print(f)

