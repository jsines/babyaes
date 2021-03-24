import random

# 16 bit inputs, 16 bit output
def bAES_Encrypt(ptext, key):
    def A(x, key):
        return x ^ key
    def NS(x):
        x0 = (x&0b1111000000000000) >> 12 
        x1 = (x&0b111100000000) >> 8
        x2 = (x&0b11110000) >> 4
        x3 = (x&0b1111)
        s0 = bAES_SBox(x0) << 12
        s1 = bAES_SBox(x1) << 8
        s2 = bAES_SBox(x2) << 4
        s3 = bAES_SBox(x3)
        return s0 | s1 | s2 | s3
    def SR(x): # swap second and fourth nibs
        x0 = x&0b1111000000000000 
        x1 = (x&0b111100000000) >> 8
        x2 = x&0b11110000
        x3 = (x&0b1111) << 8
        return x0 | x3 | x2 | x1 #note, order here doesnt matter, bits are padded. presented this way only for clarity
    def MC(x):
        byte1 = (x&0b1111111100000000) >> 8 
        byte2 = x&0b11111111
        return (MCByte(byte1) << 8) | MCByte(byte2)
    def MCByte(byte): # saw the cleaner implementation with xoring bits but I wanted to do the math the hard way for more fun
        startingCoef = (byte&0b11110000) >> 4
        startingConst = byte&0b00001111
        endingCoef = ffAdd(startingCoef, ffMultiply(startingConst, 0b0100, 0b10011))
        endingConst = ffAdd(startingConst, ffMultiply(startingCoef, 0b0100, 0b10011))
        return (endingCoef << 4) | endingConst
    keySchedule = bAES_keySchedule(key)
    k=[0,0,0]
    k[0] = keySchedule >> 32
    k[1] = (keySchedule >> 16)&0b1111111111111111
    k[2] = keySchedule&0b1111111111111111
    ctext = A(ptext, k[0])
    for i in range(1,3):
        ctext = NS(ctext)
        ctext = SR(ctext)
        if(i!=2): 
            ctext = MC(ctext)
        ctext = A(ctext, k[i])
    return ctext

# same as above, BUT ONE ROUND. Literally copy and pasted so please excuse the code repitition.
def bbAES_Encrypt(ptext, key):
    def A(x, key):
        return x ^ key
    def NS(x):
        x0 = (x&0b1111000000000000) >> 12 
        x1 = (x&0b111100000000) >> 8
        x2 = (x&0b11110000) >> 4
        x3 = (x&0b1111)
        s0 = bAES_SBox(x0) << 12
        s1 = bAES_SBox(x1) << 8
        s2 = bAES_SBox(x2) << 4
        s3 = bAES_SBox(x3)
        return s0 | s1 | s2 | s3
    def SR(x): # swap second and fourth nibs
        x0 = x&0b1111000000000000 
        x1 = (x&0b111100000000) >> 8
        x2 = x&0b11110000
        x3 = (x&0b1111) << 8
        return x0 | x3 | x2 | x1 #note, order here doesnt matter, bits are padded. presented this way only for clarity
    def MC(x):
        byte1 = (x&0b1111111100000000) >> 8 
        byte2 = x&0b11111111
        return (MCByte(byte1) << 8) | MCByte(byte2)
    def MCByte(byte): # saw the cleaner implementation with xoring bits but I wanted to do the math the hard way for more fun
        startingCoef = (byte&0b11110000) >> 4
        startingConst = byte&0b00001111
        endingCoef = ffAdd(startingCoef, ffMultiply(startingConst, 0b0100, 0b10011))
        endingConst = ffAdd(startingConst, ffMultiply(startingCoef, 0b0100, 0b10011))
        return (endingCoef << 4) | endingConst
    keySchedule = bAES_keySchedule(key)
    k=[0,0]
    k[0] = keySchedule >> 32
    k[1] = (keySchedule >> 16)&0b1111111111111111
    ctext = A(ptext, k[0])
    ctext = NS(ctext)
    ctext = SR(ctext)
    ctext = MC(ctext)
    ctext = A(ctext, k[1])
    return ctext

def bAES_Decrypt(ctext, key):
    def A(x, key): # serves as its own inverse
        return x ^ key
    def NSInverse(x): 
        x0 = (x&0b1111000000000000) >> 12 
        x1 = (x&0b111100000000) >> 8
        x2 = (x&0b11110000) >> 4
        x3 = (x&0b1111)
        s0 = bAES_SBox_Inv(x0) << 12
        s1 = bAES_SBox_Inv(x1) << 8
        s2 = bAES_SBox_Inv(x2) << 4
        s3 = bAES_SBox_Inv(x3)
        return s0 | s1 | s2 | s3
    def SR(x): # serves as its own inverse
        x0 = x&0b1111000000000000 
        x1 = (x&0b111100000000) >> 8
        x2 = x&0b11110000
        x3 = (x&0b1111) << 8
        return x0 | x3 | x2 | x1 #note, order here doesnt matter, bits are padded. presented this way only for clarity
    def MCInverse(x):
        byte1 = (x&0b1111111100000000) >> 8 
        byte2 = x&0b11111111
        return (MCByteInverse(byte1) << 8) | MCByteInverse(byte2)
    def MCByteInverse(byte):
        startingCoef = (byte&0b11110000) >> 4
        startingConst = byte&0b00001111
        endingCoef = ffAdd(ffMultiply(startingCoef, 0b1001, 0b10011), ffMultiply(startingConst, 0b0010, 0b10011))
        endingConst = ffAdd(ffMultiply(startingConst, 0b1001, 0b10011), ffMultiply(startingCoef, 0b0010, 0b10011))
        return (endingCoef << 4) | endingConst
    keySchedule = bAES_keySchedule(key)
    k=[0,0,0]
    k[0] = keySchedule >> 32
    k[1] = (keySchedule >> 16)&0b1111111111111111
    k[2] = keySchedule&0b1111111111111111
    ptext = A(ctext, k[2])
    for i in range(1,3):
        if(i!=1): 
            ptext = MCInverse(ptext)
        ptext = SR(ptext)
        ptext = NSInverse(ptext)
        ptext = A(ptext, k[2-i])
    return ptext

# 4 bit input 4 bit output
def bAES_SBox(bits):
    a = 0b1101
    b = 0b1001
    if(bits == 0b0000):
        return b
    else:
        return ffAdd(b, ffMultiply(a, ffInverse(bits, 0b10011), 0b10001))

def bAES_SBox_Inv(bits):
    if(bits == 0b1001): return 0b0000
    return ffInverse(ffAdd(ffMultiply(bits, 0b0111, 0b10001), ffMultiply(0b0111, 0b1001, 0b10001)), 0b10011)

# 16 bit input 48 bit output
def bAES_keySchedule(key): 
    def RC(i):
        x = 0b0100
        while(i > 0):
            x = ffMultiply(x, 0b0010, 0b10011)
            i = i-1
        return x
    def RCON(i):
        return RC(i) << 4
    def RotNyb(bits):
        a = (bits&0b11110000) >> 4
        b = (bits&0b00001111) << 4
        return a | b
    def SubNyb(bits):
        a = (bits&0b11110000) >> 4
        b = (bits&0b00001111)
        sa = bAES_SBox(a) << 4
        sb = bAES_SBox(b)
        return sa | sb
    w=[0,0,0,0,0,0]
    w[0] = key&0b1111111100000000 >> 8
    w[1] = key&0b0000000011111111
    for i in range(2, 6):
        if(i%2==0):
            w[i]=w[i-2] ^ RCON(i//2) ^ SubNyb(RotNyb(w[i-1]))
        else:
            w[i]=w[i-2] ^ w[i-1]
    k=[0,0,0]
    for i in range(3):
        k[i] = ((w[2 * i] << 8) | w[(2 * i) + 1]) << (16 * (2-i)) # assembling subkeys
    return k[0] | k[1] | k[2]

def ffAdd(x, y):
    return x ^ y

def ffMultiply(x, y, mod):
    result = 0
    # for loop basically cross multiplies in binary, but with no carries
    for i in range(4):
        if y&(1<<i) != 0:
            result = result ^ (x<<i)
    # mod y^4 + 1 => y^4 = 1
    # mod y^4 + y + 1 => y^4 = y + 1
    mod = mod&15 # last 4 bits
    for i in range(4, 7):
        if result&(1<<i) != 0:
            result = result ^ (mod<<(i-4))
    result = result&15
    return result

# Extremely hacky but extremely easy to write :)
def ffInverse(x, mod):
    for i in range(16):
        if(ffMultiply(x, i, mod) == 1):
            return i
    print("Could not find an inverse")
 
def generateSBoxArray():
    arr = [0 for _ in range(16)]
    for i in range(16):
        arr[i] = bAES_SBox(i)
    return arr

def high_bias(sbox):
    def hold(lhs, rhs, inp, out):
        l = bin(lhs & inp).count('1')
        r = bin(rhs & out).count('1')
        return l&1 == r&1
    m = max(sbox) + 1
    n = len(sbox)
    r = [[0 for _ in range(n)] for _ in range(m)]
    for lhs in range(n):
        for rhs in range(n):
            count = 0
            for inp in range(n):
                out = sbox[inp]
                if hold(lhs, rhs, inp, out):
                    count+=1
            r[lhs][rhs]=count-(n//2)
    return r

# uses ONE ROUND baby AES as in paper
def checkEQ(lhsp, lhsc, rhsk, tries):
    def ith_bit(bitstring, i):
        return (bitstring>>i)&1
    count=0
    key = random.randint(0, 66536)
    for _ in range(tries):
        ptext = random.randint(0, 66536)
        ctext = bbAES_Encrypt(ptext, key)
        lhs,rhs = 0,0
        for j in range(16):
            if(lhsp[j]==1):
                lhs=lhs^ith_bit(ptext, j)
            if(lhsc[j]==1):
                lhs=lhs^ith_bit(ctext, j)
            if(rhsk[j]==1):
                rhs=rhs^ith_bit(key, j)
        if lhs==rhs:
            count+=1
    return count / tries






def main():
    # a)
    # Checks every single message with every single key to make sure encryption mirrors decryption
    # WARNING: TAKES INSANELY LONG TO RUN (65536*65536 = about 10^9 possibilities)
    # if you choose to uncomment I recommend shortening the key/ptext range

    #for i in range(65536):
    #    for j in range(65536):
    #        if(i != bAES_Decrypt(bAES_Encrypt(i, j), j)):
    #            print("Broke for msg {} and key {}".format(bin(i), bin(j)))
    #    print("Finished msg {}".format(i))
    #print("fin")

    # b)
    # Generate biases of SBox, this code was taken directly from the slides but it works so why change it :)

    #for row in high_bias(generateSBoxArray()):
    #    for e in row:
    #        print('{:3} '.format(e), end='')
    #    print('')

    # c)
    # Checking equations from the paper page 10. Arrays are in reverse order ([p_15, p_14,...,p_0])
    # Each should return around 0.625 or 0.375.
    # For good measure the final equation is garbage and should return around 0.5
    #print(checkEQ([0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0], [0,0,1,0,1,0,0,0,0,0,1,0,1,0,0,0], [0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0], 100000))
    #print(checkEQ([0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,0], [0,0,1,0,1,0,0,0,0,0,1,0,1,0,0,0], [0,0,1,0,1,0,1,1,0,0,0,0,1,0,0,0], 100000))
    #print(checkEQ([0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,1], [0,0,1,0,1,0,0,0,0,0,1,0,1,0,0,0], [0,0,1,0,1,0,1,1,0,0,0,0,0,0,1,1], 100000))
    #print(checkEQ([1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0], [1,0,0,0,0,0,1,0,1,0,0,0,0,0,1,0], [0,0,0,0,0,0,1,0,1,0,0,0,0,0,0,0], 100000))
    #print(checkEQ([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1], 100000))
    

if __name__ == "__main__":
    main()

