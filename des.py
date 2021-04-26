from essentials import *

# converts to binary string
tobin = lambda x: [format(ord(i), '08b') for i in x]


# rotates left and right half of key
def left_rotate(key, round_num):
    if round_num == 1:
        key = list(key[PC_1[i] - 1] for i in range(56))                 # initial permutation of key
    key_l = key[:28]
    key_r = key[28:]
    key_l = key_l[SHIFT[round_num - 1]:] + key[:SHIFT[round_num - 1]]   # left rotate according to round shift bits
    key_r = key_r[SHIFT[round_num - 1]:] + key[:SHIFT[round_num - 1]]
    key = key_l + key_r
    return key


# key schedule for different rounds of encryption
def key_schedule(key, round_num):
    left_rotate(key, round_num)
    return list(key[PC_2[i] - 1] for i in range(48))  # substitutes after rotating key


# the f function
def f_func(ro, key):
    ro = list(ro[E[i] - 1] for i in range(48))                              # expansion of text from 32 to 48 bits
    ro = list(str(int(ro[i]) ^ int(key[i])) for i in range(len(ro)))        # xor with 48 bit key
    List = list(ro[6 * i:6 + 6 * i] for i in range(8))                      # 8 equal parts for 8 s boxes
    new_list = []
    for i in range(8):
        x = ''.join(List[i][1:5])
        y = ''.join(List[i][0] + List[i][5])
        new_list.append(S_BOX[i][int(y, 2)][int(x, 2)])                     # s box substitution
    new_list = list(''.join(format(ord(chr(i)), '04b') for i in new_list))  # 48 bits to 32 bits
    return list(new_list[P[i] - 1] for i in range(32))                      # returns the list which is used to xor text


# encryption round
def round_encryption(List, key, round_num):
    key = key_schedule(key, round_num)
    if round_num == 1:
        List = list(List[IP[i] - 1] for i in range(64))                 # initial permutation of text
    lo = List[:32]
    ro = List[32:]
    key = f_func(ro, key)
    r1 = list(str(int(lo[i]) ^ int(key[i])) for i in range(len(lo)))    # xor with output of f function
    if round_num == 16:
        b = r1 + ro
        a = list(b[IP_1[i]-1] for i in range(len(b)))                   # final permutation
        return a
    return ro + r1


# the encryption process
def process(message, key):
    msg = tobin(message)
    chipher_text = list(''.join(msg))
    key = list(''.join(i for i in tobin(key)))
    for i in range(16):
        chipher_text = round_encryption(chipher_text, key, i+1)
    chipher_text = ''.join(chipher_text)
    chipher_text = list(chipher_text[8 * i:8 + 8 * i] for i in range(8))
    chipher = ''
    for i in chipher_text:
        chipher += chr(int(i, 2))
    return chipher


def main(message, key, option='e'):
    add = ['a', 'b', 'c', 'd', 'e']
    if len(message) % 8 != 0:
        message = message + '{' + ''.join(add[i] for i in range(8 - len(message) % 8 - 1))
    message = [message[i:i+8] for i in range(0, len(message), 8)]
    a = ''
    for message in message:
        a = a + ''.join(process(message, key))
    if option == 'd':
        a = a.split('{')[0]
    return a


# make sure you don't use '{' in between it will split there and will show you first string of that list
# default option is e(encryption) put d for decryption as shown
if __name__ == '__main__':
    message = 'i like coding but i suck at it'
    cipher = main(message, '@*nFH!lo')
    print(cipher)
    message = cipher
    a = main(message, '@*nFH!lo', 'd')
    print(a)
