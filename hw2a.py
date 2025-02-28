from bitarray import bitarray
from Crypto.Cipher import DES
from bitarray import bitarray
from bitarray.util import ba2int, int2ba

PC_1 = [
    57, 49, 41, 33, 25, 17, 9, 
    1, 58, 50, 42, 34, 26, 18, 10, 
    2, 59, 51, 43, 35, 27, 19, 11, 
    3, 60, 52, 44, 36, 28, 20, 12, 
    4, 61, 53, 45, 37, 29, 21, 13, 
    5, 62, 54, 46, 38, 30, 22, 14, 
    6, 63, 55, 47, 39, 31, 23, 15, 
    7, 56, 48, 40, 32, 24, 16, 8
]

PC_2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 
    15, 6, 21, 10, 23, 19, 12, 4, 
    26, 8, 16, 7, 27, 20, 13, 2, 
    41, 52, 31, 37, 47, 55, 30, 40, 
    51, 45, 33, 48, 44, 49, 39, 56, 
    34, 53, 46, 42, 50, 36, 29, 32
]

shift_schedule = [1, 1, 2, 2, 2, 2, 1, 2, 2, 2, 2, 1, 2, 2, 2, 1]

def left_shift(key, shifts):
    return key[shifts:] + key[:shifts]

# S-boxes
S_boxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 16, 5, 3, 10, 9, 0, 6, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 15, 14, 12, 9, 7, 11, 4, 5, 3, 2, 6, 0]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 15, 11, 12, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 10, 14, 5, 1, 7, 11, 12, 2],
        [1, 10, 13, 15, 7, 11, 4, 9, 8, 12, 14, 3, 5, 0, 6, 2]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 15, 4],
        [13, 8, 7, 15, 11, 1, 10, 14, 9, 3, 4, 12, 5, 0, 6, 2],
        [1, 15, 13, 8, 10, 3, 6, 7, 9, 4, 14, 12, 0, 5, 2, 11],
        [10, 3, 14, 12, 4, 15, 7, 9, 11, 2, 8, 5, 6, 13, 1, 0]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 10, 15, 9, 3, 5, 0, 6, 8],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 14, 12, 0, 3, 5, 6],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 9, 10, 4, 5, 3, 0]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 7, 3, 10, 4, 1, 13, 11, 6, 0],
        [4, 3, 2, 12, 5, 15, 11, 10, 14, 1, 7, 9, 8, 13, 0, 6]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 12, 15, 5, 2, 8, 6],
        [1, 15, 13, 8, 10, 3, 11, 5, 9, 12, 7, 4, 2, 14, 0, 6],
        [8, 6, 2, 7, 5, 10, 14, 12, 3, 15, 0, 9, 13, 1, 4, 11]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 4, 6, 7, 9, 11, 2, 5, 14, 0, 12, 3],
        [8, 6, 15, 3, 11, 14, 5, 2, 9, 0, 13, 7, 4, 12, 10, 1],
        [7, 1, 9, 0, 5, 3, 12, 2, 15, 10, 14, 13, 11, 6, 8, 4]
    ]
]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

def apply_permutation(bits, permutation_table):
    return bitarray([bits[i-1] for i in permutation_table])

def feistel_function(right, round_key):
    expanded = apply_permutation(right, E) 
    
    xored = expanded ^ round_key
    
    s_box_output = bitarray()
    for i in range(0, len(xored), 6):
        chunk = xored[i:i+6] 
        row = int(chunk[0:1].to01(), 2)  
        col = int(chunk[1:5].to01(), 2)  
        s_box_value = S_boxes[i//6][row][col]  
        s_box_output.extend(format(s_box_value, '04b'))  
    
    P_output = apply_permutation(s_box_output, P) 
    return P_output  


IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 
    60, 52, 44, 36, 28, 20, 12, 4, 
    62, 54, 46, 38, 30, 22, 14, 6, 
    64, 56, 48, 40, 32, 24, 16, 8, 
    57, 49, 41, 33, 25, 17, 9, 1, 
    59, 51, 43, 35, 27, 19, 11, 3, 
    61, 53, 45, 37, 29, 21, 13, 5, 
    63, 55, 47, 39, 31, 23, 15, 7
]

IP_1 = [
    40, 8, 48, 16, 56, 24, 64, 32, 
    39, 7, 47, 15, 55, 23, 62, 31, 
    38, 6, 46, 14, 54, 22, 61, 30, 
    37, 5, 45, 13, 53, 21, 60, 29, 
    36, 4, 44, 12, 52, 20, 59, 28, 
    35, 3, 43, 11, 51, 19, 58, 27, 
    34, 2, 42, 10, 50, 18, 57, 26, 
    33, 1, 41, 9, 49, 17, 56, 24
]

def binary_string_to_bitarray(binary_str):
    """ Convert a binary string (e.g., '1100101...') to a bitarray object. """
    return bitarray(binary_str)


def pad_key(key):
    return key.ljust(8, b'\0')[:8]

def string_to_bitarray(s):
    return bitarray(format(int.from_bytes(s.encode(), 'big'), '064b'))

def bitarray_to_string(b):
    return int.to_bytes(int(b.to01(), 2), len(b) // 8, 'big').decode(errors='ignore')

def generate_round_keys(key):
    key_bytes = bitarray(format(int.from_bytes(key.encode(), 'big'), '064b'))
    key = apply_permutation(key_bytes, PC_1)  
    
    C, D = key[:28], key[28:] 
    round_keys = []
    
    for i in range(16):
        C = left_shift(C, shift_schedule[i])
        D = left_shift(D, shift_schedule[i])
        round_key = apply_permutation(C + D, PC_2)  
        round_keys.append(round_key)
        print("round key: "+ str(i)+ ":"+ str(round_key))
    
    return round_keys[::-1]

def des_decrypt(ciphertext, key):
    round_keys = generate_round_keys(key)
    
    ciphertext = bitarray(ciphertext)  
    
    ciphertext = apply_permutation(ciphertext, IP)
    
    left, right = ciphertext[:32], ciphertext[32:]
    
    for round_num in range(15, -1, -1):  
        round_key = round_keys[round_num]
        
        f_output = feistel_function(right, round_key)
    
        new_left = right ^ f_output 
        right = left
        left = new_left
        
        print(f"Round {round_num}: Left: {left.to01()}, Right: {right.to01()}")
    
    final_result = left + right
    final_result = apply_permutation(final_result, IP_1)
    
    return final_result.to01()

def decrypt_DES_package(ciphertext, key):
    key_bytes = pad_key(key.tobytes())
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext.tobytes())
    decrypted_bits = bitarray()
    decrypted_bits.frombytes(decrypted)
    return decrypted_bits

ciphertextpackage = bitarray('1100101011101101101000100110010101011111101101110011100001110011')
keypackage = bitarray('0100110001001111010101100100010101000011010100110100111001000100')
ciphertext = "1100101011101101101000100110010101011111101101110011100001110011"
key = "0100110001001111010101100100010101000011010100110100111001000100"
decrypted_text = des_decrypt(ciphertext, key)
#print("Decrypted Text: ", decrypted_text)
decrypted_bits_package = decrypt_DES_package(ciphertextpackage, keypackage)
plaintext = bitarray_to_string(decrypted_bits_package)
print("Plaintext (Binary):", decrypted_bits_package.to01())
print("Plaintext (String):", plaintext)