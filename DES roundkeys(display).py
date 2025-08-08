PC_1 = [
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
]

PC_2 = [
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2,
          1, 2, 2, 2, 2, 2, 2, 1]

def str_to_bit_array(text):
    array = []
    for char in text:
        binval = bin(ord(char))[2:].rjust(8, '0')
        array.extend(int(x) for x in binval)
    return array

def permute(block, table):
    return [block[x-1] for x in table]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_round_keys(key_str):
    key = str_to_bit_array(key_str)
    key = permute(key, PC_1)
    left = key[:28]
    right = key[28:]
    round_keys = []

    for i in range(16):
        left = left_shift(left, SHIFTS[i])
        right = left_shift(right, SHIFTS[i])
        combined = left + right
        round_key = permute(combined, PC_2)
        round_keys.append(round_key)

    return round_keys

def bits_to_hex(bits):
    hex_str = ''
    for i in range(0, len(bits), 4):
        nibble = bits[i:i+4]
        value = int(''.join(str(b) for b in nibble), 2)
        hex_str += f'{value:x}'
    return hex_str.upper()

def print_round_keys(round_keys):
    for i, key in enumerate(round_keys, 1):
        print(f"Round {i} Key: {bits_to_hex(key)}")

def main():
    key = input("Enter 8-character (64-bit) DES key: ")
    if len(key) != 8:
        print("Key must be exactly 8 characters (64 bits).")
        return

    round_keys = generate_round_keys(key)
    print_round_keys(round_keys)

if __name__ == "__main__":
    main()
