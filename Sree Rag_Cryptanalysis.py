from collections import Counter

def bsort(pairs):
    n = len(pairs)
    for i in range(n):
        for j in range(0, n - i - 1):
            if pairs[j][1] < pairs[j + 1][1]:
                pairs[j], pairs[j + 1] = pairs[j + 1], pairs[j]
    return pairs

def C_letter_count():
    cipher_input = input("Input the cipher text: ")
    n = cipher_input.upper()
    lc = {}
    t = len(n)

    for letter in n:
        if letter.isalpha():
            lc[letter] = lc.get(letter, 0) + 1

    letter_list = list(lc.items())
    slc = bsort(letter_list)

    for letter, count in slc:
        freq = count / t
        print(f"{letter}: Count = {count}, Frequency = {freq:.2f}")
    
    top_3_cipher = [pair[0] for pair in slc[:3]]
    top_3_plain = ['E', 'T', 'A']

    shifts = []
    for cipher_letter, plain_letter in zip(top_3_cipher, top_3_plain):
        shift = (ord(cipher_letter) - ord(plain_letter)) % 26
        shifts.append(shift)

    shift_counts = Counter(shifts)
    mshift, freq = shift_counts.most_common(1)[0]

    dtext = caesar_cipher(cipher_input, mshift, mode='decrypt')
    print("\nDecrypted Text:")
    print(dtext)

    return dict(slc)
