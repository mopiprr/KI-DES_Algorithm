# encrypt.py

from pbox import PBox
from feistel import Feistel
from key_schedule import KeySchedule

class DESEncryptor:
    def __init__(self):
        self.feistel = Feistel()
        self.ip_pbox = PBox.des_initial_permutation()  # Initial permutation
        self.fp_pbox = PBox.des_final_permutation()    # Final permutation

    def des_encrypt(self, plaintext, key):
        # Step 1: Initial permutation
        permuted_plaintext = list(map(int, self.ip_pbox.permutate(plaintext)))
        
        # Step 2: Split into left and right halves
        left, right = permuted_plaintext[:32], permuted_plaintext[32:]

        # Step 3: Generate 16 subkeys
        subkeys = KeySchedule.generate_subkeys(key)

        # Step 4: Perform 16 rounds of Feistel using subkeys
        for round_key in subkeys:
            new_right = [l ^ r for l, r in zip(left, self.feistel.feistel_round(right, round_key))]
            left = right
            right = new_right

        # Step 5: Final permutation
        return list(map(int, self.fp_pbox.permutate(right + left)))

    def des_decrypt(self, ciphertext, key):
        # Step 1: Initial permutation
        permuted_ciphertext = list(map(int, self.ip_pbox.permutate(ciphertext)))
        
        # Step 2: Split into left and right halves
        left, right = permuted_ciphertext[:32], permuted_ciphertext[32:]

        # Step 3: Generate 16 subkeys
        subkeys = KeySchedule.generate_subkeys(key)

        # Step 4: Perform 16 rounds of Feistel using subkeys in reverse order
        for round_key in reversed(subkeys):
            new_right = [l ^ r for l, r in zip(left, self.feistel.feistel_round(right, round_key))]
            left = right
            right = new_right

        # Step 5: Final permutation
        return list(map(int, self.fp_pbox.permutate(right + left)))
