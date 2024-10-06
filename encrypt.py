# encrypt.py

from pbox import PBox
from feistel import Feistel
from key_schedule import KeySchedule

class DESEncryptor:
    def __init__(self):
        self.feistel = Feistel()
        self.ip_pbox = PBox.des_initial_permutation()
        self.fp_pbox = PBox.des_final_permutation()

    def des_encrypt(self, plaintext, key):
        # Initial permutation
        permuted_plaintext = list(map(int, self.ip_pbox.permutate(plaintext)))
        
        # Split into left and right halves
        left, right = permuted_plaintext[:32], permuted_plaintext[32:]

        # Generate subkeys
        subkeys = KeySchedule.generate_subkeys(key)

        # Perform 16 rounds of Feistel
        for round_key in subkeys:
            new_right = [l ^ r for l, r in zip(left, self.feistel.feistel_round(right, round_key))]
            left = right
            right = new_right

        # Final permutation
        return list(map(int, self.fp_pbox.permutate(right + left)))

    def des_decrypt(self, ciphertext, key):
        # Initial permutation
        permuted_ciphertext = list(map(int, self.ip_pbox.permutate(ciphertext)))
        
        left, right = permuted_ciphertext[:32], permuted_ciphertext[32:]
        subkeys = KeySchedule.generate_subkeys(key)

        # Perform 16 rounds of Feistel (in reverse)
        for round_key in reversed(subkeys):
            new_right = [l ^ r for l, r in zip(left, self.feistel.feistel_round(right, round_key))]
            left = right
            right = new_right

        # Final permutation
        return list(map(int, self.fp_pbox.permutate(right + left)))
