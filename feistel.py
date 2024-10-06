# feistel.py

from pbox import PBox
from sbox import SBox
from key_schedule import KeySchedule

class Feistel:
    def __init__(self):
        self.expansion_pbox = PBox.des_single_round_expansion()
        self.p_permutation = PBox.des_single_round_final()
        self.sbox = SBox()

    def feistel_round(self, right_half, subkey):
        # Step 1: Expansion
        expanded_right = list(map(int, self.expansion_pbox.permutate(right_half)))

        # Step 2: XOR with subkey
        xor_result = [b1 ^ b2 for b1, b2 in zip(expanded_right, subkey)]

        # Step 3: S-Box substitution
        substituted = self.sbox.substitute(xor_result)

        # Step 4: P-Permutation
        return list(map(int, self.p_permutation.permutate(substituted)))
