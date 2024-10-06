# key_schedule.py

from pbox import PBox

class KeySchedule:
    SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    @staticmethod
    def shift_left(block, num_shifts):
        return block[num_shifts:] + block[:num_shifts]

    @staticmethod
    def generate_subkeys(key_64bit):
        pc1 = PBox.des_key_initial_permutation()
        pc2 = PBox.des_shifted_key_permutation()

        # Apply PC-1 to reduce 64-bit key to 56-bit
        key_56bit = list(map(int, pc1.permutate(key_64bit)))
        
        # Split key into left and right halves (28 bits each)
        left, right = key_56bit[:28], key_56bit[28:]
        
        subkeys = []
        for shift in KeySchedule.SHIFT_SCHEDULE:
            # Shift left halves
            left = KeySchedule.shift_left(left, shift)
            right = KeySchedule.shift_left(right, shift)

            # Combine halves and apply PC-2
            combined = left + right
            subkey = list(map(int, pc2.permutate(combined)))
            subkeys.append(subkey)

        return subkeys
