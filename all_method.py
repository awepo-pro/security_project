import tkinter as tk
from tkinter import filedialog, messagebox
import time
import os

# ========================
#      DES Implementation
# ========================
class DES:
    def __init__(self, key):
        # Convert bytes to list of bits (e.g., b'abc' → [0,1,0,0,0,0,1,1,...])
        key_bits = []
        for byte in key:
            key_bits += [int(bit) for bit in format(byte, '08b')]
        
        self.key = self.permute(key_bits, self.PC1)  # Now correctly 56 bits
        self.subkeys = self.generate_subkeys()

    # Initial permutation table
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

    # Final permutation
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

    # Key permutation tables
    PC1 = [57, 49, 41, 33, 25, 17, 9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4]

    PC2 = [14, 17, 11, 24, 1, 5,
           3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8,
           16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32]

    # Expansion table
    E = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]

    # S-boxes
    S_BOX = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    # P permutation
    P = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]

    # Shift amounts for key schedule
    SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def permute(self, block, table):
        return [block[i-1] for i in table]

    def left_shift(self, key, n):
        return key[n:] + key[:n]

    def generate_subkeys(self):
        # Split key into left and right halves
        left = self.key[:28]
        right = self.key[28:]
        
        subkeys = []
        for shift in self.SHIFT:
            # Left shift both halves
            left = self.left_shift(left, shift)
            right = self.left_shift(right, shift)
            
            # Combine and permute to get subkey
            combined = left + right
            subkey = self.permute(combined, self.PC2)
            subkeys.append(subkey)
            
        return subkeys

    def feistel(self, block, subkey):
        # Expansion permutation
        expanded = self.permute(block, self.E)
        
        # XOR with subkey
        xored = [a ^ b for a, b in zip(expanded, subkey)]
        
        # S-box substitution
        s_out = []
        for i in range(8):
            chunk = xored[i*6:(i+1)*6]
            row = (chunk[0] << 1) + chunk[5]
            col = (chunk[1] << 3) + (chunk[2] << 2) + (chunk[3] << 1) + chunk[4]
            val = self.S_BOX[i][row][col]
            s_out += [int(b) for b in format(val, '04b')]
            
        # P permutation
        return self.permute(s_out, self.P)

    @staticmethod
    def bytes_to_bits(data):
        """Convert bytes to a list of bits (LSB first)"""
        bits = []
        for byte in data:
            bits += [ (byte >> i) & 1 for i in range(7, -1, -1) ]
        return bits

    @staticmethod
    def bits_to_bytes(bits):
        """Convert list of bits back to bytes"""
        if len(bits) % 8 != 0:
            bits += [0] * (8 - (len(bits) % 8))  # Pad to multiple of 8
        
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i:i+8]
            byte = 0
            for j, bit in enumerate(chunk):
                byte |= (bit << (7 - j))
            bytes_data.append(byte)
        return bytes_data

    def encrypt_block(self, data_bytes):
        """Encrypt bytes data (requires 8-byte aligned input)"""
        bits = self.bytes_to_bits(data_bytes)
        
        if len(bits) % 64 != 0:
            raise ValueError("DES input must be 8-byte aligned")
        
        encrypted_bits = []
        for i in range(0, len(bits), 64):
            block = bits[i:i+64]
            encrypted_bits += self._encrypt_single_block(block)
        
        return self.bits_to_bytes(encrypted_bits)

    def decrypt_block(self, data_bytes):
        """Decrypt bytes data (returns raw output)"""
        bits = self.bytes_to_bits(data_bytes)
        
        decrypted_bits = []
        for i in range(0, len(bits), 64):
            block = bits[i:i+64]
            decrypted_bits += self._decrypt_single_block(block)
        
        return self.bits_to_bytes(decrypted_bits)

    def _encrypt_single_block(self, block):
        """Core DES encryption for a single block"""
        block = self.permute(block, self.IP)
        left = block[:32]
        right = block[32:]
        
        for i in range(16):
            new_left = right
            f_result = self.feistel(right, self.subkeys[i])
            new_right = [l ^ f for l, f in zip(left, f_result)]
            left, right = new_left, new_right
        
        combined = right + left
        return self.permute(combined, self.FP)

    def _decrypt_single_block(self, block):
        """Core DES decryption for a single block"""
        self.subkeys = self.subkeys[::-1]  # Reverse subkeys for decryption
        decrypted = self._encrypt_single_block(block)
        self.subkeys = self.subkeys[::-1]  # Restore original subkeys
        return decrypted
    

# ========================
#    Vigenère Cipher
# ========================
class Vigenere:
    def __init__(self, key):
        if not key.isalpha():
            raise ValueError("Key must contain only alphabetic characters")
        self.key = key.upper()
    
    def encrypt(self, plaintext):
        key_as_int = [ord(k) - ord('A') for k in self.key]
        ciphertext = []
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                shift = key_as_int[key_index % len(key_as_int)]
                if char.isupper():
                    ciphertext.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
                else:
                    ciphertext.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
                key_index += 1
            else:
                ciphertext.append(char)
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        key_as_int = [ord(k) - ord('A') for k in self.key]
        plaintext = []
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                shift = key_as_int[key_index % len(key_as_int)]
                if char.isupper():
                    plaintext.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    plaintext.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                key_index += 1
            else:
                plaintext.append(char)
        return ''.join(plaintext)
    

# ========================
#     Triple DES (3DES)
# ========================
class TripleDES:
    def __init__(self, key):
        if len(key) != 24:
            raise ValueError("3DES key must be 24 bytes long")
        self.des1 = DES(key[:8])
        self.des2 = DES(key[8:16])
        self.des3 = DES(key[16:])

    def encrypt(self, data):
        padded_data = pkcs7_pad(data, block_size=8)
        return self.des3.encrypt_block(
            self.des2.decrypt_block(
                self.des1.encrypt_block(padded_data)
            )
        )

    def decrypt(self, data):
        decrypted = self.des1.decrypt_block(
            self.des2.encrypt_block(
                self.des3.decrypt_block(data)
            )
        )
        return pkcs7_unpad(decrypted)


# ========================
#      AES Implementation
# ========================

def pkcs7_pad(data, block_size=16):
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)

def pkcs7_unpad(data):
    return data[:-data[-1]]

class AES:
    # AES S-box and other constants
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes")
        self.key = key
        self.rounds = {16:10, 24:12, 32:14}[len(key)]
        self.expanded_key = self.key_expansion()

    @staticmethod
    def sub_word(word):
        return [AES.S_BOX[b] for b in word]

    @staticmethod
    def rot_word(word):
        return word[1:] + word[0:1]

    def key_expansion(self):
        key = [b for b in self.key]
        key_size = len(self.key)
        expanded_size = 16 * (self.rounds + 1)
        w = []
        
        for i in range(key_size // 4):
            w.append(key[4*i:4*i+4])
            
        for i in range(key_size // 4, 4 * (self.rounds + 1)):
            temp = w[i-1]
            if i % (key_size // 4) == 0:
                temp = AES.sub_word(AES.rot_word(temp))
                temp[0] ^= AES.RCON[i//(key_size//4)-1]
            elif key_size == 32 and i % 8 == 4:
                temp = AES.sub_word(temp)
            w.append([a ^ b for a, b in zip(w[i - key_size//4], temp)])
            
        return [b for word in w for b in word][:expanded_size]

    @staticmethod
    def sub_bytes(state):
        return [AES.S_BOX[b] for b in state]

    @staticmethod
    def inv_sub_bytes(state):
        return [AES.INV_S_BOX[b] for b in state]

    @staticmethod
    def shift_rows(state):
        return [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]

    @staticmethod
    def inv_shift_rows(state):
        return [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3]
        ]

    @staticmethod
    def mix_columns(state):
        new_state = []
        for i in range(4):
            s0 = state[i*4]
            s1 = state[i*4+1]
            s2 = state[i*4+2]
            s3 = state[i*4+3]
            
            new_state += [
                AES.gmul(0x02, s0) ^ AES.gmul(0x03, s1) ^ s2 ^ s3,
                s0 ^ AES.gmul(0x02, s1) ^ AES.gmul(0x03, s2) ^ s3,
                s0 ^ s1 ^ AES.gmul(0x02, s2) ^ AES.gmul(0x03, s3),
                AES.gmul(0x03, s0) ^ s1 ^ s2 ^ AES.gmul(0x02, s3)
            ]
        return new_state

    @staticmethod
    def inv_mix_columns(state):
        new_state = []
        for i in range(4):
            s0 = state[i*4]
            s1 = state[i*4+1]
            s2 = state[i*4+2]
            s3 = state[i*4+3]
            
            new_state += [
                AES.gmul(0x0e, s0) ^ AES.gmul(0x0b, s1) ^ AES.gmul(0x0d, s2) ^ AES.gmul(0x09, s3),
                AES.gmul(0x09, s0) ^ AES.gmul(0x0e, s1) ^ AES.gmul(0x0b, s2) ^ AES.gmul(0x0d, s3),
                AES.gmul(0x0d, s0) ^ AES.gmul(0x09, s1) ^ AES.gmul(0x0e, s2) ^ AES.gmul(0x0b, s3),
                AES.gmul(0x0b, s0) ^ AES.gmul(0x0d, s1) ^ AES.gmul(0x09, s2) ^ AES.gmul(0x0e, s3)
            ]
        return new_state

    @staticmethod
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return p

    def add_round_key(self, state, round_key):
        return [s ^ k for s, k in zip(state, round_key)]

    def encrypt_block(self, block):
        state = list(block)
        state = self.add_round_key(state, self.expanded_key[0:16])
        
        for i in range(1, self.rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.expanded_key[16*i:16*(i+1)])
            
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.expanded_key[-16:])
        return bytes(state)

    def decrypt_block(self, block):
        state = list(block)
        state = self.add_round_key(state, self.expanded_key[-16:])
        
        for i in range(self.rounds-1, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.expanded_key[16*i:16*(i+1)])
            state = self.inv_mix_columns(state)
            
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.expanded_key[0:16])
        return bytes(state)
    
    def encrypt(self, plaintext):
        plaintext = pkcs7_pad(plaintext)
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            ciphertext += self.encrypt_block(block)
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            plaintext += self.decrypt_block(block)
        return pkcs7_unpad(plaintext)
    

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Tool")
        
        # Algorithm Selection
        self.algorithm = tk.StringVar(value="DES")
        tk.Label(root, text="Select Algorithm:").grid(row=0, column=0, padx=5, pady=5)
        algorithms = [("DES", "DES"), ("3DES", "3DES"), ("AES", "AES"), ("Vigenère", "Vigenère")]
        for i, (text, val) in enumerate(algorithms):
            tk.Radiobutton(root, text=text, variable=self.algorithm, value=val).grid(row=0, column=i+1)
        
        # File Selection
        tk.Label(root, text="File:").grid(row=1, column=0, padx=5, pady=5)
        self.file_entry = tk.Entry(root, width=40)
        self.file_entry.grid(row=1, column=1, columnspan=3)
        tk.Button(root, text="Browse", command=self.browse_file).grid(row=1, column=4)
        
        # Key Input
        tk.Label(root, text="Key:").grid(row=2, column=0, padx=5, pady=5)
        self.key_entry = tk.Entry(root, width=40)
        self.key_entry.grid(row=2, column=1, columnspan=3)
        
        # Operation Buttons
        tk.Button(root, text="Encrypt", command=self.encrypt).grid(row=3, column=1, pady=10)
        tk.Button(root, text="Decrypt", command=self.decrypt).grid(row=3, column=2, pady=10)
        
        # Status/Result
        self.status = tk.Label(root, text="", fg="green")
        self.status.grid(row=4, column=0, columnspan=5)
        
        # Performance Metrics
        self.time_label = tk.Label(root, text="Time: 0ms")
        self.time_label.grid(row=5, column=0, columnspan=5)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def process_file(self, mode):
        start_time = time.time()
        try:
            algorithm = self.algorithm.get()
            in_file = self.file_entry.get()

            # Generate output filename
            base, ext = os.path.splitext(in_file)
            if mode == "encrypt":
                out_file = f"{base}_encrypted{ext}"
            else:
                if "_encrypted" not in base:
                    raise ValueError("File to decrypt must have '_encrypted' in name")
                base_part = base.replace("_encrypted", "")
                out_file = f"{base_part}_decrypted{ext}"

            # Vigenère Cipher Handling
            if algorithm == "Vigenère":
                key = self.key_entry.get()
                if not key:
                    raise ValueError("Vigenère key cannot be empty")
                if not key.isalpha():
                    raise ValueError("Vigenère key must contain only letters")

                # Read/write text files
                with open(in_file, "r", encoding="utf-8") as f:
                    data = f.read()

                cipher = Vigenere(key)
                
                if mode == "encrypt":
                    result = cipher.encrypt(data)
                    # Verification
                    decrypted = cipher.decrypt(result)
                else:
                    result = cipher.decrypt(data)
                    decrypted = ""  # No verification needed for decryption

                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(result)

                if mode == "encrypt" and decrypted != data:
                    raise ValueError("Verification failed: Vigenère decryption mismatch")

            # Other Algorithms (DES/3DES/AES)
            else:
                key = self.key_entry.get().encode('utf-8')
                
                # Existing key validation and binary handling
                if algorithm == "DES" and len(key) != 8:
                    raise ValueError("DES requires 8-byte key")
                elif algorithm == "3DES" and len(key) != 24:
                    raise ValueError("3DES requires 24-byte key")
                elif algorithm == "AES" and len(key) not in [16, 24, 32]:
                    raise ValueError("AES requires 16/24/32-byte key")

                if mode == "encrypt":
                    with open(in_file, "rb") as f:
                        data = f.read()

                    if algorithm == "DES":
                        padded_data = pkcs7_pad(data, block_size=8)
                        cipher = DES(key)
                        result = cipher.encrypt_block(padded_data)
                    elif algorithm == "3DES":
                        cipher = TripleDES(key)
                        result = cipher.encrypt(data)
                    elif algorithm == "AES":
                        cipher = AES(key)
                        result = cipher.encrypt(data)

                    with open(out_file, "wb") as f:
                        f.write(result)

                    # Verification
                    if algorithm == "DES":
                        decrypted = pkcs7_unpad(cipher.decrypt_block(result))
                    elif algorithm == "3DES":
                        decrypted = cipher.decrypt(result)
                    elif algorithm == "AES":
                        decrypted = cipher.decrypt(result)

                    if decrypted != data:
                        raise ValueError("Verification failed")

                else:  # Decrypt
                    with open(in_file, "rb") as f:
                        data = f.read()

                    if algorithm == "DES":
                        cipher = DES(key)
                        decrypted = cipher.decrypt_block(data)
                        result = pkcs7_unpad(decrypted)
                    elif algorithm == "3DES":
                        cipher = TripleDES(key)
                        result = cipher.decrypt(data)
                    elif algorithm == "AES":
                        cipher = AES(key)
                        result = cipher.decrypt(data)

                    with open(out_file, "wb") as f:
                        f.write(result)

            elapsed = (time.time() - start_time) * 1000
            self.status.config(text=f"{mode.capitalize()}ion successful!" + 
                            (" Verified!" if mode == "encrypt" else ""))
            self.time_label.config(text=f"Time: {elapsed:.2f}ms")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt(self):
        self.process_file("encrypt")

    def decrypt(self):
        self.process_file("decrypt")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
       
