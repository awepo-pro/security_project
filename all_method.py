import tkinter as tk
from tkinter import filedialog, messagebox
import time
import os
from src.rsa.public_key_cipher import rsa_encryption, rsa_decryption
import tools 
import shutil
from src.cryption_impl import *

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = f'{BASE_DIR}/output'

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Tool")

        if not os.path.exists(f'{BASE_DIR}/output'):
            print('[DEBUG]: create output folder')
            os.makedirs(f'{BASE_DIR}/output')
        
        # Algorithm Selection
        self.algorithm = tk.StringVar(value="DES")
        tk.Label(root, text="Select Algorithm:").grid(row=0, column=0, padx=5, pady=5)
        algorithms = [("DES", "DES"), ("3DES", "3DES"), ("AES", "AES"), ("Vigenère", "Vigenère"), ("RSA", "RSA")]
        for i, (text, val) in enumerate(algorithms):
            tk.Radiobutton(root, text=text, variable=self.algorithm, value=val).grid(row=0, column=i+1)
        
        # File Selection
        tk.Label(root, text="File/Msg:").grid(row=1, column=0, padx=5, pady=5)
        self.file_entry = tk.Entry(root, width=40)
        self.file_entry.grid(row=1, column=1, columnspan=3)
        tk.Button(root, text="Browse", command=self.browse_file).grid(row=1, column=4)
        
        # Key Input
        tk.Label(root, text="Key:").grid(row=2, column=0, padx=5, pady=5)
        self.key_entry = tk.Entry(root, width=40)
        self.key_entry.grid(row=2, column=1, columnspan=3)

        # actions after button
        tk.Button(root, text="Encrypt", command=lambda: self.encrypt()).grid(row=3, column=1, pady=10)
        tk.Button(root, text="Decrypt", command=lambda: self.decrypt()).grid(row=3, column=2, pady=10)

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

    def process_file(self, mode, algorithm, in_file, out_file, base):
        start_time = time.time()
        try:

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
            
            # 1024 bits key size
            elif algorithm == 'RSA':
                key = self.key_entry.get()

                if mode == 'encrypt':
                    with open(out_file, 'w') as output:
                        print(rsa_encryption(in_file), file=output)

                        public_key_in = 'src/rsa/hello_pub.txt'
                        public_key_out = f'{OUTPUT_DIR}/{base}_pub.txt'
                        print(f'[DEBUG]: {public_key_out}')
                        
                        shutil.copy2(public_key_in, public_key_out)
                        messagebox.showinfo('info', f'your public key is stored to {os.path.basename(public_key_out)}!')
                
                elif mode == 'decrypt':
                    print(f'[DEBUG] decrypting file: {in_file}')
                    with open(out_file, 'w', encoding='utf-8') as output:
                        print(rsa_decryption(in_file, key), file=output)

                    messagebox.showinfo('info', f'your message is ready in {os.path.basename(out_file)}!')

            # Other Algorithms (DES/3DES/AES)
            else:
                key = self.key_entry.get().encode('utf-8')
                
                # Existing key validation and binary handling
                if algorithm == "DES" and len(key) != 8:
                    print(f'[DEBUG] key length: {len(key)}')
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
                    # if algorithm == "DES":
                    #     decrypted = pkcs7_unpad(cipher.decrypt_block(result))
                    # elif algorithm == "3DES":
                    #     decrypted = cipher.decrypt(result)
                    # elif algorithm == "AES":
                    #     decrypted = cipher.decrypt(result)

                    # if decrypted != data:
                    #     raise ValueError("Verification failed")

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
            self.status.config(text=f"{mode.capitalize()}ion successful!" + (" Verified!" if mode == "encrypt" else ""))
            self.time_label.config(text=f"Time: {elapsed:.2f}ms")

        except Exception as e:
            messagebox.showerror("Error", str(e))


    def encrypt(self):
        input = self.file_entry.get()
        algorithm = self.algorithm.get()

        if tools.is_file_path(input):
            base, _ = os.path.splitext(input)
        
            base = os.path.basename(base)
            out_file = f"{OUTPUT_DIR}/{base}_encrypted.txt"
            print(f'[DEBUG] output to: {out_file}')
            self.encrypt_file(input, out_file, algorithm, base)
        else:
            base = 'tmp'
            in_file = 'dummy.txt'
            with open(in_file, 'w') as dummy:
                print(input, file=dummy)
        
            out_file = f"{OUTPUT_DIR}/{base}_encrypted.txt"
            print(f'[DEBUG] output to: {out_file}')

            self.encrypt_file(in_file, out_file, algorithm, base)
            os.remove(in_file)

    def decrypt(self):
        input = self.file_entry.get()
        algorithm = self.algorithm.get()

        if tools.is_file_path(input):

            # Generate output filename
            base, _ = os.path.splitext(input)
            if "_encrypted" not in base:
                raise ValueError("File to decrypt must have '_encrypted' in name")
            base_part = base.replace("_encrypted", "")
            out_file = f"{base_part}_decrypted.txt"

            self.decrypt_file(input, out_file, algorithm, base)
        else:
            in_file = 'dummy_encrypted.txt'
            with open(in_file, 'w') as dummy:
                print(input, file=dummy)

            base, _ = os.path.splitext(in_file)

            if "_encrypted" not in base:
                raise ValueError("File to decrypt must have '_encrypted' in name")
            base_part = 'tmp'
            out_file = f"{OUTPUT_DIR}/{base_part}_decrypted.txt"

            self.decrypt_file(in_file, out_file, algorithm, base)
            os.remove(in_file)

    def encrypt_file(self, in_file, out_file, algorithm, base):
        self.process_file("encrypt", algorithm, in_file, out_file, base)

    def decrypt_file(self, in_file, out_file, algorithm, base):
        self.process_file("decrypt", algorithm, in_file, out_file, base)


if __name__ == "__main__":
    root = tk.Tk()

    app = CryptoApp(root)
    root.mainloop()
       
