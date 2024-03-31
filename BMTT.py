import tkinter as tk
from tkinter import ttk

def generate_playfair_key(key):
    # Generating Playfair key matrix
    key = key.replace(" ", "").upper()
    key_matrix = ""
    for char in key:
        if char not in key_matrix:
            key_matrix += char
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No 'J' in Playfair
    for char in alphabet:
        if char not in key_matrix:
            key_matrix += char

    key_matrix = [list(key_matrix[i:i + 5]) for i in range(0, 25, 5)]
    return key_matrix

def find_position(matrix, char):
    # Find position of a character in the key matrix
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j

def playfair_encrypt(plaintext, key):
    key_matrix = generate_playfair_key(key)
    plaintext = plaintext.replace(" ", "").upper().replace("J", "I")
    ciphertext = ""
    for i in range(0, len(plaintext), 2):
        char1, char2 = plaintext[i], plaintext[i + 1]
        row1, col1 = find_position(key_matrix, char1)
        row2, col2 = find_position(key_matrix, char2)
        if row1 == row2:
            ciphertext += key_matrix[row1][(col1 + 1) % 5] + key_matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += key_matrix[(row1 + 1) % 5][col1] + key_matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += key_matrix[row1][col2] + key_matrix[row2][col1]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    key_matrix = generate_playfair_key(key)
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_position(key_matrix, char1)
        row2, col2 = find_position(key_matrix, char2)
        if row1 == row2:
            plaintext += key_matrix[row1][(col1 - 1) % 5] + key_matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += key_matrix[(row1 - 1) % 5][col1] + key_matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += key_matrix[row1][col2] + key_matrix[row2][col1]
    return plaintext

def encrypt_text():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    encrypted_text = playfair_encrypt(plaintext, key)
    encrypted_entry.delete(0, tk.END)
    encrypted_entry.insert(0, encrypted_text)

def decrypt_text():
    ciphertext = encrypted_entry.get()
    key = key_entry.get()
    decrypted_text = playfair_decrypt(ciphertext, key)
    decrypted_entry.delete(0, tk.END)
    decrypted_entry.insert(0, decrypted_text)

root = tk.Tk()
root.title("Playfair Cipher")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(frame, text="Key:").grid(row=0, column=0, sticky=tk.W)
key_entry = ttk.Entry(frame)
key_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E))

ttk.Label(frame, text="Plaintext:").grid(row=1, column=0, sticky=tk.W)
plaintext_entry = ttk.Entry(frame)
plaintext_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E))

ttk.Label(frame, text="Encrypted Text:").grid(row=2, column=0, sticky=tk.W)
encrypted_entry = ttk.Entry(frame)
encrypted_entry.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E))

ttk.Label(frame, text="Ciphertext:").grid(row=3, column=0, sticky=tk.W)
ciphertext_entry = ttk.Entry(frame)
ciphertext_entry.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E))

encrypt_button = ttk.Button(frame, text="Encrypt", command=encrypt_text)
encrypt_button.grid(row=4, column=1, sticky=(tk.W, tk.E))

decrypt_button = ttk.Button(frame, text="Decrypt", command=decrypt_text)
decrypt_button.grid(row=4, column=2, sticky=(tk.W, tk.E))

root.mainloop()