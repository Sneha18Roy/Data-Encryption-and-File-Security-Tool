# =========================================================
# ADVANCED DATA ENCRYPTION & FILE SECURITY TOOL
# AES-256 + RSA HYBRID ENCRYPTION GUI
# =========================================================

import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

# =========================================================
# KEY MANAGEMENT (FIXED)
# =========================================================

def generate_aes_key():
    key = os.urandom(32)  # Always 32 bytes
    with open("secret.key", "wb") as f:
        f.write(key)

def load_aes_key():
    if not os.path.exists("secret.key"):
        generate_aes_key()

    key = open("secret.key", "rb").read()

    # FIX: ensure correct key size
    if len(key) != 32:
        generate_aes_key()
        key = open("secret.key", "rb").read()

    return key

# =========================================================
# AES FUNCTIONS
# =========================================================

def aes_encrypt_data(data, key):
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    return iv + encryptor.update(padded) + encryptor.finalize()

def aes_decrypt_data(data, key):
    iv = data[:16]
    encrypted = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# =========================================================
# PASSWORD BASED AES
# =========================================================

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# =========================================================
# RSA
# =========================================================

def generate_rsa_keys():
    if os.path.exists("private.pem") and os.path.exists("public.pem"):
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# =========================================================
# ENCRYPTION
# =========================================================

def encrypt_file():
    method = encryption_method.get()
    file_path = filedialog.askopenfilename()

    if not file_path:
        return

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if method == "aes":
            key = load_aes_key()
            encrypted = aes_encrypt_data(data, key)
            output = file_path + ".aes"

            with open(output, "wb") as f:
                f.write(encrypted)

        elif method == "password":
            password = simpledialog.askstring("Password", "Enter Password:", show="*")
            if not password:
                return

            salt = os.urandom(16)
            key = derive_key(password, salt)
            encrypted = aes_encrypt_data(data, key)

            output = file_path + ".pwd"

            with open(output, "wb") as f:
                f.write(salt + encrypted)

        elif method == "hybrid":
            aes_key = os.urandom(32)
            encrypted_data = aes_encrypt_data(data, aes_key)

            with open("public.pem", "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

            encrypted_key = public_key.encrypt(
                aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            output = file_path + ".hyb"

            with open(output, "wb") as f:
                f.write(len(encrypted_key).to_bytes(4, "big"))
                f.write(encrypted_key)
                f.write(encrypted_data)

        messagebox.showinfo("Success", "File Encrypted Successfully")

    except Exception as e:
        messagebox.showerror("Error", f"Encryption Failed\n\n{e}")

# =========================================================
# DECRYPTION
# =========================================================

def decrypt_file():
    file_path = filedialog.askopenfilename()

    if not file_path:
        return

    try:
        if file_path.endswith(".aes"):
            key = load_aes_key()
            data = open(file_path, "rb").read()
            decrypted = aes_decrypt_data(data, key)

        elif file_path.endswith(".pwd"):
            password = simpledialog.askstring("Password", "Enter Password:", show="*")
            if not password:
                return

            data = open(file_path, "rb").read()
            salt = data[:16]
            encrypted = data[16:]

            key = derive_key(password, salt)
            decrypted = aes_decrypt_data(encrypted, key)

        elif file_path.endswith(".hyb"):
            with open(file_path, "rb") as f:
                key_size = int.from_bytes(f.read(4), "big")
                encrypted_key = f.read(key_size)
                encrypted_data = f.read()

            private_key = serialization.load_pem_private_key(
                open("private.pem", "rb").read(),
                password=None,
                backend=default_backend()
            )

            aes_key = private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            decrypted = aes_decrypt_data(encrypted_data, aes_key)

        else:
            messagebox.showerror("Error", "Unsupported file type")
            return

        # SAVE FILE (FIXED - no overwrite issues)
        save_path = filedialog.asksaveasfilename(defaultextension="", title="Save Decrypted File")

        if save_path:
            with open(save_path, "wb") as f:
                f.write(decrypted)

            messagebox.showinfo("Success", "File Decrypted Successfully")

    except Exception as e:
        messagebox.showerror("Error", f"Decryption Failed\n\n{e}")

# =========================================================
# SETUP
# =========================================================

generate_rsa_keys()
load_aes_key()

# =========================================================
# UI (SIMPLE + WORKING)
# =========================================================

root = tk.Tk()
root.title("Advanced Encryption Tool")
root.geometry("900x600")
root.configure(bg="#111827")

frame = tk.Frame(root, bg="#111827")
frame.pack(expand=True)

tk.Label(frame, text="Advanced Encryption Tool",
         font=("Segoe UI", 22, "bold"),
         bg="#111827", fg="white").pack(pady=20)

encryption_method = tk.StringVar(value="aes")

tk.Radiobutton(frame, text="AES-256 Symmetric", variable=encryption_method, value="aes",
               bg="#111827", fg="white",
               selectcolor="black").pack(anchor="w", padx=40)

tk.Radiobutton(frame, text="Password AES-256", variable=encryption_method, value="password",
               bg="#111827", fg="white",
               selectcolor="black").pack(anchor="w", padx=40)

tk.Radiobutton(frame, text="Hybrid RSA + AES", variable=encryption_method, value="hybrid",
               bg="#111827", fg="white",
               selectcolor="black").pack(anchor="w", padx=40)

tk.Button(frame, text="Encrypt File", command=encrypt_file,
          bg="green", fg="white", width=20).pack(pady=15)

tk.Button(frame, text="Decrypt File", command=decrypt_file,
          bg="blue", fg="white", width=20).pack(pady=10)

root.mainloop()