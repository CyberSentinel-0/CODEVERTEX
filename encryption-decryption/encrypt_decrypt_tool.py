import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import tkinter as tk
from tkinter import messagebox
import pyperclip  # Used to copy the encrypted and decrypted messages to clipboard

# AES Encryption/Decryption Functions
def encrypt_aes(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def decrypt_aes(encrypted_message, key):
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        iv = encrypted_message[:AES.block_size]
        ct = encrypted_message[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode()
        return decrypted
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Error: {e}")
        return None

# Generate AES Key (AES-128)
def generate_aes_key():
    key = get_random_bytes(16)
    with open("aes_secret.key", "wb") as key_file:
        key_file.write(key)
    return key

# Load AES Key
def load_aes_key():
    if os.path.exists("aes_secret.key"):
        return open("aes_secret.key", "rb").read()
    else:
        return generate_aes_key()

# GUI Application
def run_gui():
    root = tk.Tk()
    root.title("AES Encryption Tool")
    root.geometry("600x450")  # Increased window size
    root.configure(bg="#f5f5f5")

    def center_window(width, height):
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        position_top = int(screen_height / 2 - height / 2)
        position_right = int(screen_width / 2 - width / 2)
        root.geometry(f'{width}x{height}+{position_right}+{position_top}')

    center_window(600, 450)

    # GUI Components
    title_label = tk.Label(root, text="AES Encryption Tool", font=("Helvetica", 16, "bold"), bg="#f5f5f5", fg="#333")
    title_label.pack(pady=20)

    message_entry_label = tk.Label(root, text="Enter Message or Encrypted Message", font=("Helvetica", 10), bg="#f5f5f5")
    message_entry_label.pack(pady=5)

    message_entry = tk.Entry(root, width=40, font=("Helvetica", 12))
    message_entry.pack(pady=10)

    # Display Encrypted Message (non-editable label)
    encrypted_message_label = tk.Label(root, text="Encrypted Message", font=("Helvetica", 12, "bold"), bg="#f5f5f5", anchor="w")
    encrypted_message_label.pack(pady=5)

    encrypted_message_display = tk.Label(root, text="", font=("Helvetica", 10), bg="#f5f5f5", anchor="w", wraplength=400)
    encrypted_message_display.pack(pady=10)

    # Button to copy encrypted message to clipboard
    def copy_encrypted_message():
        encrypted_message = encrypted_message_display.cget("text")
        if encrypted_message:  # Only copy if there's text to copy
            pyperclip.copy(encrypted_message)  # Copy to clipboard
            messagebox.showinfo("Copied", "Encrypted message copied to clipboard!")
        else:
            messagebox.showwarning("Error", "No encrypted message to copy.")

    def encrypt_message():
        message = message_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        key = load_aes_key()
        encrypted_message = encrypt_aes(message, key)
        encrypted_message_display.config(text=encrypted_message)  # Show the encrypted message

    def decrypt_message():
        encrypted_message = message_entry.get()
        if not encrypted_message:
            messagebox.showerror("Error", "Encrypted message cannot be empty!")
            return
        key = load_aes_key()
        decrypted_message = decrypt_aes(encrypted_message, key)
        if decrypted_message:
            # Open a new window for the decrypted message
            create_decrypted_window(decrypted_message)

    # Function to create a new window for the decrypted message
    def create_decrypted_window(decrypted_message):
        # Create a new top-level window
        decrypted_window = tk.Toplevel(root)
        decrypted_window.title("Decrypted Message")
        decrypted_window.geometry("400x300")
        decrypted_window.configure(bg="#f5f5f5")

        # Display the decrypted message in the new window
        decrypted_message_label = tk.Label(decrypted_window, text=f"Decrypted Message:\n{decrypted_message}",
                                           font=("Helvetica", 12), bg="#f5f5f5", anchor="w", wraplength=350)
        decrypted_message_label.pack(pady=20)

        # Button to copy decrypted message to clipboard
        def copy_decrypted_message():
            pyperclip.copy(decrypted_message)  # Copy to clipboard
            messagebox.showinfo("Copied", "Decrypted message copied to clipboard!")

        # Copy button for decrypted message
        copy_decrypted_button = tk.Button(decrypted_window, text="Copy Decrypted Message", width=20, height=2, bg="#3b5998", fg="white", font=("Helvetica", 10), command=copy_decrypted_message)
        copy_decrypted_button.pack(pady=10)

    # Copy button for encrypted message (now at the top)
    copy_button = tk.Button(root, text="Copy Encrypted Message", width=20, height=2, bg="#3b5998", fg="white", font=("Helvetica", 10), command=copy_encrypted_message)
    copy_button.pack(pady=10)

    # Buttons for encryption and decryption (swapped positions)
    encrypt_button = tk.Button(root, text="Encrypt", width=15, height=2, bg="#4CAF50", fg="white", font=("Helvetica", 12, "bold"), command=encrypt_message)
    encrypt_button.pack(pady=10)

    decrypt_button = tk.Button(root, text="Decrypt", width=15, height=2, bg="#f44336", fg="white", font=("Helvetica", 12, "bold"), command=decrypt_message)
    decrypt_button.pack(pady=10)

    # Watermark label (at the bottom)
    watermark_label = tk.Label(root, text="CODEVERTEX-sumit", font=("Helvetica", 8, "italic"), bg="#f5f5f5", fg="#aaa")
    watermark_label.pack(side="bottom", pady=5)

    root.mainloop()

# Main Program Execution
if __name__ == "__main__":
    run_gui()
