import tkinter as tk
from tkinter import messagebox
import re  # Regular expression module

# Function to check password strength
def check_password_strength(password):
    if len(password) < 8:
        return "Password is too short! It should be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return "Password should contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password should contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Password should contain at least one digit."
    if not re.search(r'[@#$%^&+=]', password):
        return "Password should contain at least one special character (@, #, $, %, etc.)."
    
    return "Password is strong!"

# Function to handle button click event
def on_check_password():
    password = password_entry.get()  # Get the password from the entry field
    result = check_password_strength(password)
    # Show the result in a pop-up message box
    messagebox.showinfo("Password Strength", result)

# Function to toggle password visibility
def toggle_password():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

# Create the main application window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x230")  # Set a larger window for better UI

# Set background color
root.configure(bg="#f0f0f0")

# Create a label for instructions
instruction_label = tk.Label(root, text="Enter a password to check its strength:", font=("Arial", 12), bg="#f0f0f0")
instruction_label.pack(pady=10)

# Create an entry widget for user input (password)
password_entry = tk.Entry(root, font=("Arial", 12), show="*")
password_entry.pack(pady=10)

# Create a checkbox for "Show Password"
show_password_var = tk.BooleanVar()  # Track the state of the checkbox
show_password_checkbox = tk.Checkbutton(root, text="Show Password", font=("Arial", 10), variable=show_password_var, command=toggle_password, bg="#f0f0f0")
show_password_checkbox.pack()

# Create a button to check password strength
check_button = tk.Button(root, text="Check Password", font=("Arial", 12, "bold"), command=on_check_password, bg="#4CAF50", fg="white", relief="raised", padx=10, pady=5)
check_button.pack(pady=20)

# Add watermark at the bottom of the window
watermark_label = tk.Label(root, text="CODEVERTEX-sumit", font=("Arial", 10), fg="gray", bg="#f0f0f0")
watermark_label.pack(side="bottom", pady=10)

# Start the GUI event loop
root.mainloop()
