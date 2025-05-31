from io import StringIO
import signal
import tkinter as tk 
from tkinter import messagebox, simpledialog, filedialog, Menu
from tkinter import ttk
import math
import sqlite3
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime, timedelta
import os
import sys
import pyperclip
import threading
import time
import base64
import random
import string
import re
from tkinter import PhotoImage
from tkinter import *
from PIL import Image, ImageTk
import pyotp
import qrcode
import win32clipboard
import ctypes
import winreg
import subprocess
import shutil
from typing import Tuple, Optional
import requests
from getpass import getpass  # For secure password input
from tkinter import filedialog
import threading
import queue
from tkinter import scrolledtext
import itertools
from windows_toasts import Toast, WindowsToaster
import multiprocessing as mp
from functools import partial
from collections import Counter
import tracemalloc

# Constants
DB_FILE = "passwords.db"

# Global variable to store the reference to the "Add" button
global add_button_ref
add_button_ref = None

# Global variable to track the last activity time
last_activity_time = time.time()

def show_tooltip(widget, text):
    global tooltip
    hide_tooltip()
    x = widget.winfo_rootx() + widget.winfo_width() + 10
    y = widget.winfo_rooty() + 10

    tooltip = tk.Toplevel(widget)
    tooltip.wm_overrideredirect(True)
    tooltip.wm_geometry(f"+{x}+{y}")
    tooltip.configure(bg="#333333")

    frame = tk.Frame(tooltip, bg="#333333", bd=0, highlightthickness=0)
    frame.pack(padx=1, pady=1)

    label = tk.Label(
        frame,
        text=text,
        bg="#ffffff",
        fg="#333333",
        padx=10,
        pady=6,
        font=("Segoe UI", 10),
        wraplength=200,
        justify="left",
        relief="flat",
        bd=0
    )
    label.pack()

    # Optional drop shadow effect
    tooltip.lift()
    tooltip.attributes("-topmost", True)

def hide_tooltip():
    global tooltip
    if 'tooltip' in globals() and tooltip.winfo_exists():
        tooltip.destroy()

# Function to display setup welcome window before database creation
def initial_setup():
    def close_setup():
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            message_window.destroy()
            root.destroy()

    def on_create():
        message_window.destroy()

    # Hide default Tkinter root window
    root = tk.Tk()
    root.withdraw()

    # Create a welcome message window
    message_window = tk.Toplevel()
    message_window.title("Welcome to Password Manager!")
    message_window.geometry("450x250")
    message_window.configure(bg="#f0f0f0")

    # Set window icon
    message_window.iconbitmap(default="./Images/logo.ico")

    # Center window on screen
    message_window.update_idletasks()
    screen_width = message_window.winfo_screenwidth()
    screen_height = message_window.winfo_screenheight()
    x = (screen_width - 450) // 2
    y = (screen_height - 250) // 2
    message_window.geometry(f"+{x}+{y}")

    # Add Logo
    logo = tk.PhotoImage(file="./Images/logo.png")  # Ensure logo is in PNG format
    logo_label = tk.Label(message_window, image=logo, bg="#f0f0f0")
    logo_label.image = logo  # Keep a reference to prevent garbage collection
    logo_label.pack()

    # Welcome message
    label = tk.Label(
        message_window,
        text="Thank you for using Password Manager!\n\n"
             "Click 'Create' to set up your password database.",
        font=("Arial", 12, "bold"),
        fg="#333",
        bg="#f0f0f0",
        justify="center",
        wraplength=400
    )
    label.pack(pady=30)

    # Create button
    create_button = tk.Button(
        message_window,
        text="Create",
        font=("Arial", 12, "bold"),
        bg="#4CAF50",
        fg="white",
        padx=20,
        pady=5,
        borderwidth=2,
        relief="raised",
        command=on_create
    )
    create_button.pack()

    # Bind Enter key to simulate Create button press
    message_window.bind("<Return>", lambda event: on_create())

    message_window.protocol("WM_DELETE_WINDOW", close_setup)

    message_window.wait_window()  # Wait for the user to click "Create"

    root.destroy()

    # Ask user to set master password
    master_password = ask_initial_master_password()
    if not master_password:
        messagebox.showerror("Error", "Master password is required.")
        return None

    return master_password

def reset_timer(event=None):
    global last_activity_time
    last_activity_time = time.time()

def check_inactivity():
    global last_activity_time
    current_time = time.time()
    inactivity_period = current_time - last_activity_time

    if inactivity_period > settings[3]:  # settings[3] is the autologout time in seconds
        lock_system()

    root.after(1000, check_inactivity)  # Check every second

def lock_system():
    global root, add_button_ref

    # Destroy existing main window if it exists
    if root:
        root.destroy()
        root = None
        add_button_ref = None

    # Create a new root window for the lock screen
    lock_window = tk.Tk()
    lock_window.title("Session Locked")
    lock_window.geometry("400x200")
    lock_window.attributes('-topmost', True)  # Keep the window on top
    lock_window.resizable(False, False)

    # Center the window on the screen
    lock_window.update_idletasks()
    screen_width = lock_window.winfo_screenwidth()
    screen_height = lock_window.winfo_screenheight()
    x = (screen_width // 2) - (400 // 2)
    y = (screen_height // 2) - (200 // 2)
    lock_window.geometry(f"+{x}+{y}")

    # Make the window modal and handle close button
    lock_window.grab_set()
    lock_window.protocol("WM_DELETE_WINDOW", lambda: unlock_session(lock_window))

    # Message and unlock button
    tk.Label(lock_window, text="Your session has been locked due to inactivity.", font=("Arial", 12)).pack(pady=40)
    tk.Button(lock_window, text="Unlock", command=lambda: unlock_session(lock_window)).pack()

    lock_window.mainloop()

def unlock_session(lock_window):
    # Close the lock screen and restart your application
    lock_window.destroy()
    main()  # Restart your main application

# Ask for the master password for the first time
def ask_initial_master_password():
    while True:
        master_password = simpledialog.askstring("Master Password", "Enter the master password:\t\t\t", show="*")
        if master_password is None:  # User pressed "Cancel" or closed the dialog
            root.destroy()
        elif not master_password:
            messagebox.showwarning("Input Error", "Master password is required.")
        else:
            return master_password
        
# Ask for the master password
def ask_master_password():
    while True:
        master_password = simpledialog.askstring("Master Password", "Enter the master password:", show="*")
        if master_password is None:  # User pressed "Cancel" or closed the dialog
            root.destroy()
        elif not master_password:
            messagebox.showwarning("Input Error", "Master password is required.")
        elif not verify_master_password(master_password):
            messagebox.showerror("Invalid Password", "Incorrect master password. Please try again.")
        else:
            return master_password

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()
        exit()

# Function to retrieve the salt from the hashed_password in the database
def get_salt_from_database():
    """Retrieve the salt from the hashed_password stored in the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password FROM master_password")
    result = cursor.fetchone()
    conn.close()

    if not result:
        return None  # No master password set

    stored_hashed_password = base64.b64decode(result[0])
    salt = stored_hashed_password[:16]  # Extract the salt
    return salt

# Function to derive key from master password using PBKDF2
def derive_key(master_password, salt):
    """Generate a 256-bit key from the master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def store_master_password(master_password):
    """Hash and store the master password in the database."""
    salt = os.urandom(16)  # Generate a 16-byte salt
    key = derive_key(master_password, salt)  # Derive a key from the password
    hashed_password = base64.b64encode(salt + key).decode()  # Store salt + key together

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM master_password")  # Ensure only one master password exists
    cursor.execute("INSERT INTO master_password (hashed_password) VALUES (?)", (hashed_password,))
    conn.commit()
    conn.close()

def verify_master_password(entered_password):
    """Verify if the entered master password is correct and return the key."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password FROM master_password")
    stored_data = cursor.fetchone()
    conn.close()

    if not stored_data:
        return None  # No master password set

    stored_hashed_password = base64.b64decode(stored_data[0])
    salt = stored_hashed_password[:16]  # Extract the salt
    stored_key = stored_hashed_password[16:]  # Extract the stored key

    # Derive the key from entered password
    entered_key = derive_key(entered_password, salt)

    if entered_key == stored_key:
        return entered_key  # Return the actual key instead of True
    return None  # Return None if the password is incorrect

# Get recovery keys from the database
def get_recovery_keys():
    """Retrieve the hashed recovery keys from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_key FROM recovery_keys")
    hashed_recovery_keys = [row[0] for row in cursor.fetchall()]
    conn.close()
    return hashed_recovery_keys

# Verify recovery key
def verify_recovery_key(entered_key, hashed_recovery_keys):
    """Check if the entered recovery key is valid."""
    entered_key_hash = hashlib.sha256(entered_key.encode()).hexdigest()
    return entered_key_hash in hashed_recovery_keys

def verify_otp(encrypted_otp_secret):
    otp_secret = decrypt_things(encrypted_otp_secret, key, 256)  # Decrypt the OTP secret

    def submit_otp():
        entered_otp = otp_entry.get()
        totp = pyotp.TOTP(otp_secret)
        if totp.verify(entered_otp):
            otp_window.result = True
            otp_window.destroy()
        else:
            messagebox.showerror("Invalid OTP", "Incorrect OTP code. Try again.")

    def on_enter(event):
        submit_otp()

    def center_window(window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        position_top = int(screen_height / 2 - height / 2)
        position_right = int(screen_width / 2 - width / 2)
        window.geometry(f'{width}x{height}+{position_right}+{position_top}')

    otp_window = tk.Tk()
    otp_window.title("OTP Verification")
    otp_window.configure(bg="#f0f0f0")
    otp_window.result = False  # Default to False unless OTP is verified

    otp_window.iconbitmap(default="./Images/logo.ico")

    center_window(otp_window, 400, 250)
    
    tk.Label(otp_window, text="Enter the OTP code:", bg="#f0f0f0", font=("Arial", 12)).pack(pady=10)

    otp_entry = tk.Entry(otp_window, font=("Arial", 14), justify="center")
    otp_entry.pack(pady=10)

    submit_button = tk.Button(otp_window, text="Verify", command=submit_otp, font=("Arial", 12), bg="#4CAF50", fg="white")
    submit_button.pack(pady=10)

    otp_window.bind('<Return>', on_enter)

    # Ensure focus after window appears
    otp_window.lift()
    otp_window.focus_force()
    otp_window.after(100, lambda: otp_entry.focus())

    otp_window.wait_window()  # Wait until OTP window closes
    return otp_window.result
    
# Encrypt with AES based on selected AES bit size (128, 192, 256)
def encrypt_things(plain_text, key, aes_bits):
    iv = os.urandom(12)  # Generate a random 12-byte IV for GCM
    if aes_bits == 128:
        cipher = Cipher(algorithms.AES(key[:16]), modes.GCM(iv), backend=default_backend())  # 128-bit AES
    elif aes_bits == 192:
        cipher = Cipher(algorithms.AES(key[:24]), modes.GCM(iv), backend=default_backend())  # 192-bit AES
    else:  # AES-256
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())  # 256-bit AES

    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + encrypted_password).decode('utf-8')

# Decrypt with AES based on selected AES bit size (128, 192, 256)
def decrypt_things(encrypted_text, key, aes_bits):
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:12]  # First 12 bytes are the IV
        tag = encrypted_data[12:28]  # Next 16 bytes are the GCM tag
        ciphertext = encrypted_data[28:]  # Remaining bytes are the ciphertext

        if aes_bits == 128:
            cipher = Cipher(algorithms.AES(key[:16]), modes.GCM(iv, tag), backend=default_backend())  # 128-bit AES
        elif aes_bits == 192:
            cipher = Cipher(algorithms.AES(key[:24]), modes.GCM(iv, tag), backend=default_backend())  # 192-bit AES
        else:  # AES-256
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())  # 256-bit AES

        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_password.decode('utf-8')
    except Exception as e:
        return None  # Return None in case of decryption error

# Database setup
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS master_password (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        hashed_password TEXT NOT NULL)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS recovery_keys (
                        id INTEGER PRIMARY KEY,
                        hashed_key TEXT NOT NULL)''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        platformName TEXT NOT NULL,
        platformLabel TEXT NOT NULL,
        platformUser TEXT NOT NULL,
        encryptedPassword TEXT NOT NULL,
        platformURL TEXT,
        platformNote TEXT,
        createdAt TEXT NOT NULL,
        updatedAt TEXT NOT NULL,
        aes_bits INTEGER NOT NULL,
        mp_reprompt BOOLEAN DEFAULT 1,
        isFavourite BOOLEAN DEFAULT 0,
        isDeleted BOOLEAN DEFAULT 0,
        deletedAt TEXT DEFAULT NULL       
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS password_criteria (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        length INTEGER NOT NULL,
        include_uppercase BOOLEAN NOT NULL,
        include_lowercase BOOLEAN NOT NULL,
        include_digits BOOLEAN NOT NULL,
        include_minus BOOLEAN NOT NULL,
        include_underline BOOLEAN NOT NULL,
        include_space BOOLEAN NOT NULL,
        include_special BOOLEAN NOT NULL,
        include_brackets BOOLEAN NOT NULL,
        include_latin1 BOOLEAN NOT NULL
    )''')

    # Drop the old settings table if it exists
    # cursor.execute('''DROP TABLE IF EXISTS settings''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS attack_settings (
        dictionary_path TEXT,
        rainbow_table_path TEXT,
        guess_per_sec INTEGER DEFAULT 3000000,
        thread_count INTEGER DEFAULT 1,
        guess_per_sec_threshold INTEGER DEFAULT 10000000,
        default_dictionary_path TEXT,
        default_rainbow_table_path TEXT,
        default_guess_per_sec INTEGER DEFAULT 3000000,
        default_thread_count INTEGER DEFAULT 1,
        default_guess_per_sec_threshold INTEGER DEFAULT 10000000
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS rainbow_crack_time (
        length INTEGER PRIMARY KEY,
        base_time REAL NOT NULL
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
        mfa BOOLEAN NOT NULL,
        alerts BOOLEAN NOT NULL,
        backup BOOLEAN NOT NULL,
        autologout INTEGER NOT NULL,
        clipboard_timer INTEGER NOT NULL,
        otp_secret TEXT,
        backup_path TEXT           
    )''')
    
    # Simplified login attempts table
    cursor.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
                        attempts INTEGER DEFAULT 0,
                        last_attempt TIMESTAMP,
                        lockout_until TIMESTAMP)''')

    # Initialize if empty
    cursor.execute("SELECT COUNT(*) FROM login_attempts")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO login_attempts (attempts) VALUES (0)")

    # Insert default password criteria if the table is empty
    cursor.execute("SELECT COUNT(*) FROM password_criteria")
    if cursor.fetchone()[0] == 0:
        cursor.execute('''INSERT INTO password_criteria (length, include_uppercase, include_lowercase, include_digits, include_minus, include_underline, include_space, include_special, include_brackets, include_latin1)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (12, True, True, True, True, True, False, True, True, False))
        
    # Insert default settings if the table is empty
    cursor.execute("SELECT COUNT(*) FROM settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute('''INSERT INTO settings (mfa, alerts, backup, autologout, clipboard_timer, otp_secret, backup_path)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''', (False, True, False, 600, 10, '', './Backup'))
            
    # Insert default settings if not exists
    cursor.execute("SELECT COUNT(*) FROM attack_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute('''INSERT INTO attack_settings (
            dictionary_path, rainbow_table_path, 
            guess_per_sec, thread_count, guess_per_sec_threshold, default_dictionary_path, default_rainbow_table_path,
            default_guess_per_sec, default_thread_count, default_guess_per_sec_threshold
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
        ("./Dictionary", "./Rainbow_Table", 3000000, 1, 10000000, "./Dictionary", "./Rainbow_Table", 3000000, 1, 10000000))
    
    cursor.execute("SELECT COUNT(*) FROM rainbow_crack_time")
    if cursor.fetchone()[0] == 0:
        crack_times = [
            (0, 0.001),  # seconds (base time for 1 thread)
            (1, 0.001),
            (2, 0.001),
            (3, 0.01),
            (4, 0.1),
            (5, 1.0),
            (6, 10.0),
            (7, 60.0)
        ]
        cursor.executemany("INSERT INTO rainbow_crack_time (length, base_time) VALUES (?, ?)", crack_times)
    conn.commit()
    conn.close()

# Load passwords from the database and display in the table
def load_passwords():
    for row in tree.get_children():
        tree.delete(row)  # Clear existing rows

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords")
    records = cursor.fetchall()
    conn.close()
    
    if records:
        for row in records:
            decrypted_password = decrypt_things(row[4], key, row[8])  # Decrypt the password
            if decrypted_password is None:
                global root, add_button_ref
                messagebox.showerror("Invalid Password", "Incorrect master password. Please retry.")
                
                if root:
                    root.destroy()  # Close the current window

                # Reset global references
                root = None
                add_button_ref = None
                
                # Restart application
                main()
            masked_password = '*' * 10  # Mask password with asterisks
            # Insert all the fields including the id
            tree.insert("", tk.END, values=(row[0], row[1], row[2], row[3], masked_password, row[5], row[6], row[7], row[8] , decrypted_password, row[9]))

# Right-click context menu
def show_context_menu(event):
    context_menu.post(event.x_root, event.y_root)


# Function to check if clipboard history is enabled
def is_clipboard_history_enabled():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard")
        value, _ = winreg.QueryValueEx(key, "EnableClipboardHistory")
        winreg.CloseKey(key)
        print(f"Clipboard history enabled: {value == 1}")
        return value == 1
    except Exception as e:
        print(f"Failed to check clipboard history: {e}")
        return False

def copy_value(value):
    try:
        # Check if clipboard history is enabled
        clipboard_history_enabled = is_clipboard_history_enabled()
        
        # Temporarily disable clipboard history if needed
        if clipboard_history_enabled:
            # PowerShell script to disable clipboard history
            powershell_script = """
            Invoke-Expression "cmd.exe /c echo | clip"
            $RegPath = "HKCU:\\Software\\Microsoft\\Clipboard"
            if (Test-Path $RegPath) {
                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction Stop
                Write-Host "Clipboard history turned off." -ForegroundColor Green
            } else {
                Write-Host "Clipboard history not found. This feature may not be enabled on your system." -ForegroundColor Cyan
            }
            """

            # Run the PowerShell script
            process = subprocess.Popen(["powershell", "-Command", powershell_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()

            if process.returncode == 0:
                print("PowerShell script executed successfully.")
                print(output.decode())
            else:
                print("Error executing PowerShell script.")
                print(error.decode())

            time.sleep(1)  # Add a small delay to ensure the setting takes effect
        
        # Open the clipboard
        win32clipboard.OpenClipboard()
        # Clear the clipboard
        win32clipboard.EmptyClipboard()
        # Set the clipboard text
        win32clipboard.SetClipboardText(value)
        # Close the clipboard
        win32clipboard.CloseClipboard()
        
        messagebox.showinfo("Copied", "Value copied to clipboard!")
        countdown(settings[4], clipboard_history_enabled)
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to copy value: {e}")
        
def countdown(seconds, clipboard_history_enabled):
    def update_countdown(remaining):
        if remaining > 0:
            timer_label.config(text=f"Copied item will be cleared in {remaining} seconds...")
            root.after(1000, update_countdown, remaining - 1)
        else:
            # Clear the clipboard
            try:
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.CloseClipboard()

                # Re-enable clipboard history if it was initially enabled
                if clipboard_history_enabled:
                    # PowerShell script to enable clipboard history
                    powershell_script = """
                    $RegPath = "HKCU:\\Software\\Microsoft\\Clipboard"
                    if (-not (Test-Path $RegPath)) {
                        New-Item -Path $RegPath -Force
                    }
                    Set-ItemProperty -Path $RegPath -Name "EnableClipboardHistory" -Value 1
                    Write-Host "Clipboard history enabled." -ForegroundColor Green
                    """
                    
                    # Run the PowerShell script
                    process = subprocess.Popen(["powershell", "-Command", powershell_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    output, error = process.communicate()

                    if process.returncode == 0:
                        print("PowerShell script executed successfully.")
                        print(output.decode())
                    else:
                        print("Error executing PowerShell script.")
                        print(error.decode())

                timer_label.config(text="Clipboard cleared")
                # Schedule clearing of the message after 3 seconds
                root.after(3000, lambda: timer_label.config(text=""))

            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear clipboard: {e}")

    update_countdown(seconds)

def open_password_generation_form(parent_window):
    if hasattr(open_password_generation_form, "password_config_window") and \
       open_password_generation_form.password_config_window.winfo_exists():
        open_password_generation_form.password_config_window.lift()
        open_password_generation_form.password_config_window.focus()
        return

    password_config_window = tk.Toplevel(root)
    password_config_window.title("Password Configuration")
    password_config_window.configure(bg="#f0f0f0")
    #password_config_window.transient(root)  # Stay on top of parent
    password_config_window.grab_set()

    window_width = 350
    window_height = 500
    screen_width = password_config_window.winfo_screenwidth()
    screen_height = password_config_window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    password_config_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    open_password_generation_form.password_config_window = password_config_window
    password_config_window.protocol("WM_DELETE_WINDOW", lambda: (
        password_config_window.grab_release(),
        password_config_window.destroy()
    ))

    # Frame for layout
    main_frame = tk.Frame(password_config_window, bg="#f0f0f0")
    main_frame.pack(pady=10, fill=tk.BOTH, expand=True)
    main_frame.grid_columnconfigure(1, weight=1)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM password_criteria ORDER BY id DESC LIMIT 1")
    criteria = cursor.fetchone()
    conn.close()

    length = criteria[1] if criteria else 12
    include_uppercase = criteria[2] if criteria else True
    include_lowercase = criteria[3] if criteria else True
    include_digits = criteria[4] if criteria else True
    include_minus = criteria[5] if criteria else True
    include_underline = criteria[6] if criteria else True
    include_space = criteria[7] if criteria else False
    include_special = criteria[8] if criteria else True
    include_brackets = criteria[9] if criteria else True
    include_latin1 = criteria[10] if criteria else False

    # Input fields
    def add_option(row, label, var):
        tk.Label(main_frame, text=label, bg="#f0f0f0").grid(row=row, column=0, padx=10, pady=5, sticky="w")
        cb = tk.Checkbutton(main_frame, text="Yes", variable=var, bg="#f0f0f0")
        cb.grid(row=row, column=1, padx=10, pady=5, sticky="w")

    tk.Label(main_frame, text="Password Length:", bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="w")
    length_entry = tk.Entry(main_frame)
    length_entry.insert(0, str(length))
    length_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

    include_uppercase_var = tk.BooleanVar(value=include_uppercase)
    include_lowercase_var = tk.BooleanVar(value=include_lowercase)
    include_digits_var = tk.BooleanVar(value=include_digits)
    include_minus_var = tk.BooleanVar(value=include_minus)
    include_underline_var = tk.BooleanVar(value=include_underline)
    include_space_var = tk.BooleanVar(value=include_space)
    include_special_var = tk.BooleanVar(value=include_special)
    include_brackets_var = tk.BooleanVar(value=include_brackets)
    include_latin1_var = tk.BooleanVar(value=include_latin1)

    options = [
        ("Include Upper-case:", include_uppercase_var),
        ("Include Lower-case:", include_lowercase_var),
        ("Include Digits:", include_digits_var),
        ("Include Minus:", include_minus_var),
        ("Include Underline:", include_underline_var),
        ("Include Space:", include_space_var),
        ("Include Special Characters:", include_special_var),
        ("Include Brackets:", include_brackets_var),
        ("Include Latin-1 Supplement:", include_latin1_var)
    ]

    for i, (label, var) in enumerate(options, start=1):
        add_option(i, label, var)

    # Buttons
    def save_criteria():
        try:
            length = int(length_entry.get())
            if length <= 0:
                raise ValueError("Password length must be greater than 0")
            if not any(var.get() for _, var in options):
                raise ValueError("At least one character type must be selected")

            values = (
                length,
                include_uppercase_var.get(),
                include_lowercase_var.get(),
                include_digits_var.get(),
                include_minus_var.get(),
                include_underline_var.get(),
                include_space_var.get(),
                include_special_var.get(),
                include_brackets_var.get(),
                include_latin1_var.get()
            )

            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE password_criteria
                SET length=?, include_uppercase=?, include_lowercase=?, include_digits=?,
                    include_minus=?, include_underline=?, include_space=?, include_special=?,
                    include_brackets=?, include_latin1=?
                WHERE id = (SELECT id FROM password_criteria LIMIT 1)
            """, values)
            conn.commit()
            messagebox.showinfo("Success", "Password criteria saved successfully!")

        except ValueError as ve:
            messagebox.showerror("Validation Error", str(ve))
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            if 'conn' in locals():
                conn.close()
            parent_window.lift()
            password_config_window.lift()
            password_config_window.focus()

    def reset_to_default_criteria():
        if not messagebox.askyesno("Reset Criteria", "Reset to default criteria?"):
            return

        defaults = {
            "length": 12,
            "include_uppercase": True,
            "include_lowercase": True,
            "include_digits": True,
            "include_minus": True,
            "include_underline": True,
            "include_space": False,
            "include_special": True,
            "include_brackets": True,
            "include_latin1": False
        }

        length_entry.delete(0, tk.END)
        length_entry.insert(0, str(defaults["length"]))
        include_uppercase_var.set(defaults["include_uppercase"])
        include_lowercase_var.set(defaults["include_lowercase"])
        include_digits_var.set(defaults["include_digits"])
        include_minus_var.set(defaults["include_minus"])
        include_underline_var.set(defaults["include_underline"])
        include_space_var.set(defaults["include_space"])
        include_special_var.set(defaults["include_special"])
        include_brackets_var.set(defaults["include_brackets"])
        include_latin1_var.set(defaults["include_latin1"])

        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE password_criteria
                SET length=?, include_uppercase=?, include_lowercase=?, include_digits=?,
                    include_minus=?, include_underline=?, include_space=?, include_special=?,
                    include_brackets=?, include_latin1=?
                WHERE id = (SELECT id FROM password_criteria LIMIT 1)
            """, tuple(defaults.values()))
            conn.commit()
            messagebox.showinfo("Reset", "Password criteria reset to default.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            if 'conn' in locals():
                conn.close()

        parent_window.lift()
        password_config_window.lift()
        password_config_window.focus()

    # Button row
    button_frame = tk.Frame(main_frame, bg="#f0f0f0")
    button_frame.grid(row=11, column=0, columnspan=2, pady=20, sticky="ew")
    button_frame.grid_columnconfigure(0, weight=1)
    button_frame.grid_columnconfigure(1, weight=1)
    button_frame.grid_columnconfigure(2, weight=1)

    tk.Button(button_frame, text="OK", bg="#4CAF50", fg="white", command=save_criteria).grid(row=0, column=0, padx=5, sticky="ew")
    tk.Button(button_frame, text="Cancel", bg="#f44336", fg="white", command=password_config_window.destroy).grid(row=0, column=1, padx=5, sticky="ew")
    tk.Button(button_frame, text="Reset Defaults", bg="#2196F3", fg="white", command=reset_to_default_criteria).grid(row=0, column=2, padx=5, sticky="ew")


# Function to generate random password
def generate_password(length=12, characters=None):
    if characters is None:  # Default character set if none is provided
        characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def generate_now(ui_context):
    """Generate a strong password based on stored criteria and update UI."""
    entry_password = ui_context["entry_password"]
    parent_window = ui_context["parent_window"]

    # Check if password field has content
    current_password = entry_password.get()
    if current_password:
        # Ask for confirmation
        confirm = messagebox.askyesno(
            "Confirm Overwrite",
            "This will overwrite your existing password. Are you sure?",
            parent=parent_window  # Use parent window from context
        )
        if not confirm:
            return  # User canceled

    # Load password criteria from the database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM password_criteria ORDER BY id DESC LIMIT 1")
    criteria = cursor.fetchone()
    conn.close()

    if not criteria:
        messagebox.showwarning("Criteria Error", "No password generation criteria found.", parent=parent_window)
        return

    length, include_uppercase, include_lowercase, include_digits, include_minus, \
    include_underline, include_space, include_special, include_brackets, include_latin1 = criteria[1:]

    # Build character set
    characters = ""
    if include_uppercase:  characters += string.ascii_uppercase
    if include_lowercase:  characters += string.ascii_lowercase
    if include_digits:     characters += string.digits
    if include_minus:      characters += "-"
    if include_underline:  characters += "_"
    if include_space:      characters += " "
    if include_special:    characters += "!\"#$%&'*+,-./:;=?@\\^_`|~"
    if include_brackets:   characters += "[]{}()<>"
    if include_latin1:     characters += ''.join(chr(i) for i in range(160, 256))

    if not characters:
        messagebox.showwarning("Selection Error", "Please select at least one character type.", parent=parent_window)
        return

    max_attempts = 1000  # Limit attempts to avoid infinite loop
    for _ in range(max_attempts):
        new_password = generate_password(length, characters)
        if check_password_strength(new_password) == "Strong":
            break
    else:
        messagebox.showerror(
            "Generation Failed",
            "Unable to generate a strong password with the selected criteria.\n\n"
            "To fix this, please update your password criteria with the following tips:\n"
            "- Use at least 12 characters\n"
            "- Include uppercase and lowercase letters\n"
            "- Add digits (0-9)\n"
            "- Include special characters (e.g. !@#$%^&*)\n",
            parent=parent_window
        )
        return

    # Insert password and update strength UI
    entry_password.delete(0, tk.END)
    entry_password.insert(0, new_password)

    update_password_strength(ui_context)

# Function to check password strength
def check_password_strength(password):
    # Check for minimum length first
    if len(password) < 8:
        return "Weak"
    
    # Check for Strong criteria: letters, numbers, special chars, and length >=12
    elif (re.search(r"[A-Za-z]", password) and
          re.search(r"[0-9]", password) and
          re.search(r"[!@#$%^&*(),.?\":{}|<>~\-]", password) and  # Added hyphen (~-) and others
          len(password) >= 12):
        return "Strong"
    
    # Check for Medium criteria: letters, numbers, and length >=8
    elif (re.search(r"[A-Za-z]", password) and
          re.search(r"[0-9]", password)):
        return "Medium"
    
    # Otherwise, Weak
    else:
        return "Weak"

def perform_breach_check(password, parent_frame):
    # Close existing breach window if open
    if hasattr(parent_frame, 'breach_window') and parent_frame.breach_window.winfo_exists():
        parent_frame.breach_window.destroy()
    
    result = check_pwned_password(password)
    message = result[0]
    
    # Get the main application window
    main_window = parent_frame.winfo_toplevel().winfo_toplevel()
    
    # Create floating window with better styling
    breach_window = tk.Toplevel(main_window)
    breach_window.overrideredirect(True)
    breach_window.configure(bg="#f8f8f8", padx=0, pady=0)  # Remove padding
    
    # Create shadow effect using multiple frames
    shadow_frame = tk.Frame(breach_window, bg="#e0e0e0", bd=0)
    shadow_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
    
    # Position at upper right of MAIN WINDOW
    x = main_window.winfo_x() + main_window.winfo_width() - 330  # Account for window width
    y = main_window.winfo_y() + 80
    breach_window.geometry(f"320x80+{x}+{y}")  # Set initial size
    
    # Create content frame with rounded corners effect
    content_frame = tk.Frame(shadow_frame, bg="#ffffff", bd=0, highlightthickness=1, highlightbackground="#e0e0e0")
    content_frame.pack(fill=tk.BOTH, expand=True)
    
    # Create header bar with color based on result
    header_color = "#e74c3c" if "⚠️" in message else "#2ecc71"  # Red for warning, green for safe
    header_frame = tk.Frame(content_frame, bg=header_color, height=3)
    header_frame.pack(fill=tk.X, pady=(0, 8))
    
    # Create Close X button on header
    close_x_button = tk.Button(
        header_frame,
        text="×",
        font=("Arial", 8, "bold"),
        fg="#ffffff",
        bg=header_color,
        relief="flat",
        bd=0,
        command=breach_window.destroy
    )
    close_x_button.pack(side=tk.RIGHT, padx=2, pady=2)
    
    # Message label with better typography
    msg_frame = tk.Frame(content_frame, bg="#ffffff")
    msg_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
    
    # Add icon based on result
    icon = "⚠️" if "⚠️" in message else "✓"
    icon_color = "#c0392b" if "⚠️" in message else "#27ae60"
    
    icon_label = tk.Label(
        msg_frame,
        text=icon,
        font=("Arial", 12, "bold"),
        bg="#ffffff",
        fg=icon_color
    )
    icon_label.pack(side=tk.LEFT, padx=(0, 5))
    
    # Message text
    msg_label = tk.Label(
        msg_frame,
        text=message,
        bg="#ffffff",
        fg="#333333",
        font=("Arial", 9),
        wraplength=250,
        justify=tk.LEFT,
        anchor="w"
    )
    msg_label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Calculate proper height after content is rendered
    breach_window.update_idletasks()
    req_height = msg_label.winfo_reqheight() + 50  # Account for all elements
    breach_window.geometry(f"320x{req_height}+{x}+{y}")
    
    # Store reference in parent frame
    parent_frame.breach_window = breach_window
    
    # Auto-close after 10 seconds
    breach_window.after(10000, breach_window.destroy)

def check_pwned_password(password: str):
    if not password:
        return "⚠️ No password entered.", None, True

    hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = hashed_password[:5]
    api_url = f'https://api.pwnedpasswords.com/range/{prefix}'

    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            hashes = response.text.split('\r\n')
            for line in hashes:
                hash_suffix, count = line.split(':')
                if hash_suffix == hashed_password[5:]:
                    return f"⚠️ This password has been seen {count} times in breaches. You should change it.", int(count), False
            return "✅ Good news — this password has not been found in any known data breaches.", None, False
        else:
            return f"⚠️ API Error: Status code {response.status_code}", None, True
    except requests.exceptions.RequestException as e:
        return f"⚠️ Network error: {str(e)}", None, True
    except Exception as e:
        return f"⚠️ Unexpected error: {str(e)}", None, True

# Compute charset size
def get_charset_size(password):
    cs = 0
    if any(c.islower() for c in password): cs += 26
    if any(c.isupper() for c in password): cs += 26
    if any(c.isdigit() for c in password): cs += 10
    if any(not c.isalnum() for c in password): cs += 32
    return max(cs, 1)

def open_guess_rate_window(parent_window, guess_sec_entry): 
    if hasattr(open_guess_rate_window, "guess_rate_win") and \
       open_guess_rate_window.guess_rate_win.winfo_exists():
        open_guess_rate_window.guess_rate_win.lift()
        open_guess_rate_window.guess_rate_win.focus()
        return

    guess_rate_win = tk.Toplevel(parent_window)
    guess_rate_win.title("Guess Rate Configuration")
    guess_rate_win.configure(bg="#f0f0f0")
    guess_rate_win.grab_set()

    # Center the window
    window_width = 510
    window_height = 450
    screen_width = guess_rate_win.winfo_screenwidth()
    screen_height = guess_rate_win.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    guess_rate_win.geometry(f"{window_width}x{window_height}+{x}+{y}")

    # Main frame
    main_frame = tk.Frame(guess_rate_win, bg="#f0f0f0")
    main_frame.pack(pady=10, fill=tk.BOTH, expand=True)
    
    # Grid configuration for expansion 
    main_frame.grid_columnconfigure(1, weight=1)

    # Load current settings
    with sqlite3.connect(DB_FILE) as conn:
        settings = conn.execute("""
            SELECT guess_per_sec, thread_count, guess_per_sec_threshold,
                   default_guess_per_sec, default_thread_count, default_guess_per_sec_threshold
            FROM attack_settings LIMIT 1
        """).fetchone()

    if settings:
        current_guess_per_sec, current_thread_count, current_threshold, \
        default_guess_per_sec, default_thread_count, default_threshold = settings
    else:
        current_guess_per_sec = default_guess_per_sec = 3000000
        current_thread_count = default_thread_count = 1
        current_threshold = default_threshold = 10000000

    tk.Label(main_frame, text="Thread Count:", bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    thread_entry = tk.Entry(main_frame)
    thread_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
    thread_entry.insert(0, str(current_thread_count))

    tk.Label(main_frame, text="Guess Threshold:", bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    threshold_entry = tk.Entry(main_frame)
    threshold_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
    threshold_entry.insert(0, str(current_threshold))

    cli_output = scrolledtext.ScrolledText(main_frame, state='disabled', height=15)
    cli_output.grid(row=2, column=0, columnspan=3, padx=5, pady=10, sticky="nsew")

    button_frame = tk.Frame(main_frame, bg="#f0f0f0")
    button_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
    button_frame.grid_columnconfigure(0, weight=1)
    button_frame.grid_columnconfigure(1, weight=1)
    button_frame.grid_columnconfigure(2, weight=1)

    test_stop_flag = threading.Event()
    test_start_flag = threading.Event()
    message_queue = queue.Queue()

    def on_guess_rate_win_close():
        if test_start_flag.is_set() and not test_stop_flag.is_set():
            confirm = messagebox.askyesno(
                "Confirm Close",
                "⚠️ A guess rate test is currently in progress.\n"
                "Closing the window will stop the test.\n\n"
                "Are you sure you want to proceed?"
            )
            if not confirm:
                return
            test_stop_flag.set()
        guess_rate_win.destroy()
        parent_window.lift()
        parent_window.focus_force()
        
    guess_rate_win.protocol("WM_DELETE_WINDOW", on_guess_rate_win_close)

    def reset_to_defaults():
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset to default Guess Rate Configuration?"):
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("""
                    UPDATE attack_settings 
                    SET guess_per_sec = default_guess_per_sec,
                        thread_count = default_thread_count,
                        guess_per_sec_threshold = default_guess_per_sec_threshold
                """)
                conn.commit()

            # Update the labels (on main thread)
            guess_rate_win.after(0, lambda: [ 
                guess_sec_entry.delete(0, tk.END),
                guess_sec_entry.insert(0, str(default_guess_per_sec))
            ])

            messagebox.showinfo("Reset Successful", "Guess Rate Configuration has been reset to defaults.")
            guess_rate_win.lift()
            guess_rate_win.focus_force()

    def start_guess_rate_test():
        try:
            thread_count = int(thread_entry.get())
            threshold = int(threshold_entry.get())
            if thread_count < 1 or threshold < 1:
                raise ValueError
        except ValueError:
            guess_rate_win.lift()
            guess_rate_win.focus_force()
            messagebox.showerror("Error", "Invalid thread count or threshold")
            parent_window.lift()
            guess_rate_win.lift()
            guess_rate_win.focus_force()
            return

        start_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)
        reset_btn.config(state=tk.DISABLED)
        test_start_flag.set()
        test_stop_flag.clear()

        def run_guess_rate_test():
            alphabet = string.ascii_letters + string.digits + string.punctuation
            random_password = ''.join(random.choices(alphabet, k=12))
            
            # Format the start message with timestamp
            start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message_queue.put(f"🚀 Starting guess rate test with random password generated: '{random_password}'")
            message_queue.put(f"⏰ Start time: {start_time}")
            message_queue.put(f"🔧 Using {thread_count} threads and threshold: {threshold:,}")

            chunk_size = len(alphabet) // thread_count
            chunks = [alphabet[i * chunk_size:(i + 1) * chunk_size] for i in range(thread_count - 1)]
            chunks.append(alphabet[(thread_count - 1) * chunk_size:])

            def brute_force(limit, chunk, pwd, stop_flag):
                for guesses, g in enumerate(itertools.product(chunk, repeat=len(pwd)), 1):
                    if stop_flag and stop_flag.is_set():
                        return
                    if ''.join(g) == pwd:
                        message_queue.put(f"🔓 Password cracked: '{''.join(g)}'")
                        break
                    if guesses >= limit:
                        break

            start = time.time()
            threads = [
                threading.Thread(
                    target=brute_force,
                    args=(threshold // thread_count, chunk, random_password, test_stop_flag)
                ) for chunk in chunks
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            if test_stop_flag.is_set():
                message_queue.put("🛑 Guess rate test stopped by user.")
                message_queue.put("")
            else:
                taken = time.time() - start
                guess_per_sec = round(threshold / taken)
                end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Format the completion message
                message_queue.put(f"⏰ End time: {end_time}")
                message_queue.put(f"⏱️ Time taken: {taken:.2f} seconds")
                message_queue.put(f"📈 New Guess/sec: {guess_per_sec:,}")
                message_queue.put("🏁 Guess rate test completed")
                message_queue.put("")

                with sqlite3.connect(DB_FILE) as conn:
                    conn.execute("""
                        UPDATE attack_settings 
                        SET guess_per_sec = ?, 
                            thread_count = ?, 
                            guess_per_sec_threshold = ?
                    """, (guess_per_sec, thread_count, threshold))
                    conn.commit()

                # Update the labels (on main thread)
                guess_rate_win.after(0, lambda: [
                    guess_sec_entry.delete(0, tk.END),
                    guess_sec_entry.insert(0, str(guess_per_sec))
                ])

            test_start_flag.clear()

            guess_rate_win.after(0, lambda: [
                start_btn.config(state=tk.NORMAL),
                stop_btn.config(state=tk.DISABLED),
                reset_btn.config(state=tk.NORMAL)
            ])

        threading.Thread(target=run_guess_rate_test, daemon=True).start()

    start_btn = tk.Button(button_frame, text="Start", bg="#4CAF50", fg="white", command=start_guess_rate_test)
    start_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

    stop_btn = tk.Button(button_frame, text="Stop", bg="#f44336", fg="white",
                         state=tk.DISABLED, command=lambda: test_stop_flag.set())
    stop_btn.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    reset_btn = tk.Button(button_frame, text="Reset Defaults", bg="#2196F3", fg="white",
                         command=reset_to_defaults)
    reset_btn.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

    def update_cli():
        while not message_queue.empty():
            msg = message_queue.get_nowait()
            cli_output.config(state=tk.NORMAL)
            cli_output.insert(tk.END, msg + "\n")
            cli_output.see(tk.END)
            cli_output.config(state=tk.DISABLED)
        guess_rate_win.after(100, update_cli)

    guess_rate_win.after(100, update_cli)
    main_frame.grid_rowconfigure(3, weight=1)

# Count dictionary line with caching
def count_lines(path: str) -> int:
    """
    Count lines in a file or in all files under a directory.
    Cache result in a side-file "<path>.lines" for instant reuse.
    """
    cache_file = path + ".lines"
    if os.path.exists(cache_file):
        try:
            return int(open(cache_file, "r").read())
        except ValueError:
            pass  # fall through to recount if cache is corrupted

    total = 0
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in files:
                full = os.path.join(root, fn)
                if os.path.isfile(full):
                    with open(full, "rb") as f:
                        total += f.read().count(b"\n")
    else:
        # try using wc for speed, fallback to pure-Python
        try:
            out = subprocess.check_output(["wc", "-l", path])
            total = int(out.split()[0])
        except Exception:
            with open(path, "rb") as f:
                total = f.read().count(b"\n")

    with open(cache_file, "w") as cf:
        cf.write(str(total))
    return total

# Estimate dictionary attack time
def estimate_dict_time(dict_size: int, guesses_per_sec) -> str:
    """Return human-readable estimate for brute forcing every entry in dict."""
    return format_time(dict_size / guesses_per_sec)

def password_in_dict(password: str, path: str) -> bool:
    """
    Check if `password` exists in the dictionary file or any file under
    `path`. Returns True on first match.
    """
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in files:
                full = os.path.join(root, fn)
                with open(full, "r", errors="ignore") as f:
                    if any(line.strip() == password for line in f):
                        return True
    else:
        with open(path, "r", errors="ignore") as f:
            if any(line.strip() == password for line in f):
                return True
    return False

def estimate_crack_time(password, aes_bits, method, dictionary_path, rainbow_path, guesses_per_sec):
    """
    Returns a dict with time estimates or status for each attack type:
      - Password Brute-Force
      - AES Brute-Force
      - Dictionary Attack
      - Rainbow Table
    """
    # Early exit on empty password
    if not password:
        return {m: "No password entered" for m in
                ["Password Brute-Force", "AES Brute-Force",
                 "Dictionary Attack", "Rainbow Table"]}

    # Check for invalid guesses_per_sec
    if guesses_per_sec <= 0:
        return {method: "Invalid guess rate: must be greater than 0"}
    
    # Character set size & entropy
    cs = get_charset_size(password)
    possible_combinations = cs ** len(password)
    total_entropy = len(password) * math.log2(cs)

    results = {}

    # — Password Brute-Force —
    if method == "Password Brute-Force":
        bf_seconds = possible_combinations / guesses_per_sec
        results["Password Brute-Force"] = format_time(bf_seconds)
    else:
        results["Password Brute-Force"] = "Password brute-force disabled"

    # — AES Brute-Force —
    if method == "AES Brute-Force":
        aes_seconds = (2 ** aes_bits) / guesses_per_sec
        results["AES Brute-Force"] = format_time(aes_seconds)
    else:
        results["AES Brute-Force"] = "AES brute-force disabled"

    # — Dictionary Attack —
    if method == "Dictionary Attack":
        dict_result = "Path not found"
        if os.path.exists(dictionary_path):
            size = count_lines(dictionary_path)
            dict_time = estimate_dict_time(size, guesses_per_sec)
            found = password_in_dict(password, dictionary_path)
            if found:
                dict_result = f"{dict_time} (found)"
            else:
                dict_result = "Not found in wordlist"
        results["Dictionary Attack"] = dict_result
    else:
        results["Dictionary Attack"] = "Dictionary attack disabled"

    # — Rainbow Table — 
    if method == "Rainbow Table":
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT base_time FROM rainbow_crack_time WHERE length = ?", (len(password),))
            result = cursor.fetchone()
            conn.close()

            if result:
                base_time = result[0]

                # Get thread count from attack_settings
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT thread_count FROM attack_settings LIMIT 1")
                thread_row = cursor.fetchone()
                conn.close()

                threads = thread_row[0] if thread_row else 1
                threads = max(1, threads)  # Avoid divide by zero

                adjusted_time = base_time / threads
                crack_time = format_time(adjusted_time)

                results["Rainbow Table"] = crack_time
            else:
                results["Rainbow Table"] = "No estimate for this password length"
        except Exception as e:
            results["Rainbow Table"] = f"Database error: {str(e)}"
    else:
        results["Rainbow Table"] = "Rainbow attack disabled"

    return results

def on_hover(event, button, hover_color, normal_color):
    button.config(bg=hover_color if event.type == tk.EventType.Enter else normal_color)

def on_hover_browse(event, button):
    """Change browse button color on hover."""
    button.config(bg="#1976D2" if event.type == tk.EventType.Enter else "#2196F3")
    
def toggle_password_visibility(entry_password, entry_confirm_password, eye_icon, show_password_img, hide_password_img):
    """Toggle password visibility between shown and hidden."""
    if entry_password.cget('show') == '*':
        entry_password.config(show='')
        entry_confirm_password.config(show='')
        eye_icon.config(image=show_password_img)
    else:
        entry_password.config(show='*')
        entry_confirm_password.config(show='*')
        eye_icon.config(image=hide_password_img)

def browse_dictionary_path(entry_widget, window):
    """Open file dialog to select dictionary path and save it to the database."""
    path = filedialog.askdirectory(title="Select Dictionary Folder")
    if path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)
        window.lift()

        # Save to database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''SELECT dictionary_path FROM attack_settings LIMIT 1''')
        existing_path = cursor.fetchone()

        if existing_path:
            # Update the dictionary path in the database if it exists
            cursor.execute('''UPDATE attack_settings SET dictionary_path = ? WHERE dictionary_path = ?''', (path, existing_path[0]))
        else:
            # Insert the new dictionary path if no existing record
            cursor.execute('''INSERT INTO attack_settings (dictionary_path) VALUES (?)''', (path,))

        conn.commit()
        conn.close()

def browse_rainbow_path(entry_widget, window):
    """Open file dialog to select rainbow table path and save it to the database."""
    path = filedialog.askdirectory(title="Select Rainbow Table Folder")
    if path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)
        window.lift()

        # Save to database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''SELECT rainbow_table_path FROM attack_settings LIMIT 1''')
        existing_path = cursor.fetchone()

        if existing_path:
            # Update the rainbow table path in the database if it exists
            cursor.execute('''UPDATE attack_settings SET rainbow_table_path = ? WHERE rainbow_table_path = ?''', (path, existing_path[0]))
        else:
            # Insert the new rainbow table path if no existing record
            cursor.execute('''INSERT INTO attack_settings (rainbow_table_path) VALUES (?)''', (path,))

        conn.commit()
        conn.close()
        
def refresh_form(parent_window, dict_path_entry, rainbow_path_entry, ui_context):
        """Reloads the dictionary and rainbow table paths."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT dictionary_path, rainbow_table_path FROM attack_settings LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        # Refresh the path values
        dict_path_entry.delete(0, tk.END)
        rainbow_path_entry.delete(0, tk.END)
        dict_path_entry.insert(0, row[0] if row else "")
        rainbow_path_entry.insert(0, row[1] if row else "")
        update_password_strength(ui_context)
        parent_window.lift()
        parent_window.focus()

def update_password_strength(context):
    """Update password strength indicator and crack time estimates using UI context."""

    entry_password = context["entry_password"]
    password_strength_label = context["password_strength_label"]
    selected_aes_bit = context["selected_aes_bit"]
    form_frame = context["form_frame"]

    password = entry_password.get()
    strength = check_password_strength(password)

    # Map each strength to a color
    color_map = {
        "Weak":   "red",
        "Medium": "orange",
        "Strong": "green"
    }
    strength_color = color_map.get(strength, "black")

    # Update label text and color
    password_strength_label.config(
        text=f"Strength: {strength}",
        fg=strength_color
    )

def open_attack_window(parent_window, current_password, aes_bit):
    if hasattr(open_attack_window, "attack_win") and \
    open_attack_window.attack_win.winfo_exists():
        open_attack_window.attack_win.lift()
        open_attack_window.attack_win.focus()
        return

    # Get paths from database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT dictionary_path, rainbow_table_path, guess_per_sec, thread_count, guess_per_sec_threshold FROM attack_settings LIMIT 1')
    db_paths = cursor.fetchone()
    dict_path = db_paths[0] if db_paths else ""
    rainbow_path = db_paths[1] if db_paths else ""
    guess_per_sec = db_paths[2] if db_paths else 3000000  # Default value if not in DB
    thread_count = db_paths[3] if db_paths else 1
    guess_per_sec_threshold = db_paths[4] if db_paths else 10000000

    attack_win = tk.Toplevel(parent_window)
    attack_win.title("Password Strength Tester")
    attack_win.configure(bg="#f0f0f0")
    attack_win.grab_set()
    attack_win.minsize(500, 600)  # Increased minimum size for better layout

    # Create a global stop flag for attack
    attack_stop_flag = threading.Event()
    
    # Main container frame
    main_frame = tk.Frame(attack_win, bg="#f0f0f0")
    main_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)

    # =============================================
    # 1. Attack Control Section
    # =============================================
    control_frame = ttk.LabelFrame(main_frame, text="Attack Configuration", padding=10)
    control_frame.pack(fill=tk.X, pady=(0, 10), padx=5)
	
    # Configure grid columns for consistent layout
    control_frame.columnconfigure(0, weight=0)
    control_frame.columnconfigure(1, weight=1)
    control_frame.columnconfigure(2, weight=0)

    # Load icons
    show_password_icon = tk.PhotoImage(file="Images/show_password_b.png").subsample(3, 3)
    hide_password_icon = tk.PhotoImage(file="Images/hide_password_b.png").subsample(3, 3)
    settings_icon = tk.PhotoImage(file="Images/settings_b.png").subsample(3, 3)
    browse_icon = tk.PhotoImage(file="Images/browse_b.png").subsample(3, 3)

    # Target Password
    row = 0
    tk.Label(control_frame, text="Target Password:", bg="#f0f0f0").grid(row=row, column=0, padx=5, pady=5, sticky="w")
    target_password_entry = tk.Entry(control_frame, show="*")
    target_password_entry.insert(0, current_password)
    target_password_entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")

    # Toggle visibility
    def toggle_attack_password_visibility():
        if target_password_entry.cget('show') == '*':
            target_password_entry.config(show='')
            attack_eye_icon.config(image=show_password_icon)
        else:
            target_password_entry.config(show='*')
            attack_eye_icon.config(image=hide_password_icon)

    attack_eye_icon = tk.Label(control_frame, image=hide_password_icon, cursor="hand2", bg="#f0f0f0")
    attack_eye_icon.grid(row=row, column=2, padx=5, pady=5, sticky="w")
    attack_eye_icon.bind("<Button-1>", lambda e: toggle_attack_password_visibility())
    attack_eye_icon.bind("<Enter>", lambda e: show_tooltip(e.widget, "Toggle password visibility"))
    attack_eye_icon.bind("<Leave>", lambda e: hide_tooltip())

    # Guess Rate
    row += 1
    tk.Label(control_frame, text="Guess Rate (per sec):", bg="#f0f0f0").grid(row=row, column=0, padx=5, pady=5, sticky="w")
    guess_sec_entry = tk.Entry(control_frame)
    guess_sec_entry.insert(0, str(guess_per_sec))
    guess_sec_entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")

    # Configure Guess Rate Button
    config_guess_rate_button = tk.Label(control_frame, image=settings_icon, cursor="hand2", bg="#f0f0f0")
    config_guess_rate_button.grid(row=row, column=2, padx=5, pady=5, sticky="w")
    config_guess_rate_button.bind("<Button-1>", lambda e: open_guess_rate_window(attack_win, guess_sec_entry))

    # To ensure the image doesn't get garbage collected
    config_guess_rate_button.image = settings_icon
    config_guess_rate_button.bind(
        "<Enter>", 
        lambda e: show_tooltip(config_guess_rate_button, "Configure guess rate settings")
    )
    config_guess_rate_button.bind(
        "<Leave>", 
        lambda e:  hide_tooltip()
    )
    
    # Attack Method
    row += 1
    tk.Label(control_frame, text="Attack Method:", bg="#f0f0f0").grid(row=row, column=0, padx=5, pady=5, sticky="w")
    method_combobox = ttk.Combobox(control_frame, values=["Password Brute-Force", "AES Brute-Force", "Dictionary Attack", "Rainbow Table"])
    method_combobox.set("Password Brute-Force")
    method_combobox.grid(row=row, column=1, padx=5, pady=5, sticky="ew", columnspan=2)

    # =============================================
    # Dynamic Attack Parameters Section
    # =============================================
    # Create all dynamic widgets but don't show them yet
    # AES Bit Size
    aes_bit_label = tk.Label(control_frame, text="AES Bit Size:", bg="#f0f0f0")
    aes_bit_combobox = ttk.Combobox(control_frame, values=["128", "192", "256"], state="readonly")
    aes_bit_combobox.set(str(aes_bit))

    # Dictionary Path
    dict_label = tk.Label(control_frame, text="Dictionary Path:", bg="#f0f0f0")
    dict_entry = tk.Entry(control_frame)
    dict_entry.insert(0, dict_path)
    dict_upload_btn = tk.Label(control_frame, image=browse_icon, cursor="hand2", bg="#f0f0f0")
    dict_upload_btn.image = browse_icon
    dict_upload_btn.bind("<Button-1>", lambda e: browse_dictionary_path(dict_entry, attack_win))

    # Rainbow Table Path
    rainbow_label = tk.Label(control_frame, text="Rainbow Table Path:", bg="#f0f0f0")
    rainbow_entry = tk.Entry(control_frame)
    rainbow_entry.insert(0, rainbow_path)
    rainbow_upload_btn = tk.Label(control_frame, image=browse_icon, cursor="hand2", bg="#f0f0f0")
    rainbow_upload_btn.image = browse_icon
    rainbow_upload_btn.bind("<Button-1>", lambda e: browse_rainbow_path(rainbow_entry, attack_win))

    # Threads
    threads_label = tk.Label(control_frame, text="Threads:", bg="#f0f0f0")
    threads_entry = tk.Entry(control_frame)
    threads_entry.insert(0, str(thread_count))

    # =============================================
    # 2. Estimated Time to Crack Section (Enhanced)
    # =============================================
    time_frame = ttk.LabelFrame(main_frame, text="Estimated Crack Time", padding=10)
    time_frame.pack(fill=tk.X, pady=10, padx=5)
    
    # Time display area with enhanced styling
    crack_display = tk.Frame(time_frame, bg="#ffffff", bd=1, relief=tk.SUNKEN)
    crack_display.pack(fill=tk.X, pady=5, padx=5)
    
    crack_time_label = tk.Label(
        crack_display, 
        text="Select attack parameters to estimate", 
        font=("Arial", 11),
        bg="#ffffff",
        anchor="w",
        justify=tk.LEFT
    )
    crack_time_label.pack(fill=tk.X, padx=10, pady=10)

    # Function to update crack time display
    def update_crack_time_display():
        password = target_password_entry.get()
        method = method_combobox.get()
        
        try:
            aes_bits = int(aes_bit_combobox.get()) if method == "AES Brute-Force" else 128
        except:
            aes_bits = 128
            
        dict_path = dict_entry.get() if method == "Dictionary Attack" else ""
        rainbow_path = rainbow_entry.get() if method == "Rainbow Table" else ""
        
        try:
            guesses_per_sec = int(guess_sec_entry.get())
        except:
            guesses_per_sec = 3431501  # Default value if entry is invalid
            
        crack_times = estimate_crack_time(password, aes_bits, method, dict_path, rainbow_path, guesses_per_sec)
        
        # Display only the relevant method's time estimate
        if method == "Password Brute-Force":
            display_text = f"Password Brute-Force: {crack_times['Password Brute-Force']}"
        elif method == "AES Brute-Force":
            display_text = f"AES-{aes_bits} Brute-Force: {crack_times['AES Brute-Force']}"
        elif method == "Dictionary Attack":
            display_text = f"Dictionary Attack: {crack_times['Dictionary Attack']}"
        elif method == "Rainbow Table":
            display_text = f"Rainbow Table: {crack_times['Rainbow Table']}"
        else:
            display_text = "Select an attack method"
            
        # Update the label with colored text
        crack_time_label.config(text=display_text)
        
        # Set color based on time estimate
        if "disabled" in display_text.lower() or "not found" in display_text.lower() or "no password" in display_text.lower():
            crack_time_label.config(fg="red")
        elif "found" in display_text.lower():
            crack_time_label.config(fg="red")
        elif "yrs" in display_text.lower():
            crack_time_label.config(fg="green")
        elif "days" in display_text.lower():
            crack_time_label.config(fg="orange")
        else:
            crack_time_label.config(fg="red")

    # =============================================
    # 3. Attack Output Section
    # =============================================
    output_frame = ttk.LabelFrame(main_frame, text="Attack Output", padding=10)
    output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=5)

    # CLI Output
    cli_output = scrolledtext.ScrolledText(output_frame, state='disabled', height=10)
    cli_output.pack(fill=tk.BOTH, expand=True, pady=5)

    # Action Buttons
    button_frame = tk.Frame(output_frame, bg="#f0f0f0")
    button_frame.pack(fill=tk.X, pady=(5, 0))
    
    # Button style configuration
    start_btn = tk.Button(
        button_frame,
        text="Start Attack",
        bg="#4CAF50",
        fg="white",
        font=("Arial", 10, "bold"),
        padx=10,
        command=lambda: start_attack(
            method_combobox.get(),
            threads_entry.get(),
            target_password_entry.get(),
            aes_bit_combobox.get(),
            dict_entry.get() if method_combobox.get() == "Dictionary Attack" else "",
            rainbow_entry.get() if method_combobox.get() == "Rainbow Table" else "",
            cli_output,
            start_btn,
            stop_btn,
            attack_stop_flag
        )
    )
    start_btn.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)

    stop_btn = tk.Button(
        button_frame,
        text="Stop Attack",
        bg="#f44336",
        fg="white",
        font=("Arial", 10, "bold"),
        padx=10,
        state=tk.DISABLED,
        command=lambda: stop_attack(attack_stop_flag)
    )
    stop_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

    # =============================================
    # Dynamic Section Visibility Management
    # =============================================
    def update_path_visibility():
        # Clear dynamic frame
        aes_bit_label.grid_forget()
        aes_bit_combobox.grid_forget()
        dict_label.grid_forget()
        dict_entry.grid_forget()
        dict_upload_btn.grid_forget()
        rainbow_label.grid_forget()
        rainbow_entry.grid_forget()
        rainbow_upload_btn.grid_forget()
        threads_label.grid_forget()
        threads_entry.grid_forget()
    
        row = 3
        method = method_combobox.get()
        
        if method == "AES Brute-Force":
            aes_bit_label.grid(row=row, column=0, padx=5, pady=5, sticky="w")
            aes_bit_combobox.grid(row=row, column=1, padx=5, pady=5, sticky="ew", columnspan=2)
            row += 1
            
        elif method == "Dictionary Attack":
            dict_label.grid(row=row, column=0, padx=5, pady=5, sticky="w")
            dict_entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")
            dict_upload_btn.grid(row=row, column=2, padx=5, pady=5, sticky="w")
            row += 1
            
        elif method == "Rainbow Table":
            rainbow_label.grid(row=row, column=0, padx=5, pady=5, sticky="w")
            rainbow_entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")
            rainbow_upload_btn.grid(row=row, column=2, padx=5, pady=5, sticky="w")
            row += 1
        
        # Threads (common for all methods)
        threads_label.grid(row=row, column=0, padx=5, pady=5, sticky="w")
        threads_entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew", columnspan=2)
        
        # Update time estimation
        update_crack_time_display()

    # Bind all relevant widgets to update the crack time display
    target_password_entry.bind("<KeyRelease>", lambda e: update_crack_time_display())
    method_combobox.bind("<<ComboboxSelected>>", lambda e: update_path_visibility())
    aes_bit_combobox.bind("<<ComboboxSelected>>", lambda e: update_crack_time_display())
    dict_entry.bind("<KeyRelease>", lambda e: update_crack_time_display())
    rainbow_entry.bind("<KeyRelease>", lambda e: update_crack_time_display())
    threads_entry.bind("<KeyRelease>", lambda e: update_crack_time_display())
    guess_sec_entry.bind("<KeyRelease>", lambda e: update_crack_time_display())

    # Initialize UI
    update_path_visibility()
    
    # Center window
    attack_win.update_idletasks()
    width = attack_win.winfo_width()
    height = attack_win.winfo_height()
    x = (attack_win.winfo_screenwidth() - width) // 2
    y = (attack_win.winfo_screenheight() - height) // 2
    attack_win.geometry(f"+{x}+{y}")

    # Shared flag to control attack threads
    attack_stop_flag = threading.Event()
    attack_started_flag = threading.Event()

    def on_attack_win_close():
        if attack_started_flag.is_set() and not attack_stop_flag.is_set():
            confirm = messagebox.askyesno(
                "Confirm Close",
                "⚠️ An attack is currently running.\nAre you sure you want to stop the attack and close the window?"
            )
            if not confirm:
                return
            stop_attack(attack_stop_flag)
        attack_win.destroy()
        parent_window.lift()
        parent_window.focus_force()

    attack_win.protocol("WM_DELETE_WINDOW", on_attack_win_close)

    def stop_attack(stop_flag):
        stop_flag.set()
        attack_started_flag.clear() 
        cli_output.config(state=tk.NORMAL)
        cli_output.insert(tk.END, "🛑 Attack stopped by user\n")
        cli_output.see(tk.END)
        cli_output.config(state=tk.DISABLED)

    def start_attack(method, threads_str, password, aes_bit, dict_path, rainbow_path, cli, start_button, stop_button, stop_flag):
        # First check if password is empty
        if not password or len(password.strip()) == 0:
            messagebox.showerror("Error", "Target password cannot be empty")
            attack_win.lift()
            attack_win.focus()
            return
        try:
            threads = int(threads_str)
            if threads < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid number of threads")
            attack_win.lift()
            attack_win.focus()
            return

        # Reset stop flag and enable/disable buttons
        stop_flag.clear()
        attack_started_flag.set()
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

        attack_thread = threading.Thread(
            target=simulate_attack,
            args=(method, threads, password, dict_path, rainbow_path, message_queue, start_button, stop_button, stop_flag),
            daemon=True
        )
        attack_thread.start()

    def simulate_attack(method, threads, password, dict_path, rainbow_path, queue, start_button, stop_button, stop_flag): 
        def post(message):
            queue.put(message)

        # 💬 Show these first
        post(f"🚀 Starting {method} attack on: '{password}'")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        post(f"⏰ Start time: {current_time}")
        post(f"🔧 Using {threads} threads")

        def brute_force_worker(start_chars, charset, target, found_event, attempt_counter, stop_flag, length_status_callback):
            max_len = len(target) + 1
            for length in range(1, max_len + 1):
                length_status_callback(length)
                for first in start_chars:
                    for combo in itertools.product(charset, repeat=length - 1):
                        if found_event.is_set() or stop_flag.is_set():
                            return
                        attempt = first + ''.join(combo)
                        attempt_counter[0] += 1
                        if attempt == target:
                            found_event.set()
                            post(f"✅ Password found: {attempt}")
                            return
                        
        start_time = time.time()
        attempt_counter = [0]

        if method == "Password Brute-Force":
            charset = string.ascii_letters + string.digits + string.punctuation
            post("🔢 Starting password brute-force with increasing lengths...")
            post(f"📚 Charset size: {len(charset)}")

            found_event = threading.Event()
            workers = []
            current_length = [0]
            length_lock = threading.Lock()

            def length_status_callback(length):
                with length_lock:
                    if current_length[0] != length:
                        current_length[0] = length
                        post(f"📏 Trying password length: {length}")

            for i in range(threads):
                start_chars = charset[i::threads]
                t = threading.Thread(
                    target=brute_force_worker,
                    args=(start_chars, charset, password, found_event, attempt_counter, stop_flag, length_status_callback),
                    daemon=True
                )
                workers.append(t)
                t.start()

            for t in workers:
                t.join()

            if not found_event.is_set() and not stop_flag.is_set():
                post("❌ Password not found (unexpected)")

        elif method == "AES Brute-Force":
            try:
                aes_bits = int(aes_bit)
                key_length = aes_bits // 8
            except:
                post("❌ Invalid AES bit size")
                return

            charset = string.printable.strip()
            charset_size = len(charset)
            post(f"🔑 Starting AES-{aes_bits} brute-force with key length {key_length} bytes...")
            post(f"📚 Charset size: {charset_size}")
            post("⚠️ WARNING: This operation is computationally infeasible with current computer technology!")

            plaintext = "secret"
            target_key = password.encode().ljust(key_length, b'\0')[:key_length]
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(target_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            tag = encryptor.tag
            target_ciphertext = base64.b64encode(iv + tag + ciphertext).decode()
            post(f"🎯 Target ciphertext: {target_ciphertext}")

            found_event = threading.Event()
            workers = []
            attempt_counter = [0]  # reuse outer stop_flag — do NOT redefine

            def aes_brute_worker(start_chars, charset, key_length, found_event, attempt_counter, stop_flag):
                for first_char in start_chars:
                    for tail in itertools.product(charset, repeat=key_length - 1):
                        if found_event.is_set() or stop_flag.is_set():
                            return
                        candidate_str = first_char + ''.join(tail)
                        candidate_key = candidate_str.encode().ljust(key_length, b'\0')[:key_length]
                        try:
                            cipher = Cipher(algorithms.AES(candidate_key), modes.GCM(iv), backend=default_backend())
                            encryptor = cipher.encryptor()
                            ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
                            tag = encryptor.tag
                            test_ciphertext = base64.b64encode(iv + tag + ct).decode()
                            attempt_counter[0] += 1

                            if attempt_counter[0] % 100000 == 0:
                                post(f"🔄 Attempt {attempt_counter[0]}: Trying key '{candidate_str}' → {candidate_key.hex()}")

                            if test_ciphertext == target_ciphertext:
                                found_event.set()
                                post(f"✅ Key found: '{candidate_str}'  (hex: {candidate_key.hex()})")
                                return
                        except Exception:
                            continue

            for i in range(threads):
                start_chars = charset[i::threads]
                t = threading.Thread(
                    target=aes_brute_worker,
                    args=(start_chars, charset, key_length, found_event, attempt_counter, stop_flag),
                    daemon=True
                )
                workers.append(t)
                t.start()

            for t in workers:
                t.join()

            if not found_event.is_set() and not stop_flag.is_set():
                post("❌ AES key not found in search space")

        elif method == "Dictionary Attack":
            post(f"📖 Dictionary path: {dict_path}")
            if not os.path.exists(dict_path):
                post("❌ Dictionary path not found")
                return

            # Get all dictionary files
            dict_files = []
            if os.path.isdir(dict_path):
                for root, _, files in os.walk(dict_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.path.isfile(file_path):
                            dict_files.append(file_path)
                post(f"🔍 Found {len(dict_files)} dictionary files in directory")
            else:
                dict_files = [dict_path]

            # Shared resources
            found_event = threading.Event()
            tried_set = set()
            found_info = {"file": "", "line": 0}
            dict_size = [0]
            lock = threading.Lock()

            def dictionary_worker(file_chunk):
                nonlocal found_info, dict_size
                for file_path in file_chunk:
                    if found_event.is_set() or stop_flag.is_set():
                        return

                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            display_path = os.path.relpath(file_path, dict_path) if os.path.isdir(dict_path) else os.path.basename(file_path)
                            with lock:
                                post(f"📄 Scanning dictionary file: {display_path}")

                            for line_num, line in enumerate(f, 1):
                                if found_event.is_set() or stop_flag.is_set():
                                    return

                                word = line.strip()
                                if not word:
                                    continue

                                with lock:
                                    dict_size[0] += 1
                                    tried_set.add(word)

                                if word == password:
                                    with lock:
                                        found_info["file"] = os.path.relpath(file_path, dict_path) if os.path.isdir(dict_path) else os.path.basename(file_path)
                                        found_info["line"] = line_num
                                        found_event.set()
                                    return
                    except Exception as e:
                        with lock:
                            post(f"⚠️ Error reading {os.path.basename(file_path)}: {str(e)}")

            # Split files into chunks for threads
            chunk_size = max(1, len(dict_files) // threads)
            file_chunks = [dict_files[i:i+chunk_size] for i in range(0, len(dict_files), chunk_size)]

            workers = []
            for chunk in file_chunks:
                t = threading.Thread(target=dictionary_worker, args=(chunk,), daemon=True)
                workers.append(t)
                t.start()

            # Wait for threads to complete or password found
            for t in workers:
                t.join()
            
            attempt_counter[0] += dict_size[0]
            
            if found_event.is_set():
                post(f"✅ Password found in dictionary: {found_info['file']} (Line {found_info['line']})")
            else:
                if not stop_flag.is_set():
                    post(f"❌ Password not found in any dictionary file (searched {dict_size[0]} words)")
                    post("⚡ Proceeding with brute-force excluding tried words...")

                    # Brute-force but skip tried_set
                    charset = string.ascii_letters + string.digits + string.punctuation
                    found_event = threading.Event()

                    def filtered_brute_force_worker(start_chars, charset, target, found_event, attempt_counter, stop_flag):
                        max_len = len(target) + 1
                        for length in range(1, max_len + 1):
                            for first in start_chars:
                                for combo in itertools.product(charset, repeat=length - 1):
                                    if found_event.is_set() or stop_flag.is_set():
                                        return
                                    attempt = first + ''.join(combo)
                                    if attempt in tried_set:
                                        continue  # Skip already tried words
                                    attempt_counter[0] += 1
                                    if attempt == target:
                                        found_event.set()
                                        post(f"✅ Password found by brute-force: {attempt}")
                                        return

                    workers = []
                    for i in range(threads):
                        start_chars = charset[i::threads]
                        t = threading.Thread(
                            target=filtered_brute_force_worker,
                            args=(start_chars, charset, password, found_event, attempt_counter, stop_flag),
                            daemon=True
                        )
                        workers.append(t)
                        t.start()

                    for t in workers:
                        t.join()

                    if not found_event.is_set() and not stop_flag.is_set():
                        post("❌ Password not found even after brute-force")

        else: # Rainbow Table
            try:
                # Generate MD5 hash of the password
                post("🔨 Generating MD5 hash...")
                md5_hash = hashlib.md5(password.encode()).hexdigest()
                post(f"🔑 MD5 hash: {md5_hash}")

                # Validate paths
                if not os.path.exists(rainbow_path):
                    post("❌ Rainbow table path not found")
                    return

                # Prepare rcracki_mt command
                command = f"rcracki_mt -h {md5_hash} -t {threads} {rainbow_path}"
                post(f"🖥️ Executing: {command}")
                
                # Execute command in the Crack_Rainbow_Table directory
                crack_dir = "Crack_Rainbow_Table"
                if not os.path.exists(crack_dir):
                    post(f"❌ Directory not found: {crack_dir}")
                    return

                # With this cross-platform solution:
                if os.name == 'nt':  # Windows
                    process = subprocess.Popen(
                        command,
                        cwd=crack_dir,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                    )
                else:  # Unix-based systems
                    process = subprocess.Popen(
                        command,
                        cwd=crack_dir,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        preexec_fn=os.setsid
                    )

                # Read output in real-time
                while True:
                    if stop_flag.is_set():
                        post("🛑 Stopping rainbow table attack...")
                        if os.name == 'nt':
                            os.kill(process.pid, signal.CTRL_BREAK_EVENT)
                        else:
                            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        break

                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        post(output.strip())

                    time.sleep(0.1)  # Prevent UI freeze

                # Check final result
                return_code = process.poll()
                if not stop_flag.is_set():  # Only check if not stopped by user
                    if return_code == 0:
                        post("✅ Password found in rainbow table!")
                    else:
                        post("❌ Password not found in rainbow tables")
                else:
                    post("🔇 All Processes Terminated")

            except Exception as e:
                post(f"⚠️ Error during rainbow table attack: {str(e)}")

        elapsed_time = time.time() - start_time
        if not stop_flag.is_set():
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            post(f"⏰ End time: {current_time}")
            post(f"🔢 Total attempts: {attempt_counter[0]:,}")
            post(f"⏱️ Time taken: {elapsed_time:.2f} seconds")
            post("🏁 Attack completed")
        post("")
        
        attack_started_flag.clear()

        # Update buttons in the main thread
        attack_win.after(0, lambda: [
            start_button.config(state=tk.NORMAL),
            stop_button.config(state=tk.DISABLED)
        ])

    # CLI message queue updates
    message_queue = queue.Queue()

    def update_cli():
        while not message_queue.empty():
            msg = message_queue.get_nowait()
            cli_output.config(state=tk.NORMAL)
            cli_output.insert(tk.END, msg + "\n")
            cli_output.see(tk.END)
            cli_output.config(state=tk.DISABLED)
        attack_win.after(100, update_cli)

    attack_win.after(100, update_cli)

    main_frame.grid_rowconfigure(4, weight=1)

    # Store window reference
    open_attack_window.attack_win = attack_win
    attack_win.protocol("WM_DELETE_WINDOW", lambda: attack_win.destroy())

def validate_non_negative_integer(value):
    return value.isdigit() or value == ""

def is_valid_input(text, max_length=255):
    """Basic sanitization check for input fields."""
    return bool(text) and isinstance(text, str) and len(text.strip()) <= max_length
    
def open_add_password_form1():
    # Check if the window is already open
    if hasattr(open_add_password_form, "add_password_window") and open_add_password_form.add_password_window.winfo_exists():
        # If it exists, focus on the existing window
        open_add_password_form.add_password_window.lift()
        open_add_password_form.add_password_window.focus()
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT dictionary_path, rainbow_table_path, guess_per_sec, thread_count, guess_per_sec_threshold 
        FROM attack_settings 
        LIMIT 1
    ''')
    row = cursor.fetchone()

    if row:
        dictionary_path = row[0]
        rainbow_path = row[1]
        guess_per_sec = row[2]
        thread_count_val = row[3]
        threshold_val = row[4]
    else:
        dictionary_path = ""
        rainbow_path = ""
        guess_per_sec = 3000000
        thread_count_val = 1
        threshold_val = 10000000

    # Create a Toplevel window (pop-up)
    add_password_window = tk.Toplevel(root)
    add_password_window.title("Add New Entry")
    window_width = 550
    window_height = 900  # Increased height to accommodate new field

    # Center the window on the screen
    screen_width = add_password_window.winfo_screenwidth()
    screen_height = add_password_window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    add_password_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    # Set the theme to match the initial setup
    add_password_window.configure(bg="#f0f0f0")
    add_password_window.grab_set()

    # Define padding
    label_padx = 20
    entry_padx = 10
    pady = 10

    # Create a Frame for form fields (ensures alignment)
    form_frame = tk.Frame(add_password_window, bg="#f0f0f0")
    form_frame.pack(pady=20)

    # Function to create label with red star
    def create_required_label(text):
        label_frame = tk.Frame(form_frame, bg="#f0f0f0")
        tk.Label(label_frame, text=text, anchor="w", bg="#f0f0f0").pack(side="left")
        tk.Label(label_frame, text="*", fg="red", bg="#f0f0f0").pack(side="left")
        return label_frame

    # Platform Name
    platform_label_frame = create_required_label("Platform Name:")
    platform_label_frame.grid(row=0, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_platform_name = tk.Entry(form_frame, width=30)
    entry_platform_name.grid(row=0, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Label (Category)
    label_frame = create_required_label("Label:")
    label_frame.grid(row=1, column=0, padx=label_padx, pady=pady, sticky="w")
    label_options = ["Work", "Entertainment", "Education", "Social Media", "Shopping", "Utilities", "Other"]
    platform_label = ttk.Combobox(form_frame, values=label_options, width=27, state="readonly")
    platform_label.grid(row=1, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Username
    username_label_frame = create_required_label("Username:")
    username_label_frame.grid(row=2, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_username = tk.Entry(form_frame, width=30)
    entry_username.grid(row=2, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Password Field
    password_label_frame = create_required_label("Password:")
    password_label_frame.grid(row=3, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_password = tk.Entry(form_frame, show="*", width=30)
    entry_password.grid(row=3, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Confirm Password
    confirm_label_frame = create_required_label("Confirm Password:")
    confirm_label_frame.grid(row=4, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_confirm_password = tk.Entry(form_frame, show="*", width=30)
    entry_confirm_password.grid(row=4, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Create a container frame for password buttons
    password_buttons_container = tk.Frame(form_frame, bg="#f0f0f0")
    password_buttons_container.grid(row=3, column=2, sticky="w")

    # Load images for Show/Hide password
    show_password = tk.PhotoImage(file="Images/show_password_b.png").subsample(3, 3)
    hide_password = tk.PhotoImage(file="Images/hide_password_b.png").subsample(3, 3)

    # Show/Hide Password Button
    eye_icon = tk.Label(password_buttons_container, image=hide_password, cursor="hand2", bg="#f0f0f0")
    eye_icon.pack(side="left", padx=(0, 5))
    eye_icon.bind("<Button-1>", lambda e: toggle_password_visibility(entry_password, entry_confirm_password, eye_icon, show_password, hide_password))
    # Add tooltip
    eye_icon.bind("<Enter>", lambda e: show_tooltip(e.widget, "Toggle password visibility"))
    eye_icon.bind("<Leave>", lambda e: hide_tooltip())
    
    # Breach Check button
    breach_icon = tk.PhotoImage(file="Images/breach_check_b.png").subsample(3, 3)
    breach_button = tk.Button(
        password_buttons_container,
        image=breach_icon,
        bg="#f0f0f0",
        relief="flat",
        cursor="hand2",
        command=lambda: perform_breach_check(entry_password.get(), add_password_window)
    )
    breach_button.pack(side="left", padx=(0, 5))
    breach_button.image = breach_icon
    # Add tooltip
    breach_button.bind("<Enter>", lambda e: show_tooltip(e.widget, "Check if password has been breached"))
    breach_button.bind("<Leave>", lambda e: hide_tooltip())

    # AES Bit Selection
    aes_label_frame = create_required_label("AES Bit:")
    aes_label_frame.grid(row=5, column=0, padx=label_padx, pady=pady, sticky="w")
    aes_bit_options = ["128", "192", "256"]
    aes_bit_combobox = ttk.Combobox(form_frame, values=aes_bit_options, width=27, state="readonly")
    aes_bit_combobox.grid(row=5, column=1, padx=entry_padx, pady=pady, sticky="w")
    aes_bit_combobox.set(256)  # Default to 256-bit
    selected_aes_bit = tk.IntVar(value=256)

    # Password Strength Indicator
    password_strength_label = tk.Label(form_frame, text="Strength: Weak", fg="red", anchor="w")
    password_strength_label.grid(row=6, column=1, padx=entry_padx, pady=5, sticky="w")

    # URL
    tk.Label(form_frame, text="URL:", anchor="w", bg="#f0f0f0").grid(row=7, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_url = tk.Entry(form_frame, width=30)
    entry_url.grid(row=7, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Notes
    tk.Label(form_frame, text="Notes:", anchor="nw", bg="#f0f0f0").grid(row=8, column=0, padx=label_padx, pady=pady, sticky="nw")
    entry_notes = tk.Text(form_frame, height=4, width=30)
    entry_notes.grid(row=8, column=1, padx=entry_padx, pady=pady, sticky="w", columnspan=2)

    # Master Password Reprompt Label and Checkbox
    mp_reprompt_label_frame = create_required_label("Master Password Reprompt:")
    mp_reprompt_label_frame.grid(row=9, column=0, padx=label_padx, pady=pady, sticky="w")
    mp_reprompt_var = tk.BooleanVar(value=True)  # Default to checked
    mp_reprompt_check = tk.Checkbutton(form_frame, variable=mp_reprompt_var, bg="#f0f0f0")
    mp_reprompt_check.grid(row=9, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Attack Method ComboBox
    tk.Label(form_frame, text="Attack Method:", anchor="w").grid(row=10, column=0, padx=label_padx, pady=pady, sticky="w")
    attack_method_options = ["Password Brute-Force", "AES Brute-Force", "Dictionary Attack", "Rainbow Table"]
    attack_method_var = tk.StringVar(value="Password Brute-Force")
    attack_method_combobox = ttk.Combobox(form_frame, values=attack_method_options, width=27, textvariable=attack_method_var, state="readonly")
    attack_method_combobox.grid(row=10, column=1, padx=entry_padx, pady=pady, sticky="w")
    
    # Test Button
    test_button = tk.Button(
        form_frame, 
        text="Test", 
        bg="#2196F3", 
        fg="white", 
        padx=10, 
        pady=2,
        command=lambda: open_attack_window(add_password_window, attack_method_var.get(), entry_password.get(), aes_bit_combobox.get(), dict_path_entry.get(), rainbow_path_entry.get())
    )
    test_button.grid(row=10, column=2, padx=5, pady=pady, sticky="w")
    test_button.bind("<Enter>", lambda e: (on_hover_browse(e, test_button), show_tooltip(e.widget, "Test password strength against selected attack method")))
    test_button.bind("<Leave>", lambda e: (on_hover_browse(e, test_button), hide_tooltip()))

    # Container frames for dictionary and rainbow path buttons
    dict_buttons_container = tk.Frame(form_frame, bg="#f0f0f0")
    rainbow_buttons_container = tk.Frame(form_frame, bg="#f0f0f0")

    # Dictionary Path Fields
    dict_path_label = tk.Label(form_frame, text="Dictionary Path:", anchor="w", bg="#f0f0f0")
    dict_path_entry = tk.Entry(form_frame, width=30)
    dict_path_entry.insert(0, dictionary_path)

    # Dictionary Browse Button 
    dict_browse_button = tk.Button(
        dict_buttons_container, 
        text="Browse", 
        bg="#2196F3", 
        fg="white", 
        padx=3, 
        pady=2,
        command=lambda: browse_dictionary_path(dict_path_entry, add_password_window, ui_context)
    )
    dict_browse_button.pack(side="left", padx=(0, 5))
    dict_browse_button.bind(
        "<Enter>", 
        lambda e: (on_hover_browse(e, dict_browse_button), show_tooltip(e.widget, "Browse for dictionary file"))
    )
    dict_browse_button.bind(
        "<Leave>", 
        lambda e: (on_hover_browse(e, dict_browse_button), hide_tooltip())
    )

    # Rainbow Table Path Fields
    rainbow_path_label = tk.Label(form_frame, text="Rainbow Table Path:", anchor="w", bg="#f0f0f0")
    rainbow_path_entry = tk.Entry(form_frame, width=30)
    rainbow_path_entry.insert(0, rainbow_path)

    # Rainbow Table Browse Button
    rainbow_browse_button = tk.Button(
        rainbow_buttons_container, 
        text="Browse", 
        bg="#2196F3", 
        fg="white", 
        padx=3, 
        pady=2,
        command=lambda: browse_rainbow_path(rainbow_path_entry, add_password_window, ui_context)
    )
    rainbow_browse_button.pack(side="left", padx=(0, 5))
    rainbow_browse_button.bind(
        "<Enter>", 
        lambda e: (on_hover_browse(e, rainbow_browse_button), show_tooltip(e.widget, "Browse for rainbow table file"))
    )
    rainbow_browse_button.bind(
        "<Leave>", 
        lambda e: (on_hover_browse(e, rainbow_browse_button), hide_tooltip())
    )

    # Update the show_attack_fields function
    def show_attack_fields(*args):
        method = attack_method_var.get()
        for widget in form_frame.grid_slaves():
            if int(widget.grid_info().get("row", 0)) in (11, 12):
                widget.grid_forget()

        if method == "Dictionary Attack":
            dict_path_label.grid(row=11, column=0, padx=label_padx, pady=5, sticky="w")
            dict_path_entry.grid(row=11, column=1, padx=entry_padx, pady=5, sticky="w")
            dict_buttons_container.grid(row=11, column=2, columnspan=2, padx=5, pady=5, sticky="w")
        elif method == "Rainbow Table":
            rainbow_path_label.grid(row=12, column=0, padx=label_padx, pady=5, sticky="w")
            rainbow_path_entry.grid(row=12, column=1, padx=entry_padx, pady=5, sticky="w")
            rainbow_buttons_container.grid(row=12, column=2, columnspan=2, padx=5, pady=5, sticky="w")

    # Trigger field update on change
    attack_method_var.trace_add("write", show_attack_fields)

    # Register the validation function
    vcmd = (root.register(validate_non_negative_integer), "%P")

    # Guess per Second Entry
    tk.Label(form_frame, text="Guess/sec:", anchor="w").grid(row=13, column=0, padx=label_padx, pady=pady, sticky="w")
    guess_sec_entry = tk.Entry(form_frame, width=30, validate="key", validatecommand=vcmd)
    guess_sec_entry.insert(0, str(guess_per_sec))  # Pre-fill with existing value
    guess_sec_entry.grid(row=13, column=1, padx=entry_padx, pady=pady, sticky="w")

    ui_context = {
        "event": None,
        "parent_window": add_password_window,
        "entry_password": entry_password,
        "password_strength_label": password_strength_label,
        "selected_aes_bit": selected_aes_bit,
        "attack_method_var": attack_method_var,
        "dict_path_entry": dict_path_entry,
        "rainbow_path_entry": rainbow_path_entry,
        "guess_sec_entry": guess_sec_entry,
        "form_frame": form_frame,
        "mp_reprompt_var": mp_reprompt_var  # Added to context
    }
    
    guess_sec_entry.bind("<KeyRelease>", lambda event: update_password_strength(ui_context))

    # Configure Guess Rate Button 
    config_guess_rate_button = tk.Button(
        form_frame, 
        text="Configure", 
        bg="#2196F3", 
        fg="white", 
        command=lambda: open_guess_rate_window(add_password_window, guess_sec_entry)
    )
    config_guess_rate_button.grid(row=13, column=2, padx=5, pady=pady, sticky="w")

    # Bind both hover color and tooltip
    config_guess_rate_button.bind(
        "<Enter>", 
        lambda e: (on_hover_browse(e, config_guess_rate_button), show_tooltip(config_guess_rate_button, "Configure guess rate settings"))
    )
    config_guess_rate_button.bind(
        "<Leave>", 
        lambda e: (on_hover_browse(e, config_guess_rate_button), hide_tooltip())
    )

    # Initialize correct visibility
    show_attack_fields()

    def on_aes_bit_change(event, context):
        context["selected_aes_bit"].set(int(event.widget.get()))
        update_password_strength(context)

    aes_bit_combobox.bind("<<ComboboxSelected>>", partial(on_aes_bit_change, context=ui_context))
    attack_method_combobox.bind("<<ComboboxSelected>>", lambda event: update_password_strength(ui_context))
    entry_password.bind("<KeyRelease>", lambda event: update_password_strength(ui_context))
    
    # Dropdown menu for Generate button
    def show_generate_menu(event=None):
        # Use the widget position instead of mouse event
        x = generate_button.winfo_rootx()
        y = generate_button.winfo_rooty() + generate_button.winfo_height()
        generate_menu.post(x, y)
        
    # Generate Password Menu
    generate_menu = tk.Menu(root, tearoff=0)
    generate_menu.add_command(label="Generate Now", command=lambda: generate_now(ui_context))
    generate_menu.add_command(label="Setup Password Generation", command=lambda: open_password_generation_form(add_password_window))
    
    # Load Generate Password Icon
    generate_icon = tk.PhotoImage(file="Images/generate_password_b.png").subsample(3, 3)

    # Generate Password Button
    generate_button = tk.Button(
        password_buttons_container,
        image=generate_icon,
        bg="#f0f0f0",
        relief="flat",
        cursor="hand2",
        command=lambda: show_generate_menu()
    )
    generate_button.pack(side="left", padx=(0, 5))
    generate_button.image = generate_icon
    generate_button.bind("<Enter>", lambda e: show_tooltip(e.widget, "Generate a secure password"))
    generate_button.bind("<Leave>", lambda e: hide_tooltip())

    # OK & Cancel Buttons - Centered
    button_frame = tk.Frame(add_password_window, bg="#f0f0f0")
    button_frame.pack(pady=20)

    # Save paths and AES bits to database when the password is saved
    def save_attack_settings():
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("UPDATE attack_settings SET dictionary_path = ?, rainbow_table_path = ?",
                    (dict_path_entry.get(), rainbow_path_entry.get()))
        conn.commit()
        conn.close()

    # OK Button
    def add_password_action():
        platform_name = entry_platform_name.get()
        platform_label_value = platform_label.get()
        username = entry_username.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()
        aes_bits = selected_aes_bit.get()
        url = entry_url.get()
        notes = entry_notes.get("1.0", tk.END).strip()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mp_reprompt = mp_reprompt_var.get()  # Get the checkbox value
        save_attack_settings()

        # Check if passwords match
        if password != confirm_password:
            messagebox.showwarning("Password Mismatch", "The passwords do not match.")
            add_password_window.lift()
            add_password_window.focus()
            return

        if all([
            is_valid_input(platform_name),
            is_valid_input(platform_label_value),
            is_valid_input(username),
            is_valid_input(password)
        ]):
            try:
                encrypted_password = encrypt_things(password, key)
                
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO passwords (
                        platformName, platformLabel, platformUser, encryptedPassword,
                        platformURL, platformNote, createdAt, updatedAt, aes_bits, mp_reprompt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    platform_name.strip(), platform_label_value.strip(), username.strip(),
                    encrypted_password, url.strip(), notes.strip(), current_time, current_time,
                    aes_bits, mp_reprompt
                ))
                conn.commit()
                conn.close()
                
                messagebox.showinfo("Success", "Password added successfully!")
                add_password_window.destroy()
                load_passwords()
            
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
                add_password_window.lift()
                add_password_window.focus()
        else:
            messagebox.showwarning("Input Error", "Please fill in all required fields correctly.")
            add_password_window.lift()
            add_password_window.focus()
            
    ok_button = tk.Button(button_frame, text="OK", font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", padx=20, pady=5, relief="raised", command=add_password_action)
    ok_button.grid(row=0, column=0, padx=10, sticky="w")
    ok_button.bind("<Enter>", lambda event: on_hover(event, ok_button, "#388E3C", "#4CAF50"))
    ok_button.bind("<Leave>", lambda event: on_hover(event, ok_button, "#388E3C", "#4CAF50"))

    # Highlight OK button as default
    ok_button.config(default="active")  
    add_password_window.bind("<Return>", lambda event: add_password_action())  # Pressing Enter triggers OK
    
    # Cancel Button
    cancel_button = tk.Button(button_frame, text="Cancel", font=("Arial", 10, "bold"), bg="#f44336", fg="white", padx=20, pady=5, relief="raised", command=add_password_window.destroy)
    cancel_button.grid(row=0, column=1, padx=10, sticky="w")
    cancel_button.bind("<Enter>", lambda event: on_hover(event, cancel_button, "#d32f2f", "#f44336"))
    cancel_button.bind("<Leave>", lambda event: on_hover(event, cancel_button, "#d32f2f", "#f44336"))

    # Set focus to OK button
    ok_button.focus_set()

    update_password_strength(ui_context)

def edit_selected_entry():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "Please select an entry to edit.")
        return

    item = tree.item(selected_item[0])
    values = item["values"]

    # Create a Toplevel window (pop-up)
    edit_password_window = tk.Toplevel(root)
    edit_password_window.title("Edit Entry")
    window_width = 550
    window_height = 700

    # Center the window on the screen
    screen_width = edit_password_window.winfo_screenwidth()
    screen_height = edit_password_window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    edit_password_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    # Set the theme to match the initial setup
    edit_password_window.configure(bg="#f0f0f0")

    # Define padding
    label_padx = 20
    entry_padx = 10
    pady = 10

    # Create a Frame for form fields (ensures alignment)
    form_frame = tk.Frame(edit_password_window, bg="#f0f0f0")
    form_frame.pack(pady=20)

    # Platform Name
    tk.Label(form_frame, text="Platform Name:", anchor="w").grid(row=0, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_platform_name = tk.Entry(form_frame, width=30)
    entry_platform_name.insert(0, values[1])
    entry_platform_name.grid(row=0, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Label (Category)
    tk.Label(form_frame, text="Label:", anchor="w").grid(row=1, column=0, padx=label_padx, pady=pady, sticky="w")
    label_options = ["Banking", "Browser", "Cloud Services", "Development", "Education", "Email", "Entertainment", 
                    "Finance", "Forums", "Gaming", "Government", "Health", "News", "Personal", "Shopping", 
                    "Social Media", "Sports", "Streaming", "Travel", "Utilities", "Work", "Others"]
    platform_label = ttk.Combobox(form_frame, values=label_options, width=27)
    platform_label.set(values[2])
    platform_label.grid(row=1, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Username
    tk.Label(form_frame, text="Username:", anchor="w").grid(row=2, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_username = tk.Entry(form_frame, width=30)
    entry_username.insert(0, values[3])
    entry_username.grid(row=2, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Password Field
    tk.Label(form_frame, text="Password:", bg="#f0f0f0", anchor="w").grid(row=3, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_password = tk.Entry(form_frame, show="*", width=30)
    entry_password.insert(0, values[9])
    entry_password.grid(row=3, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Confirm Password
    tk.Label(form_frame, text="Confirm Password:", anchor="w").grid(row=4, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_confirm_password = tk.Entry(form_frame, show="*", width=30)
    entry_confirm_password.insert(0, values[9])
    entry_confirm_password.grid(row=4, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Show/Hide password icon
    def toggle_password_visibility():
        if entry_password.cget('show') == '*':
            entry_password.config(show='')
            entry_confirm_password.config(show='')
            eye_icon.config(image=show_password)
        else:
            entry_password.config(show='*')
            entry_confirm_password.config(show='*')
            eye_icon.config(image=hide_password)

    # Load images for Show/Hide password
    show_password = tk.PhotoImage(file="Images/show_password_b.png").subsample(3, 3)
    hide_password = tk.PhotoImage(file="Images/hide_password_b.png").subsample(3, 3)

    # Show/Hide Password Button
    eye_icon = tk.Label(form_frame, image=hide_password, cursor="hand2", bg="#f0f0f0")
    eye_icon.grid(row=3, column=2, padx=5, sticky="w")
    eye_icon.bind("<Button-1>", lambda e: toggle_password_visibility())

    # AES Bit Selection
    tk.Label(form_frame, text="AES Bit:", anchor="w").grid(row=5, column=0, padx=label_padx, pady=pady, sticky="w")
    aes_bit_options = ["128", "192", "256"]
    aes_bit_combobox = ttk.Combobox(form_frame, values=aes_bit_options, width=27)
    aes_bit_combobox.grid(row=5, column=1, padx=entry_padx, pady=pady, sticky="w")
    aes_bit_combobox.set(256)  # Default to 256-bit
    selected_aes_bit = tk.IntVar(value=256)

    # Password Strength Indicator
    password_strength_label = tk.Label(form_frame, text="Strength: Weak", fg="red", anchor="w")
    password_strength_label.grid(row=6, column=1, padx=entry_padx, pady=5, sticky="w")

    # Attack Method ComboBox
    tk.Label(form_frame, text="Attack Method:", anchor="w").grid(row=7, column=0, padx=label_padx, pady=pady, sticky="w")
    attack_method_options = ["Brute Force", "Dictionary Attack", "Rainbow Table"]
    attack_method_var = tk.StringVar(value="Brute Force")
    attack_method_combobox = ttk.Combobox(form_frame, values=attack_method_options, width=27, textvariable=attack_method_var)
    attack_method_combobox.grid(row=7, column=1, padx=entry_padx, pady=pady, sticky="w")

    def update_password_strength(event):
        password = entry_password.get()
        strength = check_password_strength(password)

        color_map = {
            "Weak": "red",
            "Medium": "orange",
            "Strong": "green"
        }
        strength_color = color_map.get(strength, "black")
        password_strength_label.config(text=f"Strength: {strength}", fg=strength_color)

        crack_times = estimate_crack_time(password, selected_aes_bit.get(), attack_method_var.get())
        
        if not hasattr(entry_password, 'crack_time_labels'):
            entry_password.crack_time_labels = {}
            crack_frame = tk.Frame(form_frame)
            crack_frame.grid(row=10, column=0, columnspan=4, pady=5, sticky="w")
            tk.Label(crack_frame, text="Estimated Time to Crack:", font=("Arial", 9, "bold")).pack(anchor="w")
            
            algorithms = ["AES Brute-Force", "Password Brute-Force", "Dictionary Attack", "Rainbow Table", "Breach Check"]
            for algo in algorithms:
                frame = tk.Frame(crack_frame)
                frame.pack(anchor="w")
                tk.Label(frame, text=f"{algo}:", width=16, anchor="w").pack(side=tk.LEFT)
                label = tk.Label(frame, text="", fg="red")
                label.pack(side=tk.LEFT)
                entry_password.crack_time_labels[algo] = label
        
        for algo, time in crack_times.items():
            label = entry_password.crack_time_labels[algo]
            label.config(text=time)
            if algo == "Breach Check":
                color = "red" if "⚠️" in time or time == "No password entered" else "green"
                label.config(fg=color)
            elif algo == "Dictionary Attack":
                color = "red" if time in ["Dictionary attack disabled", "No password entered", "Found in wordlist"] else "green"
                label.config(fg=color)
            else:
                color = "green" if "yrs" in time else "orange" if "days" in time else "red"
                label.config(fg=color)

    def on_aes_bit_change(event):
        selected_aes_bit.set(int(aes_bit_combobox.get()))
        update_password_strength(None)

    aes_bit_combobox.bind("<<ComboboxSelected>>", on_aes_bit_change)
    attack_method_combobox.bind("<<ComboboxSelected>>", update_password_strength)
    entry_password.bind("<KeyRelease>", update_password_strength)
    update_password_strength(None)  # <-- Auto-check strength on form load

    # URL
    tk.Label(form_frame, text="URL:", anchor="w").grid(row=8, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_url = tk.Entry(form_frame, width=30)
    entry_url.insert(0, values[5])
    entry_url.grid(row=8, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Notes
    tk.Label(form_frame, text="Notes:", anchor="nw").grid(row=9, column=0, padx=label_padx, pady=pady, sticky="nw")
    entry_notes = tk.Text(form_frame, height=4, width=30)
    entry_notes.insert("1.0", values[6])
    entry_notes.grid(row=9, column=1, padx=entry_padx, pady=pady, sticky="w", columnspan=2)

    # Generate Password Menu
    def show_generate_menu(event):
        generate_menu.post(event.x_root, event.y_root)
        
    def generate_now():
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM password_criteria ORDER BY id DESC LIMIT 1")
        criteria = cursor.fetchone()
        conn.close()

        if not criteria:
            messagebox.showwarning("Criteria Error", "No password generation criteria found.")
            return

        length, include_uppercase, include_lowercase, include_digits, include_minus, \
        include_underline, include_space, include_special, include_brackets, include_latin1 = criteria[1:]

        characters = ""
        if include_uppercase: characters += string.ascii_uppercase
        if include_lowercase: characters += string.ascii_lowercase
        if include_digits: characters += string.digits
        if include_minus: characters += "-"
        if include_underline: characters += "_"
        if include_space: characters += " "
        if include_special: characters += "!\"#$%&'*+,-./:;=?@\\^_`|~"
        if include_brackets: characters += "[]{}()<>"
        if include_latin1: characters += ''.join(chr(i) for i in range(160, 256))

        if not characters:
            messagebox.showwarning("Selection Error", "Please select at least one character type.")
            return

        while True:
            new_password = generate_password(length, characters)
            if check_password_strength(new_password) == "Strong":
                break

        entry_password.delete(0, tk.END)
        entry_password.insert(0, new_password)
        update_password_strength(None)

    def setup_password_generation():
        open_password_generation_form()

    # Generate Password Button
    generate_menu = tk.Menu(root, tearoff=0)
    generate_menu.add_command(label="Generate Now", command=generate_now)
    generate_menu.add_command(label="Setup Password Generation", command=setup_password_generation)
    
    generate_button = tk.Button(form_frame, text="Generate", font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", padx=5, pady=2, relief="raised")
    generate_button.grid(row=3, column=4, padx=5, sticky="w")
    generate_button.bind("<Button-1>", show_generate_menu)
    generate_button.bind("<Enter>", lambda event: on_hover(event, generate_button, "#45a049", "#4CAF50"))
    generate_button.bind("<Leave>", lambda event: on_hover(event, generate_button, "#45a049", "#4CAF50"))

    # OK & Cancel Buttons
    button_frame = tk.Frame(edit_password_window, bg="#f0f0f0")
    button_frame.pack(pady=20)

    def update_password_action():
        platform_name = entry_platform_name.get()
        platform_label_value = platform_label.get()
        username = entry_username.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()
        url = entry_url.get()
        notes = entry_notes.get("1.0", tk.END).strip()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if password != confirm_password:
            messagebox.showwarning("Password Mismatch", "The passwords do not match.")
            return
        
        if platform_name and platform_label_value and username and password:
            encrypted_password = encrypt_things(password, key)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE passwords SET platformName=?, platformLabel=?, platformUser=?, encryptedPassword=?, platformURL=?, platformNote=?, updatedAt=? WHERE id=?",
                        (platform_name, platform_label_value, username, encrypted_password, url, notes, current_time, values[0]))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Password updated successfully!")
            edit_password_window.destroy()
            load_passwords()
        else:
            messagebox.showwarning("Input Error", "Please fill in all fields.")
            
    ok_button = tk.Button(button_frame, text="OK", font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", padx=20, pady=5, relief="raised", command=update_password_action)
    ok_button.grid(row=0, column=0, padx=10, sticky="w")
    ok_button.bind("<Enter>", lambda event: on_hover(event, ok_button, "#388E3C", "#4CAF50"))
    ok_button.bind("<Leave>", lambda event: on_hover(event, ok_button, "#388E3C", "#4CAF50"))

    cancel_button = tk.Button(button_frame, text="Cancel", font=("Arial", 10, "bold"), bg="#f44336", fg="white", padx=20, pady=5, relief="raised", command=edit_password_window.destroy)
    cancel_button.grid(row=0, column=1, padx=10, sticky="w")
    cancel_button.bind("<Enter>", lambda event: on_hover(event, cancel_button, "#d32f2f", "#f44336"))
    cancel_button.bind("<Leave>", lambda event: on_hover(event, cancel_button, "#d32f2f", "#f44336"))

    ok_button.focus_set()
    edit_password_window.bind("<Return>", lambda event: update_password_action())

def delete_selected_entry():
    selected_item = tree.selection()
    if not selected_item:
        messagebox.showwarning("Selection Error", "Please select an entry to delete.")
        return

    item = tree.item(selected_item[0])
    values = item["values"]

    confirm = messagebox.askyesno("Delete Entry", f"Are you sure you want to delete the entry for {values[1]}?")
    if confirm:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE id=?", (values[0],))
        conn.commit()
        conn.close()
        load_passwords()  # Refresh the password list
        messagebox.showinfo("Success", "Password entry deleted successfully!")

def show_home_content1():
    global tree, add_button_ref, context_menu, timer_label

    # Function to display home content
    for widget in main_frame.winfo_children():
        if widget != timer_label:  # Do not destroy the timer label
            widget.destroy()
    
    # Destroy any placeholders or other widgets in the navigation bar
    for widget in nav_bar.winfo_children():
        if isinstance(widget, tk.Frame) and widget["bg"] == "#333333":
            widget.destroy()

    # Destroy the existing "Add" button if it exists
    if add_button_ref:
        add_button_ref.destroy()  # Destroy the old button
        add_button_ref = None     # Reset the global reference

    # Load and resize the icon for the "Add Password" button
    try:
        original_icon = Image.open("Images/add_w.png")  # Ensure this path is correct
        resized_icon = original_icon.resize((30, 30))
        add_icon = ImageTk.PhotoImage(resized_icon)
    except Exception as e:
        print(f"Error loading image: {e}")
        add_icon = None  # Fallback in case of error

    # Add the "Add" button at the far right
    if add_icon:
        add_button = tk.Button(
            nav_bar,
            image=add_icon,
            command=open_add_password_form,
            bg="#333333",
            borderwidth=0,
            highlightthickness=0,
            activebackground="#333333",
            cursor="hand2"
        )
        add_button.image = add_icon  # Keep a reference to prevent garbage collection
        add_button.pack(side=tk.RIGHT, padx=10)
        add_button_ref = add_button  # Store reference globally
    else:
        print("Failed to load add button icon.")

    # Create frames
    frame_tree = tk.Frame(main_frame, bg="#f0f0f0")
    frame_tree.pack(pady=10)

    # Create a treeview to display passwords
    tree = ttk.Treeview(frame_tree, columns=("ID", "Platform", "Label", "Username", "Password", "URL", "Notes", "Date Added", "Date Modified"), show="headings", height=10)
    tree.heading("ID", text="ID")
    tree.heading("Platform", text="Platform")
    tree.heading("Label", text="Label")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.heading("URL", text="URL")
    tree.heading("Notes", text="Notes")
    tree.heading("Date Added", text="Date Added")
    tree.heading("Date Modified", text="Date Modified")
    
    # Set column widths
    tree.column("ID", width=30)
    tree.column("Platform", width=200)
    tree.column("Label", width=120)
    tree.column("Username", width=200)
    tree.column("Password", width=200)
    tree.column("URL", width=200)
    tree.column("Notes", width=300)
    tree.column("Date Added", width=120)
    tree.column("Date Modified", width=120)

    tree.pack(side=tk.LEFT)

    # Create a scrollbar
    scrollbar = ttk.Scrollbar(frame_tree, orient="vertical", command=tree.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    tree.configure(yscrollcommand=scrollbar.set)

    tree.bind("<Button-3>", show_context_menu)  # Right-click for context menu

    # Create context menu
    context_menu = Menu(root, tearoff=0)
    context_menu.add_command(label="Copy Platform", command=lambda: copy_value(tree.item(tree.selection()[0], "values")[1]))
    context_menu.add_command(label="Copy Label", command=lambda: copy_value(tree.item(tree.selection()[0], "values")[2]))
    context_menu.add_command(label="Copy Username", command=lambda: copy_value(tree.item(tree.selection()[0], "values")[3]))
    context_menu.add_command(label="Copy Password", command=lambda: copy_value(tree.item(tree.selection()[0], "values")[9]))
    context_menu.add_command(label="Copy URL", command=lambda: copy_value(tree.item(tree.selection()[0], "values")[5]))
    context_menu.add_command(label="Copy Notes", command=lambda: copy_value(tree.item(tree.selection()[0], "values")[6]))
    context_menu.add_separator()
    context_menu.add_command(label="Edit Entry", command=edit_selected_entry)
    context_menu.add_command(label="Delete Entry", command=delete_selected_entry)

    # Load existing passwords into the table
    load_passwords()
    
def show_home_content():
    global add_button_ref, timer_label, selected_item_frame, selected_item_widget, items_container, details_placeholder
    selected_item_widget = None  # Track selected widget

    # Hide the main scrollbar for home content
    toggle_scrollbar(False)
    toggle_scrolling(False)

    # Clear existing widgets
    for widget in main_frame.winfo_children():
        if widget != timer_label:
            widget.destroy()

    for widget in nav_bar.winfo_children():
        if isinstance(widget, tk.Frame) and widget["bg"] == "#333333":
            widget.destroy()

    if add_button_ref:
        add_button_ref.destroy()
        add_button_ref = None

    try:
        original_icon = Image.open("Images/add_w.png")
        resized_icon = original_icon.resize((30, 30))
        add_icon = ImageTk.PhotoImage(resized_icon)
    except Exception as e:
        print(f"Error loading image: {e}")
        add_icon = None

    if add_icon:
        add_button = tk.Button(nav_bar, image=add_icon, command=open_add_password_form,
                             bg="#333333", borderwidth=0, highlightthickness=0,
                             activebackground="#333333", cursor="hand2")
        add_button.image = add_icon  # Keep reference to prevent garbage collection
        add_button.pack(side=tk.RIGHT, padx=10)
        add_button_ref = add_button

    main_container = tk.Frame(main_frame, bg="#f0f0f0")
    main_container.pack(fill=tk.BOTH, expand=True)  # Ensure container expands

    sidebar_frame = tk.Frame(main_container, width=200, bg="#2c3e50")
    sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

    content_frame = tk.Frame(main_container, bg="#f0f0f0")
    content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)  # Make content frame expandable

    # Items list
    items_list_frame = tk.Frame(content_frame, bg="#ffffff", bd=1, relief=tk.SOLID)
    items_list_frame.pack(side=tk.LEFT, fill=tk.BOTH)

    # Details frame with placeholder
    global details_frame
    details_frame = tk.Frame(content_frame, bg="#ffffff", bd=1, relief=tk.SOLID)
    details_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    selected_item_frame = tk.Frame(details_frame, bg="#ffffff")
    selected_item_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Add placeholder for details frame
    details_placeholder = tk.Label(selected_item_frame, text="No item selected. Select an item to view details.",
                                  bg="#ffffff", fg="#666666", font=("Arial", 10), wraplength=400)
    details_placeholder.pack(expand=True, fill=tk.BOTH, padx=40, pady=40)

    def on_sidebar_enter(e): 
        e.widget.config(bg="#34495e", cursor="hand2")
    def on_sidebar_leave(e): 
        e.widget.config(bg="#2c3e50")

    # Function to filter items
    def filter_items(filter_type=None, filter_value=None):
        global selected_item_widget
        selected_item_widget = None

        # Clear existing items and placeholder
        for widget in items_container.winfo_children():
            widget.destroy()
        
        # Fetch filtered items from database
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                query = "SELECT id, platformName, platformUser, updatedAt, platformLabel FROM passwords"
                params = []
                
                if filter_type == "favorites":
                    query += " WHERE isFavourite = 1"
                elif filter_type == "type":
                    query += " WHERE platformLabel = ?"
                    params.append(filter_value)
                elif filter_type == "trash":
                    query += " WHERE isDeleted= 1"
                
                query += " ORDER BY platformName"
                cursor.execute(query, params)
                passwords = cursor.fetchall()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            passwords = []
        
        # Display placeholder if no items
        if not passwords:
            placeholder = tk.Label(items_container, text="No items found. Click the '+' button to add a new item.",
                                  bg="#ffffff", fg="#666666", font=("Arial", 10), wraplength=200)
            placeholder.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            # Display filtered items
            for id, platform, username, modified, label in passwords:
                create_item_widget(id, platform, username, modified, label)

    def create_item_widget(id, platform, username, modified, label):
        item_frame = tk.Frame(items_container, bg="#ffffff", bd=1, relief=tk.RIDGE)
        item_frame.pack(fill=tk.X, pady=0, padx=0, anchor="w")

        content = tk.Frame(item_frame, bg="#ffffff")
        content.pack(fill=tk.BOTH, padx=10, pady=10)

        if label:
            try:
                label_color = get_label_color(label)
                tag = tk.Label(content, text=label, bg=label_color, fg="white",
                             font=("Arial", 8), padx=3, bd=1, relief=tk.RAISED)
                tag.pack(anchor="w")
            except Exception as e:
                print(f"Error creating label: {e}")

        platform_label = tk.Label(content, text=platform, bg="#ffffff",
                                font=("Arial", 10), anchor="w")
        platform_label.pack(fill=tk.X)

        user_mod_frame = tk.Frame(content, bg="#ffffff")
        user_mod_frame.pack(fill=tk.X, padx=0)

        user_label = tk.Label(user_mod_frame, text=username, bg="#ffffff", fg="#666666", 
                            font=("Arial", 9), anchor="w", justify="left")
        user_label.pack(fill=tk.X, anchor="w")

        mod_label = tk.Label(user_mod_frame, text=modified, bg="#ffffff", fg="#999999", 
                           font=("Arial", 8), anchor="w", justify="left")
        mod_label.pack(fill=tk.X, anchor="w")
       
       # Make entire item clickable
        for widget in [item_frame, content, platform_label, user_mod_frame, user_label, mod_label]:
            widget.bind("<Button-1>", lambda e, id=id, frame=item_frame: select_item(e, id, frame))
            if widget not in [item_frame, content]:  # Don't change cursor for container frames
                widget.config(cursor="hand2")
                
    def select_item(e, id, item_frame):
        global selected_item_widget, details_placeholder

        if not item_frame.winfo_exists():
            return

        if selected_item_widget and selected_item_widget.winfo_exists():
            selected_item_widget.config(bg="#ffffff")

        item_frame.config(bg="#e0f7fa")
        selected_item_widget = item_frame

        # Remove details placeholder
        details_placeholder.destroy()
        show_password_details(id)

    # Create sidebar filter buttons
    def create_filter_button(parent, text, command, is_header=False):
        if is_header:
            btn = tk.Label(parent, text=text, fg="white", bg="#2c3e50",
                          font=("Arial", 12, "bold"), anchor="w", padx=10, pady=5)
        else:
            btn = tk.Label(parent, text=text, fg="white", bg="#2c3e50",
                          font=("Arial", 10), anchor="w", padx=10, pady=5)
        
        btn.bind("<Button-1>", lambda e: command())
        btn.bind("<Enter>", on_sidebar_enter)
        btn.bind("<Leave>", on_sidebar_leave)
        btn.pack(fill=tk.X)
        return btn

    # All items filter (header)
    create_filter_button(sidebar_frame, "All items", 
                        lambda: filter_items(), is_header=True)
    
    # Favorites filter
    create_filter_button(sidebar_frame, "Favorites", 
                        lambda: filter_items("favorites"))
    
    # Trash filter
    create_filter_button(sidebar_frame, "Trash", 
                        lambda: filter_items("trash"))

    # Types filter header
    type_header = tk.Label(sidebar_frame, text="TYPES", fg="white", bg="#2c3e50",
                         font=("Arial", 10), anchor="w", padx=10)
    type_header.pack(fill=tk.X, pady=(15, 5))
    
    # Make type header clickable to show all items
    type_header.bind("<Button-1>", lambda e: filter_items())
    type_header.bind("<Enter>", on_sidebar_enter)
    type_header.bind("<Leave>", on_sidebar_leave)
    
    # Type filters
    for item_type in ["Work", "Education", "Entertainment", "Social Media", "Shopping", "Utilities", "Other"]:
        create_filter_button(sidebar_frame, item_type, 
                           lambda t=item_type: filter_items("type", t))

    tk.Frame(sidebar_frame, height=1, bg="#34495e").pack(fill=tk.X, pady=10)

    # Canvas and scrollbar setup for items list
    items_canvas = tk.Canvas(items_list_frame, bg="#ffffff", highlightthickness=0)
    scrollbar = ttk.Scrollbar(items_list_frame, orient="vertical", command=items_canvas.yview)
    
    scrollable_frame = tk.Frame(items_canvas, bg="#ffffff")
    scrollable_frame.bind(
        "<Configure>",
        lambda e: items_canvas.configure(
            scrollregion=items_canvas.bbox("all"),
            width=e.width  # Ensure canvas width matches frame
        )
    )
    
    # Use a container frame for better item organization
    items_container = tk.Frame(scrollable_frame, bg="#ffffff")
    items_container.pack(fill=tk.BOTH, expand=True)

    items_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    items_canvas.configure(yscrollcommand=scrollbar.set)

    scrollbar.pack(side="right", fill="y")
    items_canvas.pack(side="left", fill=tk.BOTH, expand=True)  # Make canvas expandable

    # Initial load with all items
    filter_items()

def show_password_details(password_id=None):
    global selected_item_frame, details_frame
    is_edit_mode = password_id is not None

    # First pack the details frame if it's not already visible
    if not details_frame.winfo_ismapped():
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Clear previous details
    for widget in selected_item_frame.winfo_children():
        widget.destroy()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Fetch the password details from the database
    if is_edit_mode:
        cursor.execute(''' 
            SELECT platformName, platformLabel, platformUser, encryptedPassword, 
                platformURL, platformNote, createdAt, updatedAt, aes_bits, 
                mp_reprompt, isFavourite, IsDeleted, deletedAt
            FROM passwords WHERE id = ? 
        ''', (password_id,))
        row = cursor.fetchone()

        if row:
            # Check if master password is required
            if row[9]:  # mp_reprompt is True
                if not require_master_password():  # If user cancels or enters wrong password
                    conn.close()
                    return  # Cancel the operation

            # Decrypt password
            try:
                decrypted_password = decrypt_things(row[3], key, row[8])
            except:
                decrypted_password = "Error decrypting"
        else:
            row = [None] * 13
            decrypted_password = ''
    else:
        row = [None] * 13
        decrypted_password = ''

    # Fetch attack settings from database
    cursor.execute('''
        SELECT dictionary_path, rainbow_table_path, guess_per_sec, thread_count, guess_per_sec_threshold 
        FROM attack_settings 
        LIMIT 1
    ''')
    attack_row = cursor.fetchone()

    if attack_row:
        dictionary_path = attack_row[0]
        rainbow_path = attack_row[1]
        guess_per_sec = attack_row[2]
        thread_count_val = attack_row[3]
        threshold_val = attack_row[4]
    else:
        dictionary_path = ""
        rainbow_path = ""
        guess_per_sec = 3000000
        thread_count_val = 1
        threshold_val = 10000000

    conn.close()

    # Style configurations
    normal_color = "#ffffff"
    highlight_color = "#e0f0ff"
    style = ttk.Style()
    style.configure("Normal.TLabel", foreground="#6E6C6C", background=normal_color)
    style.configure("Highlight.TLabel", foreground="#6E6C6C", background=highlight_color)

    # Canvas and scrollbar setup
    details_canvas = tk.Canvas(selected_item_frame, bg=normal_color, highlightthickness=0)
    scrollbar = ttk.Scrollbar(selected_item_frame, orient="vertical", command=details_canvas.yview)
    scrollable_details_frame = tk.Frame(details_canvas, bg=normal_color)
    
    scrollable_details_frame.bind(
        "<Configure>",
        lambda e: details_canvas.configure(
            scrollregion=details_canvas.bbox("all"),
            width=e.width
        )
    )
    
    details_canvas.create_window((0, 0), window=scrollable_details_frame, anchor="nw")
    details_canvas.configure(yscrollcommand=scrollbar.set)

    scrollbar.pack(side="right", fill="y")
    details_canvas.pack(side="left", fill="both", expand=True)

    # Title
    title_text = "EDIT ITEM" if is_edit_mode else "ADD NEW ITEM"
    ttk.Label(scrollable_details_frame, text=title_text, font=("Arial", 10, "bold"), 
            style="Normal.TLabel").pack(fill='x', padx=20, pady=(0, 20))

    # --- Platform Name Row ---
    name_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    name_row.pack(fill='x', padx=20, pady=(0, 0))
    label_frame = tk.Frame(name_row, bg=normal_color)
    label_frame.pack(anchor='w')
    ttk.Label(label_frame, text="Platform Name:", style="Normal.TLabel").pack(side='left')
    tk.Label(label_frame, text="*", fg="red", bg=normal_color).pack(side='left')
    name_entry = tk.Entry(name_row, fg="#000000", bg=normal_color, relief="flat")
    name_entry.insert(0, row[0] if row[0] else "")
    name_entry.pack(fill='x')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
    name_entry.bind("<FocusIn>", lambda e: highlight_row(name_row, [name_entry]))
    name_entry.bind("<FocusOut>", lambda e: reset_row(name_row, [name_entry]))

    # --- Label Type Row ---
    label_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    label_row.pack(fill='x', padx=20)
    label_lframe = tk.Frame(label_row, bg=normal_color)
    label_lframe.pack(anchor='w')
    ttk.Label(label_lframe, text="Label:", style="Normal.TLabel").pack(side='left')
    tk.Label(label_lframe, text="*", fg="red", bg=normal_color).pack(side='left')
    label_var = tk.StringVar(value=row[1] if row[1] else "Work")
    label_combobox = ttk.Combobox(label_row, textvariable=label_var, 
                                values=["Work", "Education", "Entertainment", "Social Media", "Shopping", "Utilities", "Other"],
                                width=27, state="readonly")
    label_combobox.pack(fill='x')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))

    # --- Username Row ---
    user_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    user_row.pack(fill='x', padx=20)
    user_lframe = tk.Frame(user_row, bg=normal_color)
    user_lframe.pack(anchor='w')
    ttk.Label(user_lframe, text="Username:", style="Normal.TLabel").pack(side='left')
    tk.Label(user_lframe, text="*", fg="red", bg=normal_color).pack(side='left')
    user_entry = tk.Entry(user_row, fg="#000000", bg=normal_color, relief="flat")
    user_entry.insert(0, row[2] if row[2] else "")
    user_entry.pack(fill='x')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
    user_entry.bind("<FocusIn>", lambda e: highlight_row(user_row, [user_entry]))
    user_entry.bind("<FocusOut>", lambda e: reset_row(user_row, [user_entry]))

    # --- Password Row ---
    pass_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    pass_row.pack(fill='x', padx=20)
    pass_lframe = tk.Frame(pass_row, bg=normal_color)
    pass_lframe.pack(anchor='w')
    ttk.Label(pass_lframe, text="Password:", style="Normal.TLabel").pack(side='left')
    tk.Label(pass_lframe, text="*", fg="red", bg=normal_color).pack(side='left')
    
    pass_frame = tk.Frame(pass_row, bg=normal_color)
    pass_frame.pack(fill='x')
    pass_entry = tk.Entry(pass_frame, width=30, show="•", relief="flat", bg=normal_color)
    pass_entry.insert(0, decrypted_password)
    pass_entry.pack(side='left', fill='x', expand=True)
    
    # Show/Hide button
    show_icon = tk.PhotoImage(file="Images/show_password_b.png").subsample(3, 3)
    hide_icon = tk.PhotoImage(file="Images/hide_password_b.png").subsample(3, 3)
    show_btn = tk.Button(pass_frame, image=hide_icon, bg=normal_color, bd=0)
    show_btn.pack(side='left', padx=5)
    show_btn.bind("<Button-1>", lambda e: toggle_password_visibility(pass_entry, confirm_pass_entry, show_btn, show_icon, hide_icon))
    show_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Toggle password visibility"))
    show_btn.bind("<Leave>", lambda e: hide_tooltip())
    
    # Breach check button
    breach_icon = tk.PhotoImage(file="Images/breach_check_b.png").subsample(3, 3)
    breach_btn = tk.Button(pass_frame, image=breach_icon, bg=normal_color, bd=0)
    breach_btn.pack(side='left', padx=5)
    breach_btn.bind("<Button-1>", lambda e: perform_breach_check(pass_entry.get(), scrollable_details_frame))
    breach_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Check if password has been breached"))
    breach_btn.bind("<Leave>", lambda e: hide_tooltip())
	
    # Generate password button
    generate_icon = tk.PhotoImage(file="Images/generate_password_b.png").subsample(3, 3)
    generate_btn = tk.Button(pass_frame, image=generate_icon, bg=normal_color, bd=0)
    generate_btn.pack(side='left', padx=5)
    generate_btn.bind("<Button-1>", lambda e: show_generate_menu())
    generate_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Generate a secure password"))
    generate_btn.bind("<Leave>", lambda e: hide_tooltip())
    
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
    pass_entry.bind("<FocusIn>", lambda e: highlight_row(pass_row, [pass_entry]))
    pass_entry.bind("<FocusOut>", lambda e: reset_row(pass_row, [pass_entry]))
	
    # Dropdown menu for Generate button
    def show_generate_menu(event=None):
        # Use the widget position instead of mouse event
        x = generate_btn.winfo_rootx()
        y = generate_btn.winfo_rooty() + generate_btn.winfo_height()
        generate_menu.post(x, y)
        
    # Generate Password Menu
    generate_menu = tk.Menu(root, tearoff=0)
    generate_menu.add_command(label="Generate Now", command=lambda: generate_now(ui_context))
    generate_menu.add_command(label="Setup Password Generation", command=lambda: open_password_generation_form(scrollable_details_frame))
    
    # --- Confirm Password Row ---
    confirm_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    confirm_row.pack(fill='x', padx=20)
    confirm_lframe = tk.Frame(confirm_row, bg=normal_color)
    confirm_lframe.pack(anchor='w')
    ttk.Label(confirm_lframe, text="Confirm Password:", style="Normal.TLabel").pack(side='left')
    tk.Label(confirm_lframe, text="*", fg="red", bg=normal_color).pack(side='left')
    confirm_pass_frame = tk.Frame(confirm_row, bg=normal_color)
    confirm_pass_frame.pack(fill='x')
    confirm_pass_entry = tk.Entry(confirm_pass_frame, width=30, show="•", relief="flat", bg=normal_color)
    confirm_pass_entry.insert(0, decrypted_password)
    confirm_pass_entry.pack(side='left', fill='x', expand=True)
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
    confirm_pass_entry.bind("<FocusIn>", lambda e: highlight_row(confirm_row, [confirm_pass_entry]))
    confirm_pass_entry.bind("<FocusOut>", lambda e: reset_row(confirm_row, [confirm_pass_entry]))

    # --- AES Bit Row ---
    aes_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    aes_row.pack(fill='x', padx=20)
    aes_lframe = tk.Frame(aes_row, bg=normal_color)
    aes_lframe.pack(anchor='w')
    ttk.Label(aes_lframe, text="AES Bit:", style="Normal.TLabel").pack(side='left')
    tk.Label(aes_lframe, text="*", fg="red", bg=normal_color).pack(side='left')

    # AES Bit Combobox and Pick for Me button
    aes_bit_var = tk.StringVar(value=str(row[8]) if row[8] else "256")
    aes_bit_combobox = ttk.Combobox(aes_row, textvariable=aes_bit_var, 
                                values=["128", "192", "256"], state="readonly")
    aes_bit_combobox.pack(side='left', fill='x', expand=True)

    # Add Pick for Me button
    pick_button = tk.Button(aes_row, text="Pick for Me", bg="#2196F3", fg="white", 
                            padx=2, pady=2, command=lambda: open_aes_evaluation_window(
                                scrollable_details_frame, 
                                pass_entry.get(),
                                aes_bit_var
                            ))
    pick_button.pack(side='left', padx=5)
    pick_button.bind("<Enter>", lambda e: (on_hover_browse(e, pick_button), 
                    show_tooltip(pick_button, "Recommend optimal AES bit length")))
    pick_button.bind("<Leave>", lambda e: (on_hover_browse(e, pick_button), hide_tooltip()))

    # Separator
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
	
    # --- Password Strength Indicator ---
    strength_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    strength_row.pack(fill='x', padx=20, pady=5)

    strength_label = tk.Label(strength_row, text="Strength: ", anchor="w", bg=normal_color)
    strength_label.pack(side='left', fill='x', expand=True)

    # --- Test Button ---
    test_btn = tk.Button(strength_row, text="Test", bg="#2196F3", fg="white", padx=2, pady=2,
                        command=lambda: open_attack_window(scrollable_details_frame, pass_entry.get(), aes_bit_var.get()))
    test_btn.pack(side='right', padx=5)
    test_btn.bind("<Enter>", lambda e: (on_hover_browse(e, test_btn), show_tooltip(e.widget, "Test password strength against various attack methods")))
    test_btn.bind("<Leave>", lambda e: (on_hover_browse(e, test_btn), hide_tooltip()))

    # --- URL Row ---
    url_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    url_row.pack(fill='x', padx=20)
    url_lframe = tk.Frame(url_row, bg=normal_color)
    url_lframe.pack(anchor='w')
    ttk.Label(url_lframe, text="URL:", style="Normal.TLabel").pack(side='left')
    url_entry = tk.Entry(url_row, fg="#000000", bg=normal_color, relief="flat")
    url_entry.insert(0, row[4] if row[4] else "")
    url_entry.pack(fill='x')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
    url_entry.bind("<FocusIn>", lambda e: highlight_row(url_row, [url_entry]))
    url_entry.bind("<FocusOut>", lambda e: reset_row(url_row, [url_entry]))

    # --- Notes Row ---
    notes_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    notes_row.pack(fill='x', padx=20)
    notes_lframe = tk.Frame(notes_row, bg=normal_color)
    notes_lframe.pack(anchor='w')
    ttk.Label(notes_lframe, text="Notes:", style="Normal.TLabel").pack(side='left')
    notes_text = tk.Text(notes_row, height=4, width=22, fg="#000000", bg=normal_color, relief="flat")
    notes_text.insert("1.0", row[5] if row[5] else "")
    notes_text.pack(fill='x')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
    notes_text.bind("<FocusIn>", lambda e: highlight_row(notes_row, [notes_text]))
    notes_text.bind("<FocusOut>", lambda e: reset_row(notes_row, [notes_text]))

    # --- Master Password Reprompt Row ---
    mp_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    mp_row.pack(fill='x', padx=20, pady=(0, 5))
    ttk.Label(mp_row, text="Master Password Reprompt:", style="Normal.TLabel").pack(side='left', padx=(0, 5))
    mp_reprompt_var = tk.BooleanVar(value=row[9] if row[9] is not None else False)
    mp_check = tk.Checkbutton(mp_row, variable=mp_reprompt_var, bg=normal_color)
    mp_check.pack(side='left')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
	
    # --- Favourite Row ---
    fav_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    fav_row.pack(fill='x', padx=20, pady=(0, 5))
    ttk.Label(fav_row, text="Favourite:", style="Normal.TLabel").pack(side='left', padx=(0, 5))
    is_favourite_var = tk.BooleanVar(value=row[10] if row[10] is not None else False)
    fav_check = tk.Checkbutton(fav_row, variable=is_favourite_var, bg=normal_color)
    fav_check.pack(side='left')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))

    def highlight_row(row_frame, widgets):
        """Highlight a row and its child widgets"""
        row_frame.config(bg=highlight_color)
        
        # Update standard tk widgets
        for widget in widgets:
            if not isinstance(widget, ttk.Widget):
                widget.config(bg=highlight_color)
        
        # Update ttk.Labels and child frames
        for child in row_frame.winfo_children():
            if isinstance(child, ttk.Label):
                child.configure(style="Highlight.TLabel")
            elif isinstance(child, tk.Frame):
                child.config(bg=highlight_color)
                for subchild in child.winfo_children():
                    if isinstance(subchild, ttk.Label):
                        subchild.configure(style="Highlight.TLabel")
                    elif not isinstance(subchild, ttk.Widget):
                        try:
                            subchild.config(bg=highlight_color)
                        except tk.TclError:
                            pass  # Ignore widgets that don't support bg

    def reset_row(row_frame, widgets):
        """Reset a row and its child widgets to normal colors"""
        row_frame.config(bg=normal_color)
        
        # Reset standard tk widgets
        for widget in widgets:
            if not isinstance(widget, ttk.Widget):
                widget.config(bg=normal_color)
        
        # Reset ttk.Labels and child frames
        for child in row_frame.winfo_children():
            if isinstance(child, ttk.Label):
                child.configure(style="Normal.TLabel")
            elif isinstance(child, tk.Frame):
                child.config(bg=normal_color)
                for subchild in child.winfo_children():
                    if isinstance(subchild, ttk.Label):
                        subchild.configure(style="Normal.TLabel")
                    elif not isinstance(subchild, ttk.Widget):
                        try:
                            subchild.config(bg=normal_color)
                        except tk.TclError:
                            pass  # Ignore widgets that don't support bg

    # Create UI context for password strength updates
    ui_context = {
        "event": None,
        "parent_window": scrollable_details_frame,
        "entry_password": pass_entry,
        "password_strength_label": strength_label,
        "selected_aes_bit": aes_bit_var,
        "form_frame": scrollable_details_frame
    }

    # --- Buttons Frame ---
    buttons_frame = tk.Frame(scrollable_details_frame, bg="#ffffff")
    buttons_frame.pack(pady=10, fill='x')

    if is_edit_mode:
        # Save Button for editing
        save_button = tk.Button(buttons_frame, text="Save", bg="#4CAF50", fg="white", padx=20, pady=5,
                              command=lambda: save_password_changes(
                                  password_id, name_entry.get(), label_var.get(),
                                  user_entry.get(), pass_entry.get(), url_entry.get(),
                                  notes_text.get("1.0", tk.END).strip(), int(aes_bit_var.get()),
                                  mp_reprompt_var.get(), is_favourite_var.get()
                              ))
    else:
        # Save Button for adding new
        save_button = tk.Button(buttons_frame, text="Save", bg="#4CAF50", fg="white", padx=20, pady=5,
                              command=lambda: save_new_password(
                                  name_entry.get(), label_var.get(),
                                  user_entry.get(), pass_entry.get(), url_entry.get(),
                                  notes_text.get("1.0", tk.END).strip(), int(aes_bit_var.get()),
                                  mp_reprompt_var.get(), is_favourite_var.get()
                              ))

    save_button.pack(side='left', padx=10, expand=True)

    # Cancel Button
    cancel_button = tk.Button(buttons_frame, text="Cancel", bg="#f44336", fg="white", padx=20, pady=5,
                            command=lambda: details_frame.pack_forget())
    cancel_button.pack(side='left', padx=10, expand=True)

    def on_aes_bit_change(event, context):
        context["selected_aes_bit"].set(int(event.widget.get()))
        update_password_strength(context)
    
    # Bind password strength updates
    aes_bit_combobox.bind("<<ComboboxSelected>>", partial(on_aes_bit_change, context=ui_context))
    pass_entry.bind("<KeyRelease>", lambda event: update_password_strength(ui_context))

    # Keep references to images
    show_btn.image = hide_icon
    breach_btn.image = breach_icon
    generate_btn.image = generate_icon

    # Initial password strength update
    update_password_strength(ui_context)

def open_add_password_form():
    show_password_details()  # Call without password_id to enter add mode

def save_new_password(name, label, user, password, url, notes, aes_bits, mp_reprompt, is_favourite):
    # Validation logic
    if not name or not label or not user or not password:
        messagebox.showerror("Error", "Please fill in all required fields")
        return
    
    # Encryption logic
    encrypted_password = encrypt_things(password, key, aes_bits)
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Database insertion
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO passwords (
            platformName, platformLabel, platformUser, encryptedPassword,
            platformURL, platformNote, createdAt, updatedAt, aes_bits,
            mp_reprompt, isFavourite
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (name, label, user, encrypted_password, url, notes, current_time, current_time, aes_bits, mp_reprompt, is_favourite))
        conn.commit()
        messagebox.showinfo("Success", "Password saved successfully")
        show_home_content()  # Refresh the list
    except Exception as e:
        messagebox.showerror("Database Error", f"Error saving password: {str(e)}")
    finally:
        conn.close()

def save_password_changes(password_id, name, label, user, password, url, notes, aes_bits, mp_reprompt, is_favourite):
    # Validation logic
    if not name or not label or not user or not password:
        messagebox.showerror("Error", "Please fill in all required fields")
        return
    
    # Encrypt the password before saving
    encrypted_password = encrypt_things(password, key, aes_bits)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE passwords 
            SET platformName = ?, platformLabel = ?, platformUser = ?, encryptedPassword = ?,
                platformURL = ?, platformNote = ?, updatedAt = ?, aes_bits = ?, 
                mp_reprompt = ?, isFavourite = ?
            WHERE id = ?
        """, (name, label, user, encrypted_password, url, notes, current_time, aes_bits, mp_reprompt, is_favourite, password_id))
        conn.commit()
        conn.close()
        
        # Success message
        messagebox.showinfo("Success", "Password updated successfully")
        
        # Refresh the display
        show_home_content()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save changes: {str(e)}")

def open_aes_evaluation_window(parent_window, current_password, aes_bit_var):
    eval_win = tk.Toplevel(parent_window)
    eval_win.title("AES Bit Evaluation")
    eval_win.configure(bg="#f0f0f0")
    eval_win.grab_set()

    # Window configuration
    window_width = 620
    window_height = 650
    screen_width = eval_win.winfo_screenwidth()
    screen_height = eval_win.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    eval_win.geometry(f"{window_width}x{window_height}+{x}+{y}")

    main_frame = tk.Frame(eval_win, bg="#f0f0f0")
    main_frame.pack(pady=10, fill=tk.BOTH, expand=True)
    main_frame.grid_columnconfigure(1, weight=1)

    # Password Input
    tk.Label(main_frame, text="Target Password:", bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    password_entry = tk.Entry(main_frame, show="*")
    password_entry.insert(0, current_password)
    password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    # Show/Hide Password Button
    show_password_icon = tk.PhotoImage(file="Images/show_password_b.png").subsample(3, 3)
    hide_password_icon = tk.PhotoImage(file="Images/hide_password_b.png").subsample(3, 3)
    settings_icon = tk.PhotoImage(file="Images/settings_b.png").subsample(3, 3)

    def toggle_password_visibility():
        if password_entry.cget('show') == '*':
            password_entry.config(show='')
            password_eye_icon.config(image=show_password_icon)
        else:
            password_entry.config(show='*')
            password_eye_icon.config(image=hide_password_icon)

    password_eye_icon = tk.Label(main_frame, image=hide_password_icon, cursor="hand2", bg="#f0f0f0")
    password_eye_icon.grid(row=0, column=2, padx=5, pady=5, sticky="e")
    password_eye_icon.bind("<Button-1>", lambda e: toggle_password_visibility())
    password_eye_icon.bind("<Enter>", lambda e: show_tooltip(e.widget, "Toggle password visibility"))
    password_eye_icon.bind("<Leave>", lambda e: hide_tooltip())

    # Get current values for guess_per_sec, thread_count, and guess_per_sec_threshold from the database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''SELECT guess_per_sec, thread_count, guess_per_sec_threshold FROM attack_settings LIMIT 1''')
    settings = cursor.fetchone()
    conn.close()

    # Set default values if no settings found
    guess_per_sec = settings[0] if settings else 3000000
    thread_count = settings[1] if settings else 1
    guess_per_sec_threshold = settings[2] if settings else 10000000

    # Guess Rate
    tk.Label(main_frame, text="Guess Rate (per sec):", bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    guess_sec_entry = tk.Entry(main_frame)
    guess_sec_entry.insert(0, str(guess_per_sec))
    guess_sec_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

    # Configure Guess Rate Button
    config_guess_rate_button = tk.Label(main_frame, image=settings_icon, cursor="hand2", bg="#f0f0f0")
    config_guess_rate_button.grid(row=1, column=2, padx=5, pady=5, sticky="w")
    config_guess_rate_button.bind("<Button-1>", lambda e: open_guess_rate_window(eval_win, guess_sec_entry))

    # To ensure the image doesn't get garbage collected
    config_guess_rate_button.image = settings_icon
    config_guess_rate_button.bind(
        "<Enter>", 
        lambda e: show_tooltip(config_guess_rate_button, "Configure guess rate settings")
    )
    config_guess_rate_button.bind(
        "<Leave>", 
        lambda e:  hide_tooltip()
    )
    # Evaluation Parameters Frame
    params_frame = tk.LabelFrame(main_frame, text="Evaluation Parameters", bg="#f0f0f0")
    params_frame.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
    
    # Performance Testing
    tk.Label(params_frame, text="Performance Testing:", bg="#f0f0f0").grid(row=0, column=0, sticky="w")
    enc_time_var = tk.BooleanVar(value=True)
    dec_time_var = tk.BooleanVar(value=True)
    mem_usage_var = tk.BooleanVar(value=True)
    throughput_var = tk.BooleanVar(value=True)
    tk.Checkbutton(params_frame, text="Encryption Time", variable=enc_time_var, bg="#f0f0f0").grid(row=0, column=1, sticky="w")
    tk.Checkbutton(params_frame, text="Decryption Time", variable=dec_time_var, bg="#f0f0f0").grid(row=0, column=2, sticky="w")
    tk.Checkbutton(params_frame, text="Memory Usage", variable=mem_usage_var, bg="#f0f0f0").grid(row=0, column=3, sticky="w")
    tk.Checkbutton(params_frame, text="Throughput", variable=throughput_var, bg="#f0f0f0").grid(row=0, column=4, sticky="w")
    
    # Estimated Time to Crack
    tk.Label(params_frame, text="Est. Crack Time:", bg="#f0f0f0").grid(row=1, column=0, sticky="w")
    aes_var = tk.BooleanVar(value=True)
    tk.Checkbutton(params_frame, variable=aes_var, bg="#f0f0f0").grid(row=1, column=1, sticky="w")

    # Ciphertext Entropy
    tk.Label(params_frame, text="Ciphertext Entropy:", bg="#f0f0f0").grid(row=2, column=0, sticky="w")
    entropy_var = tk.BooleanVar(value=True)
    tk.Checkbutton(params_frame, variable=entropy_var, bg="#f0f0f0").grid(row=2, column=1, sticky="w")

    # CLI Output
    cli_output = scrolledtext.ScrolledText(main_frame, state='disabled', height=20)
    cli_output.grid(row=5, column=0, columnspan=3, padx=5, pady=10, sticky="nsew")

    # Control Buttons
    button_frame = tk.Frame(main_frame, bg="#f0f0f0")
    button_frame.grid(row=6, column=0, columnspan=3, pady=10, sticky="ew")
    button_frame.grid_columnconfigure(0, weight=1)
    button_frame.grid_columnconfigure(1, weight=1)

    # Start Evaluation Button
    start_btn = tk.Button(button_frame, text="Start Evaluation", bg="#4CAF50", fg="white", width=20,
                         command=lambda: start_evaluation(
                             password_entry.get(),
                             enc_time_var.get(),
                             dec_time_var.get(),
                             mem_usage_var.get(),
                             throughput_var.get(),
                             entropy_var.get(),
                             aes_var.get(),
                             int(guess_sec_entry.get()),
                             cli_output,
                             aes_bit_var,
                             eval_win
                         ))
    start_btn.grid(row=0, column=0, padx=5)
   
    # Cancel Button
    tk.Button(button_frame, text="Cancel", bg="#f44336", fg="white", width=20, command=eval_win.destroy).grid(row=0, column=1, padx=5)
    return eval_win
    
def start_evaluation(password, enc_time, dec_time, mem_usage, throughput, entropy, 
                    est_aes, guess_sec, cli_output, aes_bit_var, eval_win):
    
    cli_output.config(state=tk.NORMAL)
    
    results = {}
    
    cli_output.insert(tk.END, f"\nGenerating 1 MB random plaintext for encryption and decryption tests...\n")

    for bits in ["128", "192", "256"]:
        cli_output.insert(tk.END, f"\n=== Evaluating AES-{bits} ===\n")
        
        perf = {}
        if enc_time or dec_time:
            perf = test_aes_performance(
                int(bits), password, 
                enc_time, dec_time,
                mem_usage, throughput, entropy
            )
        
        # Estimated crack times
        est_times = estimate_crack_times_evaluation(password, int(bits), est_aes, guess_sec)
            
        results[bits] = {
            'performance': perf,
            'estimates': est_times
        }

    # Encryption Performance Summary Table
    cli_output.insert(tk.END, "\n=== Encryption Performance Summary ===")
    cli_output.insert(tk.END, "\nKey Size | Enc Time (ms) | Enc Mem (MB) | Enc Throughput (MB/s)")
    cli_output.insert(tk.END, "\n-------------------------------------------------------------------------")
    for bits in ["128", "192", "256"]:
        perf = results[bits]['performance']
        cli_output.insert(tk.END, 
            f"\nAES-{bits.ljust(4)} | "
            f"{perf.get('encryption_time', 0):12.2f} | "
            f"{perf.get('encryption_memory', 0):12.2f} | "
            f"{perf.get('encryption_throughput', 0):17.2f} | ")
    
    # Decryption Performance Summary Table
    cli_output.insert(tk.END, "\n\n=== Decryption Performance Summary ===")
    cli_output.insert(tk.END, "\nKey Size | Dec Time (ms) | Dec Mem (MB) | Dec Throughput (MB/s)")
    cli_output.insert(tk.END, "\n-------------------------------------------------------------------------")
    for bits in ["128", "192", "256"]:
        perf = results[bits]['performance']
        cli_output.insert(tk.END, 
            f"\nAES-{bits.ljust(4)} | "
            f"{perf.get('decryption_time', 0):12.2f} | "
            f"{perf.get('decryption_memory', 0):12.2f} | "
            f"{perf.get('decryption_throughput', 0):17.2f}")
    
    # Security Summary Table (Ciphertext Entropy & Estimated Crack Time)
    cli_output.insert(tk.END, "\n\n=== Security Summary ===")
    cli_output.insert(tk.END, "\nKey Size | Ciphertext Entropy (bits) | Estimated Crack Time")
    cli_output.insert(tk.END, "\n---------------------------------------------------------------")
    for bits in ["128", "192", "256"]:
        perf = results[bits]['performance']
        est_times = results[bits]['estimates']
        
        # Only show the entropy and estimated crack time if they are selected
        entropy_display = perf.get('encryption_entropy', "N/A")
        crack_time_display = est_times.get("AES Brute-Force", "N/A")
        
        cli_output.insert(tk.END, 
            f"\nAES-{bits.ljust(4)} | "
            f"{entropy_display:25} | "
            f"{crack_time_display}")

    cli_output.insert(tk.END, "\n\nNote: AES uses different rounds based on key size:")
    cli_output.insert(tk.END, "\n- AES-128: 10 rounds\n- AES-192: 12 rounds\n- AES-256: 14 rounds")
    cli_output.insert(tk.END, "\nMore rounds = More computation time")
    cli_output.insert(tk.END, "\n\nSecurity Notes:")
    cli_output.insert(tk.END, "\n- Higher entropy indicates better randomness in ciphertext")
    cli_output.insert(tk.END, "\n- AES-256 provides strongest security with 14 rounds")

    # Determine best AES bit (example criteria)
    best_bit = determine_best_aes(results, cli_output)
    cli_output.insert(tk.END, f"\n\nRecommended AES Bit: AES-{best_bit} (best balance of performance and security)")
    cli_output.insert(tk.END, f"\n\nNote: This recommendation is based on experimental results; however, for best security, AES-256 is strongly recommended.\n")
    aes_bit_var.set(best_bit)
    
    cli_output.config(state=tk.DISABLED)
    eval_win.lift()
    
def calculate_entropy(data):
    """Calculate Shannon entropy of given data"""
    if not data:
        return 0.0
    entropy = 0.0
    data_size = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / data_size
        entropy += -p_x * math.log2(p_x)
    return entropy

def test_aes_performance(bits, password, test_enc, test_dec, test_mem, test_throughput, test_entropy):
    results = {}
    plaintext = os.urandom(1 * 1024 * 1024)  # 1MB random data
    key_length = bits // 8
    
    total_enc_time = 0
    total_dec_time = 0
    total_enc_memory = 0
    total_dec_memory = 0
    total_enc_throughput = 0
    total_dec_throughput = 0
    total_enc_entropy = 0
    total_dec_entropy = 0
    
    try:
        target_key = password.encode().ljust(key_length, b'\0')[:key_length]

        for _ in range(10):  # Run the test 10 times
            # Encryption metrics
            if test_enc:
                start_time = time.perf_counter()
                if test_mem:
                    tracemalloc.start()

                iv = os.urandom(12)
                cipher = Cipher(algorithms.AES(target_key), modes.GCM(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()

                if test_mem:
                    _, peak = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    total_enc_memory += peak / (1024 ** 2)  # MB

                end_time = time.perf_counter()
                total_enc_time += (end_time - start_time) * 1000  # ms

                if test_throughput:
                    total_enc_throughput += (1 * 1024 * 1024) / (end_time - start_time) / (1024 ** 2)  # MB/s

                if test_entropy:
                    total_enc_entropy += calculate_entropy(ciphertext)

            # Decryption metrics
            if test_dec:
                iv = os.urandom(12)
                cipher = Cipher(algorithms.AES(target_key), modes.GCM(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                tag = encryptor.tag
                combined = iv + tag + ciphertext

                start_time = time.perf_counter()
                if test_mem:
                    tracemalloc.start()

                iv = combined[:12]
                tag = combined[12:28]
                ciphertext_part = combined[28:]

                cipher = Cipher(algorithms.AES(target_key), modes.GCM(iv, tag), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext_part) + decryptor.finalize()

                if test_mem:
                    _, peak = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    total_dec_memory += peak / (1024 ** 2)  # MB

                end_time = time.perf_counter()
                total_dec_time += (end_time - start_time) * 1000  # ms

                if test_throughput:
                    total_dec_throughput += (1 * 1024 * 1024) / (end_time - start_time) / (1024 ** 2)  # MB/s

        # Calculate average results
        if test_enc:
            results['encryption_time'] = total_enc_time / 10
            results['encryption_memory'] = total_enc_memory / 10
            results['encryption_throughput'] = total_enc_throughput / 10
            results['encryption_entropy'] = total_enc_entropy / 10 if test_entropy else 0

        if test_dec:
            results['decryption_time'] = total_dec_time / 10
            results['decryption_memory'] = total_dec_memory / 10
            results['decryption_throughput'] = total_dec_throughput / 10

    except Exception as e:
        print(f"Performance test error: {str(e)}")
        return {}

    return results

def format_time(total_seconds: float) -> str:
    """Convert seconds into a human-readable string with scientific notation (e+something) if needed."""
    if total_seconds == math.inf:
        return "∞"

    sec_per_year = 365 * 24 * 3600
    units = [
        (sec_per_year, "years"),
        (30 * 24 * 3600, "months"),
        (24 * 3600,    "days"),
        (3600,         "hours"),
        (60,           "mins"),
        (1,            "s"),
    ]

    for unit_seconds, unit_name in units:
        value = total_seconds / unit_seconds
        if value >= 1:
            if value >= 1000:
                exponent = int(math.floor(math.log10(value)))
                base = value / (10 ** exponent)
                return f"{base:.2f}e+{exponent} {unit_name}"
            else:
                if value.is_integer():
                    return f"{int(value)} {unit_name}"
                else:
                    return f"{value:.5f} {unit_name}"

    # less than one second
    return f"{total_seconds:.10f} s"

def estimate_crack_times_evaluation(password, aes_bits, aes, guesses_per_sec):
    """
    Returns a dictionary with estimated crack times for different methods.
    Each method will be enabled/disabled based on the user's selection in the GUI.
    """
    # Early exit if the password is empty
    if not password:
        return {method: "No password entered" for method in
                ["AES Brute-Force"]}

    # Check for invalid guesses_per_sec
    if guesses_per_sec <= 0:
        return {"Error": "Invalid guess rate: must be greater than 0"}
    
    # Charset size & entropy for password brute-force
    cs = get_charset_size(password)  # This function calculates the charset size based on the password
    possible_combinations = cs ** len(password)
    total_entropy = len(password) * math.log2(cs)

    results = {}

    # AES Brute-Force
    if aes:
        aes_seconds = (2 ** aes_bits) / guesses_per_sec  # Time to brute-force AES key
        results["AES Brute-Force"] = format_time(aes_seconds)
    else:
        results["AES Brute-Force"] = "AES brute-force disabled"
    return results

def determine_best_aes(results, cli_output):
    # Initialize scores for each AES bit
    scores = {"128": 0, "192": 0, "256": 0}
    total_metrics = {"128": 0, "192": 0, "256": 0}  # Tracks the number of metrics counted
    
    # Store detailed breakdown of scores for display
    score_details = {
        "128": {'enc_time': 0, 'mem_usage': 0, 'throughput': 0, 'entropy': 0, 'crack_time': 0, 'dec_time': 0, 'dec_mem_usage': 0, 'dec_throughput': 0},
        "192": {'enc_time': 0, 'mem_usage': 0, 'throughput': 0, 'entropy': 0, 'crack_time': 0, 'dec_time': 0, 'dec_mem_usage': 0, 'dec_throughput': 0},
        "256": {'enc_time': 0, 'mem_usage': 0, 'throughput': 0, 'entropy': 0, 'crack_time': 0, 'dec_time': 0, 'dec_mem_usage': 0, 'dec_throughput': 0}
    }

    # Maximum score per metric
    max_score_per_metric = 10

    for bits in ["128", "192", "256"]:
        perf = results[bits]['performance']
        est_times = results[bits]['estimates']
        
        # Calculate score for Encryption Time: Lower is better
        enc_time = perf.get('encryption_time', None)
        if enc_time is not None:
            enc_time_score = max_score_per_metric / (enc_time + 1)
            scores[bits] += enc_time_score
            score_details[bits]['enc_time'] = enc_time_score
            total_metrics[bits] += 1
        
        # Calculate score for Memory Usage (Encryption): Lower is better
        mem_usage = perf.get('encryption_memory', None)
        if mem_usage is not None:
            mem_usage_score = max_score_per_metric / (mem_usage + 1)
            scores[bits] += mem_usage_score
            score_details[bits]['mem_usage'] = mem_usage_score
            total_metrics[bits] += 1
        
        # Calculate score for Throughput (Encryption): Higher is better
        throughput = perf.get('encryption_throughput', None)
        if throughput is not None:
            throughput_score = min(throughput, max_score_per_metric)
            scores[bits] += throughput_score
            score_details[bits]['throughput'] = throughput_score
            total_metrics[bits] += 1
        
        # Calculate score for Entropy: Higher is better
        entropy = perf.get('encryption_entropy', None)
        if entropy is not None:
            entropy_score = min(entropy, max_score_per_metric)
            scores[bits] += entropy_score
            score_details[bits]['entropy'] = entropy_score
            total_metrics[bits] += 1
        
        # Calculate score for Estimated Crack Time: Lower is better
        crack_time = est_times.get("AES Brute-Force", "N/A")
        if crack_time != "N/A":
            time_in_seconds = convert_crack_time_to_seconds(crack_time)
            crack_time_score = max_score_per_metric / (time_in_seconds + 1)
            scores[bits] += crack_time_score
            score_details[bits]['crack_time'] = crack_time_score
            total_metrics[bits] += 1
        
        # Calculate Decryption Metrics: Now including decryption time, memory usage, and throughput
        # Score for Decryption Time: Lower is better
        dec_time = perf.get('decryption_time', None)
        if dec_time is not None:
            dec_time_score = max_score_per_metric / (dec_time + 1)
            scores[bits] += dec_time_score
            score_details[bits]['dec_time'] = dec_time_score
            total_metrics[bits] += 1
        
        # Score for Decryption Memory Usage: Lower is better
        dec_mem_usage = perf.get('decryption_memory', None)
        if dec_mem_usage is not None:
            dec_mem_usage_score = max_score_per_metric / (dec_mem_usage + 1)
            scores[bits] += dec_mem_usage_score
            score_details[bits]['dec_mem_usage'] = dec_mem_usage_score
            total_metrics[bits] += 1
        
        # Score for Decryption Throughput: Higher is better
        dec_throughput = perf.get('decryption_throughput', None)
        if dec_throughput is not None:
            dec_throughput_score = min(dec_throughput, max_score_per_metric)
            scores[bits] += dec_throughput_score
            score_details[bits]['dec_throughput'] = dec_throughput_score
            total_metrics[bits] += 1

    # Normalize the score to be out of 100, based on the number of metrics available
    for bits in ["128", "192", "256"]:
        if total_metrics[bits] > 0:
            scores[bits] = (scores[bits] / (total_metrics[bits] * max_score_per_metric)) * 100  # Normalize out of 100

    # Select the AES bit with the highest score
    best_bit = max(scores, key=scores.get)

    # Output the detailed scores for each AES bit using cli_output
    cli_output.insert(tk.END, "\n\nDetailed Scores for each AES bit:")
    for bits in ["128", "192", "256"]:
        cli_output.insert(tk.END, f"\nAES-{bits}:")
        cli_output.insert(tk.END, f"\n  Encryption Time: {score_details[bits]['enc_time']:.2f}")
        cli_output.insert(tk.END, f"\n  Encryption Memory Usage: {score_details[bits]['mem_usage']:.2f}")
        cli_output.insert(tk.END, f"\n  Encryption Throughput: {score_details[bits]['throughput']:.2f}")
        cli_output.insert(tk.END, f"\n  Decryption Time: {score_details[bits]['dec_time']:.2f}")
        cli_output.insert(tk.END, f"\n  Decryption Memory Usage: {score_details[bits]['dec_mem_usage']:.2f}")
        cli_output.insert(tk.END, f"\n  Decryption Throughput: {score_details[bits]['dec_throughput']:.2f}")
        cli_output.insert(tk.END, f"\n  Ciphertext Entropy: {score_details[bits]['entropy']:.2f}")
        cli_output.insert(tk.END, f"\n  Estimated Crack Time: {score_details[bits]['crack_time']:.2f}")
        
        # Display the total score out of 100%
        cli_output.insert(tk.END, f"\n  Total Score: {scores[bits]:.2f}%\n")

    cli_output.insert(tk.END, f"\n\nBest AES bit: AES-{best_bit} with a total score of {scores[best_bit]:.2f}%")
    
    return best_bit

def convert_crack_time_to_seconds(crack_time_str):
    """
    Converts estimated crack time string (e.g., '24 years', '3 days', '150s') into seconds.
    """
    # Define the conversion factors for each time unit to seconds
    time_units = {
        "years": 365 * 24 * 3600,    # 1 year = 365 days
        "months": 30 * 24 * 3600,    # 1 month = 30 days
        "days": 24 * 3600,           # 1 day = 24 hours
        "hours": 3600,               # 1 hour = 60 minutes * 60 seconds
        "mins": 60,                  # 1 minute = 60 seconds
        "s": 1                       # seconds
    }

    # Try to match the pattern with a number followed by a time unit (e.g., '24 years')
    match = re.match(r"(\d+(?:\.\d+)?)\s*(\w+)", crack_time_str.strip().lower())
    if match:
        number = float(match.group(1))  # The number (e.g., 24, 3, etc.)
        unit = match.group(2)           # The unit (e.g., 'years', 'days', etc.)

        # If the unit is valid, convert to seconds
        if unit in time_units:
            return number * time_units[unit]
        else:
            return 0  # Invalid unit, return 0 seconds
    else:
        return 0  # Could not parse the time string, return 0 seconds

def get_label_color(label):
    # Assign colors based on label types
    colors = {
        "Work": "#3498db",
        "Education": "#2ecc71",
        "Entertainment": "#e74c3c",
        "Social Media": "#9b59b6",
        "Shopping": "#f39c12",
        "Utilities": "#1abc9c",
        "Other": "#95a5a6"
    }
    return colors.get(label, "#95a5a6")  # Default color if label not found

def show_password_health_content():
    global add_button_ref

    toggle_scrollbar(True)
    toggle_scrolling(True)

    # Function to display password health content
    for widget in main_frame.winfo_children():
        if widget != timer_label:  # Do not destroy the timer label
            widget.destroy()

    # Destroy the existing "Add" button if it exists
    if add_button_ref:
        add_button_ref.destroy()  # Destroy the old button
        add_button_ref = None     # Reset the global reference

    # Create a container frame that will center its contents
    container = tk.Frame(main_frame, bg="#f0f0f0")
    container.pack(fill=tk.BOTH, expand=True)

    # Add your content to this container instead of main_frame directly
    tk.Label(container, text="Password Health Checker", font=("Helvetica", 16, "bold")).pack(pady=10)
    tk.Label(container, text="Identify weak, old or reused passwords. Click to take action now!").pack(pady=5)

    # Function to identify weak, old, and reused passwords
    def identify_password_issues():
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, platformName, platformLabel, platformUser, encryptedPassword, createdAt, updatedAt, aes_bits FROM passwords")
        passwords = cursor.fetchall()
        conn.close()

        weak_passwords = []
        old_passwords = []
        reused_passwords = []
        breached_passwords = []

        decrypted_passwords = [decrypt_things(pwd[4], key, pwd[7]) for pwd in passwords]

        for i, pwd in enumerate(passwords):
            decrypted_password = decrypted_passwords[i]
            if len(decrypted_password) < 8 or not re.search(r"[A-Z]", decrypted_password) or not re.search(r"[a-z]", decrypted_password) or not re.search(r"[0-9]", decrypted_password):
                weak_passwords.append(pwd)
            if (datetime.now() - datetime.strptime(pwd[6], "%Y-%m-%d %H:%M:%S")).days > 365:
                old_passwords.append(pwd)
            if decrypted_passwords.count(decrypted_password) > 1:
                reused_passwords.append(pwd)
            breach_msg, count, error = check_pwned_password(decrypted_password)
            if not error and count is not None:
                breached_passwords.append(pwd)

        return weak_passwords, old_passwords, reused_passwords, breached_passwords

    weak_passwords, old_passwords, reused_passwords, breached_passwords = identify_password_issues()

    # Function to show password entries
    def show_entries(entries):
        for widget in main_frame.winfo_children():
            widget.destroy()

        # Back arrow to return to main menu
        back_arrow = tk.Label(main_frame, text="←", font=("Helvetica", 14), cursor="hand2", bg="white")
        back_arrow.pack(anchor="w", padx=10, pady=10)
        back_arrow.bind("<Button-1>", lambda e: show_password_health_content())

        # Display password entries
        for entry in entries:
            entry_frame = tk.Frame(main_frame, relief=tk.RAISED, borderwidth=2, bg="white")
            entry_frame.config(width=350, height=100)  # Set a slightly larger fixed size
            entry_frame.pack_propagate(False)  # Prevent resizing
            entry_frame.pack(pady=10, padx=10)

            # Create labels for platform details
            platform_name = tk.Label(entry_frame, text=f"Platform: {entry[1]}", bg="white", anchor="w")
            platform_name.grid(row=0, column=0, padx=10, pady=5, sticky="w")

            platform_label = tk.Label(entry_frame, text=f"Label: {entry[2]}", bg="white", anchor="w")
            platform_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

            platform_user = tk.Label(entry_frame, text=f"Username: {entry[3]}", bg="white", anchor="w")
            platform_user.grid(row=2, column=0, padx=10, pady=5, sticky="w")

            masked_password = tk.Label(entry_frame, text="Password: **********", bg="white", anchor="w")
            masked_password.grid(row=3, column=0, padx=10, pady=5, sticky="w")

            # Buttons container to align them vertically
            buttons_frame = tk.Frame(entry_frame, bg="white")
            buttons_frame.grid(row=0, column=1, rowspan=4, padx=10, pady=5, sticky="ns")

            # Change Password button
            change_button = tk.Button(buttons_frame, text="Change Password", command=lambda e=entry: edit_selected_entry_by_id(e[0]))
            change_button.pack(pady=5, fill="x")

            # Delete button
            delete_button = tk.Button(buttons_frame, text="Delete", command=lambda e=entry: delete_selected_entry_by_id(e[0]))
            delete_button.pack(pady=5, fill="x")

        # Ensure the layout is updated correctly after the entries are shown
        main_frame.update_idletasks()

    # Sections for weak, old, reused and breached passwords
    sections = [
        ("Weak Passwords", len(weak_passwords), weak_passwords, "No weak passwords found.", "Weak passwords found. Click to view."),
        ("Old Passwords", len(old_passwords), old_passwords, "No old passwords found.", "Old passwords found. Click to view."),
        ("Reused Passwords", len(reused_passwords), reused_passwords, "No reused passwords found.", "Reused passwords found. Click to view."),
        ("Breached Passwords", len(breached_passwords), breached_passwords, "No breached passwords found.", "Breached passwords found. Click to view.")
    ]

    # Create a frame for sections
    section_container = tk.Frame(container)
    section_container.pack(pady=10, padx=20)

    for section in sections:
        frame = tk.Frame(section_container, relief=tk.RAISED, borderwidth=2, bg="white", cursor="hand2")
        frame.config(width=350, height=80)  # Set fixed size
        frame.pack_propagate(False)  # Prevent resizing
        frame.pack(pady=10, padx=10, fill="x")

        # Create a frame inside for content
        content_frame = tk.Frame(frame, bg="white")
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

        count_color = "green" if section[1] == 0 else "red"
        count_label = tk.Label(content_frame, text=f"{section[1]}", font=("Helvetica", 14, "bold"), fg=count_color, bg="white")
        count_label.pack(side=tk.TOP, pady=(5, 2))  # Top padding

        description = section[3] if section[1] == 0 else section[4]
        label = tk.Label(content_frame, text=description, font=("Helvetica", 12), bg="white")
        label.pack(side=tk.TOP, pady=(2, 5))  # Bottom padding

        # Right arrow aligned to the middle right side
        arrow = tk.Label(frame, text="→", font=("Helvetica", 12), cursor="hand2", bg="white")
        if section[1] == 0:
            arrow.place_forget()  # Hide the arrow if there are no issues
        else:
            arrow.place(relx=0.95, rely=0.5, anchor="e")  # Align to right-middle

        # Bind click event to the entire section (frame)
        if section[1] > 0:
            frame.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
            content_frame.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
            count_label.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
            label.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
            arrow.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))

def edit_selected_entry_by_id(password_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE id=?", (password_id,))
    entry = cursor.fetchone()
    conn.close()

    if not entry:
        messagebox.showwarning("Selection Error", "Password entry not found.")
        return

    # Create a Toplevel window (pop-up)
    edit_password_window = tk.Toplevel(root)
    edit_password_window.title("Edit Entry")
    window_width = 550
    window_height = 700

    # Center the window
    screen_width = edit_password_window.winfo_screenwidth()
    screen_height = edit_password_window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    edit_password_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
    edit_password_window.configure(bg="#f0f0f0")

    # Define padding
    label_padx = 20
    entry_padx = 10
    pady = 10

    # Create form frame
    form_frame = tk.Frame(edit_password_window, bg="#f0f0f0")
    form_frame.pack(pady=20)

    # Platform Name
    tk.Label(form_frame, text="Platform Name:", anchor="w").grid(row=0, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_platform_name = tk.Entry(form_frame, width=30)
    entry_platform_name.insert(0, entry[1])
    entry_platform_name.grid(row=0, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Label (Category)
    tk.Label(form_frame, text="Label:", anchor="w").grid(row=1, column=0, padx=label_padx, pady=pady, sticky="w")
    label_options = ["Banking", "Browser", "Cloud Services", "Development", "Education", "Email", "Entertainment", 
                    "Finance", "Forums", "Gaming", "Government", "Health", "News", "Personal", "Shopping", 
                    "Social Media", "Sports", "Streaming", "Travel", "Utilities", "Work", "Others"]
    platform_label = ttk.Combobox(form_frame, values=label_options, width=27)
    platform_label.set(entry[2])
    platform_label.grid(row=1, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Username
    tk.Label(form_frame, text="Username:", anchor="w").grid(row=2, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_username = tk.Entry(form_frame, width=30)
    entry_username.insert(0, entry[3])
    entry_username.grid(row=2, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Password Field
    tk.Label(form_frame, text="Password:", bg="#f0f0f0", anchor="w").grid(row=3, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_password = tk.Entry(form_frame, show="*", width=30)
    entry_password.insert(0, decrypt_things(entry[4], key))
    entry_password.grid(row=3, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Confirm Password
    tk.Label(form_frame, text="Confirm Password:", anchor="w").grid(row=4, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_confirm_password = tk.Entry(form_frame, show="*", width=30)
    entry_confirm_password.insert(0, decrypt_things(entry[4], key))
    entry_confirm_password.grid(row=4, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Show/Hide password icon
    def toggle_password_visibility():
        if entry_password.cget('show') == '*':
            entry_password.config(show='')
            entry_confirm_password.config(show='')
            eye_icon.config(image=show_password)
        else:
            entry_password.config(show='*')
            entry_confirm_password.config(show='*')
            eye_icon.config(image=hide_password)

    show_password = tk.PhotoImage(file="Images/show_password_b.png").subsample(3, 3)
    hide_password = tk.PhotoImage(file="Images/hide_password_b.png").subsample(3, 3)
    eye_icon = tk.Label(form_frame, image=hide_password, cursor="hand2", bg="#f0f0f0")
    eye_icon.grid(row=3, column=2, padx=5, sticky="w")
    eye_icon.bind("<Button-1>", lambda e: toggle_password_visibility())

    # Add breach check button next to show/hide
    breach_icon = tk.PhotoImage(file="Images/breach_check_b.png").subsample(15, 15)
    breach_button = tk.Button(
        form_frame,
        image=breach_icon,
        bg="#f0f0f0",
        relief="flat",
        cursor="hand2",
        command=lambda: perform_breach_check(entry_password.get(), edit_password_window)
    )
    breach_button.grid(row=3, column=3, padx=5, sticky="w")
    breach_button.image = breach_icon  # Keep reference

    # AES Bit Selection
    tk.Label(form_frame, text="AES Bit:", anchor="w").grid(row=5, column=0, padx=label_padx, pady=pady, sticky="w")
    aes_bit_options = ["128", "192", "256"]
    aes_bit_combobox = ttk.Combobox(form_frame, values=aes_bit_options, width=27)
    aes_bit_combobox.grid(row=5, column=1, padx=entry_padx, pady=pady, sticky="w")
    aes_bit_combobox.set(256)
    selected_aes_bit = tk.IntVar(value=256)

    # Password Strength Indicator
    password_strength_label = tk.Label(form_frame, text="Strength: Weak", fg="red", anchor="w")
    password_strength_label.grid(row=6, column=1, padx=entry_padx, pady=5, sticky="w")

    # Attack Method ComboBox
    tk.Label(form_frame, text="Attack Method:", anchor="w").grid(row=7, column=0, padx=label_padx, pady=pady, sticky="w")
    attack_method_options = ["Brute Force", "Dictionary Attack", "Rainbow Table"]
    attack_method_var = tk.StringVar(value="Brute Force")
    attack_method_combobox = ttk.Combobox(form_frame, values=attack_method_options, width=27, textvariable=attack_method_var)
    attack_method_combobox.grid(row=7, column=1, padx=entry_padx, pady=pady, sticky="w")

    def update_password_strength(event):
        password = entry_password.get()
        strength = check_password_strength(password)
        color_map = {"Weak": "red", "Medium": "orange", "Strong": "green"}
        strength_color = color_map.get(strength, "black")
        password_strength_label.config(text=f"Strength: {strength}", fg=strength_color)

        crack_times = estimate_crack_time(password, selected_aes_bit.get(), attack_method_var.get())
        
        if not hasattr(entry_password, 'crack_time_labels'):
            entry_password.crack_time_labels = {}
            crack_frame = tk.Frame(form_frame)
            crack_frame.grid(row=10, column=0, columnspan=4, pady=5, sticky="w")
            tk.Label(crack_frame, text="Estimated Time to Crack:", font=("Arial", 9, "bold")).pack(anchor="w")
            
            algorithms = ["AES Brute-Force", "Password Brute-Force", "Dictionary Attack", "Rainbow Table", "Breach Check"]
            for algo in algorithms:
                frame = tk.Frame(crack_frame)
                frame.pack(anchor="w")
                tk.Label(frame, text=f"{algo}:", width=16, anchor="w").pack(side=tk.LEFT)
                label = tk.Label(frame, text="", fg="red")
                label.pack(side=tk.LEFT)
                entry_password.crack_time_labels[algo] = label
        
        for algo, time in crack_times.items():
            label = entry_password.crack_time_labels[algo]
            label.config(text=time)
            if algo == "Breach Check":
                color = "red" if "⚠️" in time or time == "No password entered" else "green"
                label.config(fg=color)
            elif algo == "Dictionary Attack":
                color = "red" if time in ["Dictionary attack disabled", "No password entered", "Found in wordlist"] else "green"
                label.config(fg=color)
            else:
                color = "green" if "yrs" in time else "orange" if "days" in time else "red"
                label.config(fg=color)

    def on_aes_bit_change(event):
        selected_aes_bit.set(int(aes_bit_combobox.get()))
        update_password_strength(None)

    aes_bit_combobox.bind("<<ComboboxSelected>>", on_aes_bit_change)
    attack_method_combobox.bind("<<ComboboxSelected>>", update_password_strength)
    entry_password.bind("<KeyRelease>", update_password_strength)
    update_password_strength(None)  # <-- Auto-check strength on form load

    # URL
    tk.Label(form_frame, text="URL:", anchor="w").grid(row=8, column=0, padx=label_padx, pady=pady, sticky="w")
    entry_url = tk.Entry(form_frame, width=30)
    entry_url.insert(0, entry[5])
    entry_url.grid(row=8, column=1, padx=entry_padx, pady=pady, sticky="w")

    # Notes
    tk.Label(form_frame, text="Notes:", anchor="nw").grid(row=9, column=0, padx=label_padx, pady=pady, sticky="nw")
    entry_notes = tk.Text(form_frame, height=4, width=30)
    entry_notes.insert("1.0", entry[6])
    entry_notes.grid(row=9, column=1, padx=entry_padx, pady=pady, sticky="w", columnspan=2)

    # Generate Password Menu
    def show_generate_menu(event):
        generate_menu.post(event.x_root, event.y_root)
        
    def generate_now():
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM password_criteria ORDER BY id DESC LIMIT 1")
        criteria = cursor.fetchone()
        conn.close()

        if not criteria:
            messagebox.showwarning("Criteria Error", "No password generation criteria found.")
            return

        length, include_uppercase, include_lowercase, include_digits, include_minus, \
        include_underline, include_space, include_special, include_brackets, include_latin1 = criteria[1:]

        characters = ""
        if include_uppercase: characters += string.ascii_uppercase
        if include_lowercase: characters += string.ascii_lowercase
        if include_digits: characters += string.digits
        if include_minus: characters += "-"
        if include_underline: characters += "_"
        if include_space: characters += " "
        if include_special: characters += "!\"#$%&'*+,-./:;=?@\\^_`|~"
        if include_brackets: characters += "[]{}()<>"
        if include_latin1: characters += ''.join(chr(i) for i in range(160, 256))

        if not characters:
            messagebox.showwarning("Selection Error", "Please select at least one character type.")
            return

        while True:
            new_password = generate_password(length, characters)
            if check_password_strength(new_password) == "Strong":
                break

        entry_password.delete(0, tk.END)
        entry_password.insert(0, new_password)
        update_password_strength(None)

    def setup_password_generation():
        open_password_generation_form()

    # Generate Password Button
    generate_menu = tk.Menu(root, tearoff=0)
    generate_menu.add_command(label="Generate Now", command=generate_now)
    generate_menu.add_command(label="Setup Password Generation", command=setup_password_generation)
    
    generate_button = tk.Button(form_frame, text="Generate", font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", padx=5, pady=2, relief="raised")
    generate_button.grid(row=3, column=4, padx=5, sticky="w")
    generate_button.bind("<Button-1>", show_generate_menu)
    generate_button.bind("<Enter>", lambda event: on_hover(event, generate_button, "#45a049", "#4CAF50"))
    generate_button.bind("<Leave>", lambda event: on_hover(event, generate_button, "#45a049", "#4CAF50"))

    # OK & Cancel Buttons
    button_frame = tk.Frame(edit_password_window, bg="#f0f0f0")
    button_frame.pack(pady=20)

    def update_password_action():
        platform_name = entry_platform_name.get()
        platform_label_value = platform_label.get()
        username = entry_username.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()
        url = entry_url.get()
        notes = entry_notes.get("1.0", tk.END).strip()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if password != confirm_password:
            messagebox.showwarning("Password Mismatch", "The passwords do not match.")
            return
        
        if platform_name and platform_label_value and username and password:
            encrypted_password = encrypt_things(password, key)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE passwords SET platformName=?, platformLabel=?, platformUser=?, encryptedPassword=?, platformURL=?, platformNote=?, updatedAt=? WHERE id=?",
                        (platform_name, platform_label_value, username, encrypted_password, url, notes, current_time, entry[0]))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Password updated successfully!")
            edit_password_window.destroy()
            show_password_health_content()  # Or load_passwords() depending on context
        else:
            messagebox.showwarning("Input Error", "Please fill in all fields.")
            
    ok_button = tk.Button(button_frame, text="OK", font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", padx=20, pady=5, relief="raised", command=update_password_action)
    ok_button.grid(row=0, column=0, padx=10, sticky="w")
    ok_button.bind("<Enter>", lambda event: on_hover(event, ok_button, "#388E3C", "#4CAF50"))
    ok_button.bind("<Leave>", lambda event: on_hover(event, ok_button, "#388E3C", "#4CAF50"))

    cancel_button = tk.Button(button_frame, text="Cancel", font=("Arial", 10, "bold"), bg="#f44336", fg="white", padx=20, pady=5, relief="raised", command=edit_password_window.destroy)
    cancel_button.grid(row=0, column=1, padx=10, sticky="w")
    cancel_button.bind("<Enter>", lambda event: on_hover(event, cancel_button, "#d32f2f", "#f44336"))
    cancel_button.bind("<Leave>", lambda event: on_hover(event, cancel_button, "#d32f2f", "#f44336"))

    ok_button.focus_set()
    edit_password_window.bind("<Return>", lambda event: update_password_action())

# New delete_selected_entry_by_id function
def delete_selected_entry_by_id(password_id):
    confirm = messagebox.askyesno("Delete Entry", "Are you sure you want to delete this entry?")
    if confirm:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE id=?", (password_id,))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Password entry deleted successfully!")
        show_password_health_content()  # Refresh the password list
        
# def insert_sample_data():
#     conn = sqlite3.connect(DB_FILE)
#     cursor = conn.cursor()
#
#     # Sample data with an old date
#     sample_data = [
#         ("Sample Platform 1", "Label 1", "User 1", encrypt_things("Password1!", derive_key(master_password)), "http://example.com", "Note 1", "2020-01-01 12:00:00", "2020-01-01 12:00:00"),
#         ("Sample Platform 2", "Label 2", "User 2", encrypt_things("Password2@", derive_key(master_password)), "http://example.com", "Note 2", "2021-01-01 12:00:00", "2021-01-01 12:00:00"),
#         ("Sample Platform 3", "Label 3", "User 3", encrypt_things("Password3#", derive_key(master_password)), "http://example.com", "Note 3", "2022-01-01 12:00:00", "2022-01-01 12:00:00")
#     ]
#
#     cursor.executemany('''INSERT INTO passwords (platformName, platformLabel, platformUser, encryptedPassword, platformURL, platformNote, createdAt, updatedAt)
#                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', sample_data)
#
#     conn.commit()
#     conn.close()

def show_settings_content():
    global add_button_ref

    toggle_scrollbar(True)
    toggle_scrolling(True)

    # Function to display settings content
    for widget in main_frame.winfo_children():
        if widget != timer_label:  # Do not destroy the timer label
            widget.destroy()
    
    # Destroy the existing "Add" button if it exists
    if add_button_ref:
        add_button_ref.destroy()  # Destroy the old button
        add_button_ref = None     # Reset the global reference

    # Add a placeholder to maintain height
    placeholder = tk.Frame(nav_bar, width=30, height=30, bg="#333333")
    placeholder.pack(side=tk.RIGHT, padx=10)

    # Create a container frame that will center its contents
    container = tk.Frame(main_frame, bg="#f0f0f0")
    container.pack(fill=tk.BOTH, expand=True)

    # Create the sidebar and content area within the container
    sidebar = tk.Frame(container, width=200, bg="#f0f0f0")
    sidebar.pack(side=tk.LEFT, fill=tk.Y)

    content_area = tk.Frame(container, bg="white")
    content_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Display initial message - centered in the content area
    initial_msg_frame = tk.Frame(content_area, bg="white")
    initial_msg_frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(initial_msg_frame, 
             text="Here is the settings page. Click any option from the left sidebar to configure individual settings.", 
             font=("Helvetica", 14), 
             wraplength=400, 
             justify="center").pack(pady=20, expand=True)

    # Sidebar options
    options = ["MFA", "Alerts", "Recovery Keys", "Backup & Restore", "Autologout", "Clipboard Timer"]

    # Flag to track if the master password has been entered
    global password_verified
    password_verified = False
    
    def save_settings(setting_name, setting_value, callback):
        global password_verified
        # Only require master password once for backup settings
        if not password_verified:
            if not require_master_password():
                return
            password_verified = True  # Set the flag after verifying the password

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            cursor.execute(f"UPDATE settings SET {setting_name} = ? WHERE rowid = 1", (setting_value,))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            conn.rollback()
        finally:
            conn.close()
        # Reload settings after saving
        global settings
        settings = load_settings()
        if callback:
            callback()

    def show_mfa_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
        
        # Create a frame to center the content
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(center_frame, text="MFA Settings", font=("Helvetica", 16)).pack(pady=10)
        mfa_var = tk.BooleanVar(value=settings[0])
        tk.Checkbutton(center_frame, text="Enable MFA", variable=mfa_var).pack(pady=5)
        
        def show_qr_and_otp():
            otp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(otp_secret)
            qr_code = qrcode.make(totp.provisioning_uri("", issuer_name="Password Manager"))
            
            # Reduce the size of the QR code
            qr_code = qr_code.resize((200, 200), Image.LANCZOS)
            
            qr_code_img = ImageTk.PhotoImage(qr_code)
            
            # Place the setup key before the QR code
            tk.Label(center_frame, text=f"Setup Key: {otp_secret}", font=("Helvetica", 12)).pack(pady=5)
            qr_label = tk.Label(center_frame, image=qr_code_img)
            qr_label.image = qr_code_img
            qr_label.pack(pady=10)
            
            # Instructions for the user
            tk.Label(center_frame, text="Use an authenticator app (e.g., Google Authenticator, Microsoft Authenticator) on your phone to scan the QR code or manually enter the setup key.", 
                    font=("Helvetica", 12)).pack(pady=5)
            
            # OTP entry field
            tk.Label(center_frame, text="Enter the OTP code from your authenticator app:", 
                    font=("Helvetica", 12)).pack(pady=10)
            otp_entry = tk.Entry(center_frame, font=("Helvetica", 14), justify="center")
            otp_entry.pack(pady=10)
            otp_entry.focus_set()  # Set focus to the entry field

            def verify_and_save():
                entered_otp = otp_entry.get()
                totp = pyotp.TOTP(otp_secret)
                if totp.verify(entered_otp):
                    encrypted_otp_secret = encrypt_things(otp_secret, key, 256)
                    save_settings('mfa', True, show_mfa_settings)
                    save_settings('otp_secret', encrypted_otp_secret, show_mfa_settings)
                    messagebox.showinfo("Success", "MFA settings saved and verified.")
                else:
                    messagebox.showerror("Error", "OTP verification failed. MFA settings not saved.")

            verify_button = tk.Button(center_frame, text="Verify and Save", command=verify_and_save)
            verify_button.pack(pady=10)
            
            # Bind the Enter key to the verify_and_save function
            otp_entry.bind('<Return>', lambda event: verify_and_save())

        def save_mfa_setting():
            if settings[0] and mfa_var.get():  # MFA is already enabled
                messagebox.showinfo("MFA Already Enabled", "MFA is already enabled and cannot be re-enabled.")   
                return

            if mfa_var.get():  # Enabling MFA
                global password_verified
                # Only require master password once for backup settings
                if not password_verified:
                    if not require_master_password():
                        return
                    password_verified = True  # Set the flag after verifying the password
                save_button.pack_forget()  # Hide the Save button
                show_qr_and_otp()
            else:  # Disabling MFA
                save_settings('mfa', 0, show_mfa_settings)
                save_settings('otp_secret', '', show_mfa_settings)  # Clear OTP secret
                messagebox.showinfo("Success", "MFA settings disabled.")


        save_button = tk.Button(center_frame, text="Save", command=save_mfa_setting)
        save_button.pack(pady=10)

        #def cancel_operation():
        #    save_settings('mfa', False, show_mfa_settings)

        # Bind the cancel operation to window close event
        #content_area.bind("<Destroy>", lambda event: cancel_operation())

    def show_alerts_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
        
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(center_frame, text="Alerts Settings", font=("Helvetica", 16)).pack(pady=10)
        alerts_var = tk.BooleanVar(value=settings[1])
        tk.Checkbutton(center_frame, text="Enable Alerts", variable=alerts_var).pack(pady=5)
        tk.Button(center_frame, text="Save", 
                 command=lambda: save_settings('alerts', alerts_var.get(), show_alerts_settings)).pack(pady=10)

    def generate_recovery_keys():
        """Generate 10 recovery keys and store their hashes in the database."""
        global password_verified
        # Only require master password once for backup settings
        if not password_verified:
            if not require_master_password():
                return
            password_verified = True  # Set the flag after verifying the password

        # Generate 10 new recovery keys
        new_keys = [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(10)]
        hashed_recovery_keys = [hashlib.sha256(key.encode()).hexdigest() for key in new_keys]

        # Invalidate old keys and save new keys in the database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM recovery_keys")  # Clear old recovery keys
        for hashed_key in hashed_recovery_keys:
            cursor.execute("INSERT INTO recovery_keys (hashed_key) VALUES (?)", (hashed_key,))
        conn.commit()
        conn.close()

        # Display the new keys to the user
        for widget in keys_frame.winfo_children():
            widget.destroy()

        all_keys = ', '.join(new_keys)
        for i in range(0, len(new_keys), 2):
            key_frame = tk.Frame(keys_frame)
            key_frame.pack(pady=2)
            tk.Label(key_frame, text=new_keys[i]).pack(side=tk.LEFT, padx=5)
            if i + 1 < len(new_keys):
                tk.Label(key_frame, text=new_keys[i + 1]).pack(side=tk.LEFT, padx=5)

        # Add a button to copy all keys
        copy_all_button = tk.Button(keys_frame, text="Copy All", command=lambda: copy_value(all_keys))
        copy_all_button.pack(pady=10)

        messagebox.showinfo("Recovery Keys Generated", "New recovery keys have been successfully generated.")

    def show_recovery_keys_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
            
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add a button to generate new recovery keys
        tk.Label(center_frame, text="Recovery Keys Settings", font=("Helvetica", 16)).pack(pady=10)
        tk.Button(center_frame, text="Generate New Recovery Keys", command=generate_recovery_keys).pack(pady=10)
        
        global keys_frame
        keys_frame = tk.Frame(center_frame, bd=2, relief=tk.SUNKEN, padx=10, pady=10)
        keys_frame.pack(pady=10)
        
    def show_backup_settings(): 
        for widget in content_area.winfo_children():
            widget.destroy()
            
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(center_frame, text="Backup & Restore Settings", font=("Helvetica", 16, "bold"), bg="white").pack(pady=10)

        # Automatic Backup Settings
        auto_frame = tk.LabelFrame(center_frame, text="Automatic Backup", bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        auto_frame.pack(fill=tk.X, pady=10)

        backup_var = tk.BooleanVar(value=settings[2])
        tk.Checkbutton(auto_frame, text="Enable Automatic Backup", variable=backup_var, bg="white", font=("Helvetica", 11)).pack(anchor="w", pady=5)

        tk.Label(auto_frame, text="Backup Path:", font=("Helvetica", 11), bg="white").pack(anchor="w")
        
        path_frame = tk.Frame(auto_frame, bg="white")
        path_frame.pack(fill=tk.X, pady=5)
        
        backup_path_var = tk.StringVar(value=settings[6])
        entry = tk.Entry(path_frame, textvariable=backup_path_var, width=50)
        entry.pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(path_frame, text="Browse...", command=lambda: browse_backup_dir(backup_path_var)).pack(side=tk.LEFT)

        # Save Button
        tk.Button(center_frame, text="Save Settings", font=("Helvetica", 11, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5,
                command=lambda: (
                    save_settings("backup", int(backup_var.get()), show_backup_settings),
                    save_settings("backup_path", backup_path_var.get(), show_backup_settings)
                )).pack(pady=(10, 20))

        # Manual Backup
        manual_frame = tk.LabelFrame(center_frame, text="Manual Operations", bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        manual_frame.pack(fill=tk.X)

        tk.Label(manual_frame, text="Manual Backup:", font=("Helvetica", 11), bg="white").pack(anchor="w", pady=(0, 5))
        tk.Button(manual_frame, text="Backup Now", font=("Helvetica", 10), command=manual_backup).pack(anchor="w", pady=5)

        tk.Label(manual_frame, text="Manual Restore:", font=("Helvetica", 11), bg="white").pack(anchor="w", pady=(10, 5))
        tk.Button(manual_frame, text="Restore Now", font=("Helvetica", 10), command=manual_restore).pack(anchor="w", pady=5)

    def browse_backup_dir(path_var):
        directory = filedialog.askdirectory()
        if directory:
            path_var.set(directory)

    def manual_backup():
        backup_path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("Database Files", "*.db")])
        if backup_path:
            try:
                global password_verified
                # Only require master password once for backup settings
                if not password_verified:
                    if not require_master_password():
                        return
                    password_verified = True  # Set the flag after verifying the password
                shutil.copy(DB_FILE, backup_path)
                messagebox.showinfo("Backup Successful", f"Database backed up to {backup_path}")
            except Exception as e:
                messagebox.showerror("Backup Failed", f"Failed to backup database: {e}")

    def manual_restore():
        restore_path = filedialog.askopenfilename(filetypes=[("Database Files", "*.db")])
        if restore_path:
            try:
                global password_verified
                # Only require master password once for backup settings
                if not password_verified:
                    if not require_master_password():
                        return
                    password_verified = True  # Set the flag after verifying the password
                shutil.copy(restore_path, DB_FILE)
                messagebox.showinfo("Restore Successful", f"Database restored from {restore_path}")
            except Exception as e:
                messagebox.showerror("Restore Failed", f"Failed to restore database: {e}")

    def validate_integer(value_if_allowed):
        if value_if_allowed.isdigit() or value_if_allowed == "":
            return True
        else:
            return False

    def show_autologout_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
            
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(center_frame, text="Autologout Settings", font=("Helvetica", 16)).pack(pady=10)
        tk.Label(center_frame, text="Automatically lock the workspace after a period of inactivity (in seconds):", 
                font=("Helvetica", 12)).pack(pady=5)

        frame = tk.Frame(center_frame)
        frame.pack(pady=5)
        autologout_var = tk.IntVar(value=settings[3])
        validate_cmd = center_frame.register(validate_integer)
        tk.Spinbox(frame, from_=0, to=float('inf'), textvariable=autologout_var, width=5, 
                  validate='key', validatecommand=(validate_cmd, '%P')).pack(side=tk.LEFT)
        tk.Label(frame, text="seconds", font=("Helvetica", 12)).pack(side=tk.LEFT)

        def save_autologout():
            total_seconds = autologout_var.get()
            save_settings('autologout', total_seconds, show_autologout_settings)

        tk.Button(center_frame, text="Save", command=save_autologout).pack(pady=10)

    def show_clipboard_timer_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
            
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(center_frame, text="Clipboard Timer Settings", font=("Helvetica", 16)).pack(pady=10)
        tk.Label(center_frame, text="Automatically clear the clipboard after copying an item (in seconds):", 
                font=("Helvetica", 12)).pack(pady=5)

        frame = tk.Frame(center_frame)
        frame.pack(pady=5)
        seconds_var = tk.IntVar(value=settings[4])
        validate_cmd = center_frame.register(validate_integer)
        tk.Spinbox(frame, from_=0, to=float('inf'), textvariable=seconds_var, width=5, 
                  validate='key', validatecommand=(validate_cmd, '%P')).pack(side=tk.LEFT)
        tk.Label(frame, text="seconds", font=("Helvetica", 12)).pack(side=tk.LEFT)

        def save_clipboard_timer():
            total_seconds = seconds_var.get()
            save_settings('clipboard_timer', total_seconds, show_clipboard_timer_settings)

        tk.Button(center_frame, text="Save", command=save_clipboard_timer).pack(pady=10)

    # Load current settings
    global settings
    settings = load_settings()

    # Sidebar buttons
    for option in options:
        load_settings()
        if option == "MFA":
            button = tk.Button(sidebar, text=option, anchor="w", command=show_mfa_settings)
        elif option == "Alerts":
            button = tk.Button(sidebar, text=option, anchor="w", command=show_alerts_settings)
        elif option == "Recovery Keys":
            button = tk.Button(sidebar, text=option, anchor="w", command=show_recovery_keys_settings)
        elif option == "Backup & Restore":
            button = tk.Button(sidebar, text=option, anchor="w", command=show_backup_settings)
        elif option == "Autologout":
            button = tk.Button(sidebar, text=option, anchor="w", command=show_autologout_settings)
        elif option == "Clipboard Timer":
            button = tk.Button(sidebar, text=option, anchor="w", command=show_clipboard_timer_settings)
        button.pack(fill=tk.X, pady=2)

def automatic_backup():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT backup, backup_path FROM settings")
    enabled, path = cursor.fetchone()
    conn.close()
    
    if enabled:
        try:
            os.makedirs(path, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(path, f"backup_{timestamp}.db")
            shutil.copy(DB_FILE, backup_file)
            # Optional: Add backup rotation here
        except Exception as e:
            print(f"Backup failed: {str(e)}")

def schedule_backups():
    automatic_backup()
    # Run daily (86400 seconds)
    threading.Timer(86400, schedule_backups).start()


def load_settings():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM settings LIMIT 1")
    settings = cursor.fetchone()
    conn.close()
    if settings is None:
        # Initialize with default values if no settings are found
        settings = (False, True, False, 600, 10, '', './Backup')
    return settings

def increment_login_attempt():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT attempts FROM login_attempts LIMIT 1")
    current_attempts = cursor.fetchone()[0]
    new_attempts = current_attempts + 1
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if new_attempts >= 5:
        lockout_until = datetime.now() + timedelta(hours=1)
        cursor.execute("""UPDATE login_attempts 
                        SET attempts=?, last_attempt=?, lockout_until=?""",
                      (new_attempts, current_time, lockout_until.isoformat()))
    else:
        cursor.execute("""UPDATE login_attempts 
                        SET attempts=?, last_attempt=?""",
                      (new_attempts, current_time))
    
    conn.commit()
    conn.close()
    return new_attempts

def check_lockout_status():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT attempts, lockout_until FROM login_attempts LIMIT 1")
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return False, None
    
    attempts, lockout_until_str = row
    lockout_until = None
    if lockout_until_str:
        lockout_until = datetime.fromisoformat(lockout_until_str)
        if datetime.now() < lockout_until:
            conn.close()
            return True, lockout_until
        else:
            # Reset expired lockout
            cursor.execute("UPDATE login_attempts SET attempts=0, lockout_until=NULL")
            conn.commit()
    
    conn.close()
    return False, None

def reset_login_attempts():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE login_attempts SET attempts = 0, lockout_until = NULL")
    conn.commit()
    conn.close()

toaster = WindowsToaster("Password Manager")

def show_alert(title, message):
    settings = load_settings()
    alerts_enabled = settings[1]
    
    if alerts_enabled:
        # Create the toast notification
        toast = Toast()
        toast.text_fields = [title, message]
        toast.icon_path = "./Images/logo.ico"  # Default icon path
        toaster.show_toast(toast)

def require_master_password():
    # Ask for master password before proceeding
    entered_password = simpledialog.askstring("Master Password", "Re-enter the master password to proceed:", show="*")
    
    if entered_password is None:
        return False  # User cancelled
    
    if entered_password.strip() == "":
        messagebox.showwarning("Empty Password", "Password cannot be empty. Action cancelled.")
        return False

    if not verify_master_password(entered_password):
        messagebox.showerror("Invalid Password", "Incorrect master password. Action cancelled.")
        return False

    return True

# Function to handle mouse wheel scrolling
def on_mousewheel(event):
    if scroll_enabled:  # Only scroll if scrolling is enabled
        if event.delta:
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        else:
            # For Linux systems
            if event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")

# Track scroll state
scroll_enabled = True

# Modified function to bind/unbind mouse wheel
def bind_to_mousewheel(widget, bind=True):
    if bind:
        widget.bind("<MouseWheel>", on_mousewheel)
        widget.bind("<Button-4>", on_mousewheel)  # Linux scroll up
        widget.bind("<Button-5>", on_mousewheel)  # Linux scroll down
    else:
        widget.unbind("<MouseWheel>")
        widget.unbind("<Button-4>")
        widget.unbind("<Button-5>")


def toggle_scrollbar(show):
    """Show or hide the scrollbar based on the parameter"""
    if show:
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    else:
        scrollbar.pack_forget()
    canvas.configure(yscrollcommand=scrollbar.set if show else None)

# Function to toggle scrolling
def toggle_scrolling(enable):
    global scroll_enabled
    scroll_enabled = enable
    
    if enable:
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.configure(yscrollcommand=scrollbar.set)
        bind_to_mousewheel(root, True)
        bind_to_mousewheel(canvas, True)
        bind_to_mousewheel(main_frame, True)
    else:
        scrollbar.pack_forget()
        canvas.configure(yscrollcommand=None)
        bind_to_mousewheel(root, False)
        bind_to_mousewheel(canvas, False)
        bind_to_mousewheel(main_frame, False)
    
    # Reset the view to top when disabling
    if not enable:
        canvas.yview_moveto(0)

def main(): 
    global master_password

    # Check if the database exists
    if not os.path.exists(DB_FILE):
        master_password = initial_setup()
        if master_password is None:
            return  # Exit if user cancels

        # Setup the new database
        setup_database()
        store_master_password(master_password)
        schedule_backups()
        messagebox.showinfo("Success", "New password database created successfully!")

    # Check if master password is set
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM master_password")
    master_password_set = cursor.fetchone()[0] > 0
    conn.close()

    if not master_password_set:
        # First-time setup
        master_password = ask_initial_master_password()
        if master_password is None:
            return  # Exit if user cancels

        # Setup the new database
        setup_database()
        store_master_password(master_password)
        schedule_backups()
        messagebox.showinfo("Success", "New password database created successfully!")
    else:
        #Login
        def show_login_screen():
            login_root = tk.Tk()
            login_root.title("Login - Password Manager")
            login_root.geometry("550x300")
            login_root.configure(bg="#f0f0f0")
            
            # Set window icon
            login_root.iconbitmap(default="./Images/logo.ico")

            # Center the window
            window_width = 500
            window_height = 250
            screen_width = login_root.winfo_screenwidth()
            screen_height = login_root.winfo_screenheight()
            position_top = int(screen_height / 2 - window_height / 2)
            position_right = int(screen_width / 2 - window_width / 2)
            login_root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

            tk.Frame(login_root, bg="#f0f0f0", height=1).pack(fill="x")  # Top lighter line
            tk.Frame(login_root, bg="#cccccc", height=1).pack(fill="x")  # Bottom darker line

            def toggle_password(entry, toggle_button):
                if entry.cget('show') == '':
                    entry.config(show='*')
                    toggle_button.config(text='Show')
                else:
                    entry.config(show='')
                    toggle_button.config(text='Hide')

            var = tk.IntVar()
            var.set(1)  # Default to master password

            # Check lockout status first
            is_locked, until_time = check_lockout_status()
            
            # Create countdown label with improved style and AM/PM formatting
            countdown_label = tk.Label(
                login_root,
                text="",
                fg="red",
                bg="#f0f0f0",
                font=("Arial", 14),
                justify="center"  # Center-align multi-line text
            )

            def update_countdown(until_time):
                remaining = until_time - datetime.now()
                if remaining.total_seconds() <= 0:
                    countdown_label.pack_forget()
                    # Recreate login elements when lock expires
                    create_login_elements()
                    return
                mins, secs = divmod(int(remaining.total_seconds()), 60)
                formatted_until = until_time.strftime("%I:%M:%S %p")  # 12-hour format with AM/PM
                countdown_label.config(
                    text=(
                        f"⚠️ Account locked.\n"
                        f"⏳ Time remaining: {mins:02d}:{secs:02d}\n"
                        f"🔓 Unlock at: {formatted_until}"
                    )
                )
                login_root.after(1000, update_countdown, until_time)

            # Show lockout status if needed
            if is_locked:
                countdown_label.pack(pady=50)
                update_countdown(until_time)

            def update_row_state():
                if var.get() == 1:
                    master_password_entry.config(state='normal')
                    master_password_toggle.config(state='normal')
                    recovery_key_entry.config(state='disabled')
                    recovery_key_toggle.config(state='disabled')
                    recovery_key_cb.config(style="Disabled.TCheckbutton")
                    master_password_cb.config(style="TCheckbutton")
                elif var.get() == 2:
                    master_password_entry.config(state='disabled')
                    master_password_toggle.config(state='disabled')
                    recovery_key_entry.config(state='normal')
                    recovery_key_toggle.config(state='normal')
                    master_password_cb.config(style="Disabled.TCheckbutton")
                    recovery_key_cb.config(style="TCheckbutton")

            def on_login():
                # Check lockout status first
                is_locked, until_time = check_lockout_status()
                if is_locked:
                    login_frame.pack_forget()
                    countdown_label.pack()
                    update_countdown(until_time)
                    return

                if var.get() == 1:  # Master Password selected
                    master_password = master_password_entry.get()

                    if not master_password:  # Check if no master password is entered
                        messagebox.showerror("Error", "No master password entered.")
                        return

                    global key
                    key = verify_master_password(master_password)
                    if not key:
                        attempts = increment_login_attempt()
                        remaining_attempts = 5 - attempts

                        if remaining_attempts > 0:
                            messagebox.showerror(
                                "Invalid Password",
                                f"Invalid password. Remaining attempts: {remaining_attempts}"
                            )
                        else:
                            is_locked, until_time = check_lockout_status()
                            if is_locked:
                                formatted_until = until_time.strftime("%I:%M:%S %p")
                                message = f"Your account is locked until {formatted_until}."
                                show_alert("🔒 Account Locked", message)

                                login_frame.pack_forget()
                                countdown_label.pack_forget()  # Remove any previous countdown label
                                countdown_label.pack(pady=50, anchor="center")  # Repack the label to ensure it's centered
                                update_countdown(until_time)

                        master_password_entry.delete(0, tk.END)
                        return
                    else:
                        reset_login_attempts()

                elif var.get() == 2:  # Recovery Key selected
                    recovery_key = recovery_key_entry.get()

                    if not recovery_key:  # Check if no recovery key is entered
                        messagebox.showerror("Error", "No recovery key entered.")
                        return

                    hashed_recovery_keys = get_recovery_keys()
                    if verify_recovery_key(recovery_key, hashed_recovery_keys):
                        reset_login_attempts()
                        # Retrieve the stored key
                        conn = sqlite3.connect(DB_FILE)
                        cursor = conn.cursor()
                        cursor.execute("SELECT hashed_password FROM master_password")
                        result = cursor.fetchone()
                        conn.close()

                        if result:
                            stored_hashed_password = base64.b64decode(result[0])
                            key = stored_hashed_password[16:]
                            master_password = recovery_key
                        else:
                            messagebox.showerror("Error", "No master password found! Please enter a valid recovery key.")
                            login_root.destroy()
                            show_login_screen()
                            return
                    else:
                        attempts = increment_login_attempt()
                        remaining_attempts = 5 - attempts

                        if remaining_attempts > 0:
                            messagebox.showerror(
                                "Invalid Recovery Key",
                                f"Invalid recovery key. Remaining attempts: {remaining_attempts}"
                            )
                        else:
                            is_locked, until_time = check_lockout_status()
                            if is_locked:
                                formatted_until = until_time.strftime("%I:%M:%S %p")
                                message = f"Your account is locked until {formatted_until}."
                                show_alert("🔒 Account Locked", message)

                                login_frame.pack_forget()
                                countdown_label.pack_forget()  # Remove any previous countdown label
                                countdown_label.pack(pady=50, anchor="center")  # Repack the label to ensure it's centered
                                update_countdown(until_time)

                    recovery_key_entry.delete(0, tk.END)
                    return

                else:
                    messagebox.showerror("Invalid Choice", "Please select a valid option.")
                    return

                login_root.destroy()
                check_mfa_and_show_main_window()

            def create_login_elements():
                global master_password_entry, master_password_toggle
                global recovery_key_entry, recovery_key_toggle
                global master_password_cb, recovery_key_cb
                global login_frame 
                # Clear existing elements
                for widget in login_root.winfo_children():
                    if widget not in [countdown_label]:
                        widget.destroy()

                login_frame = tk.Frame(login_root, bg="#f0f0f0")
                login_frame.pack(pady=10)

                welcome_label = tk.Label(login_frame, text="Welcome! Please enter your master password or recovery key to proceed.", bg="#f0f0f0", font=("Helvetica", 10), fg="black")
                welcome_label.grid(row=0, column=0, columnspan=3, pady=10)

                bordered_frame = tk.Frame(login_frame, bg="#ffffff", bd=4, relief="groove")
                bordered_frame.grid(row=1, column=0, columnspan=3, pady=5, padx=5, sticky='ew')

                master_password_cb = ttk.Checkbutton(bordered_frame, text="Master Password", variable=var, onvalue=1, offvalue=0, style="TCheckbutton", command=update_row_state)
                master_password_cb.grid(row=0, column=0, sticky='w', padx=5, pady=5)
                master_password_entry = ttk.Entry(bordered_frame, show='*')
                master_password_entry.grid(row=0, column=1, padx=5, pady=5)
                master_password_toggle = ttk.Button(bordered_frame, text='Show', command=lambda: toggle_password(master_password_entry, master_password_toggle), style="TButton")
                master_password_toggle.grid(row=0, column=2, padx=5, pady=5)

                bordered_frame.grid_rowconfigure(1, minsize=20)  # Add vertical space

                recovery_key_cb = ttk.Checkbutton(bordered_frame, text="Recovery Key", variable=var, onvalue=2, offvalue=0, style="Disabled.TCheckbutton", command=update_row_state)
                recovery_key_cb.grid(row=2, column=0, sticky='w', padx=5, pady=5)
                recovery_key_entry = ttk.Entry(bordered_frame, show='*')
                recovery_key_entry.grid(row=2, column=1, padx=5, pady=5)
                recovery_key_entry.config(state='disabled')  # Initially disabled
                recovery_key_toggle = ttk.Button(bordered_frame, text='Show', command=lambda: toggle_password(recovery_key_entry, recovery_key_toggle), style="TButton")
                recovery_key_toggle.grid(row=2, column=2, padx=5, pady=5)
                recovery_key_toggle.config(state='disabled')  # Initially disabled

                # Add login button INSIDE the login frame
                login_button = ttk.Button(login_frame, text="Login", command=on_login, style="TButton")
                login_button.grid(row=3, column=0, columnspan=3, pady=20)

                style = ttk.Style()
                style.configure("TButton", font=("Helvetica", 10), foreground="black")
                style.configure("TCheckbutton", font=("Helvetica", 10), foreground="black", background="#ffffff")
                style.configure("Disabled.TCheckbutton", font=("Helvetica", 10), foreground="grey", background="#ffffff")

                # Return the frame reference
                return login_frame

            # Only create login elements if not locked
            if not is_locked:
                login_frame = create_login_elements()

            def on_enter(event):
                on_login()

            def on_closing():
                login_root.destroy()
                exit()

            login_root.bind('<Return>', on_enter)
            login_root.protocol("WM_DELETE_WINDOW", on_closing)

            login_root.after(100, login_root.focus_force)
            login_root.after(200, lambda: master_password_entry.focus())
            login_root.mainloop()

        def check_mfa_and_show_main_window():
            global settings
            settings = load_settings()
            if settings[0]:  # MFA is enabled
                encrypted_otp_secret = settings[5]
                if verify_otp(encrypted_otp_secret):
                    show_main_window()
                else:
                    show_login_screen()
            else:
                show_main_window()

        def show_main_window():
            global root, canvas, scrollbar, scroll_enabled
            root = tk.Tk()
            root.protocol("WM_DELETE_WINDOW", on_closing)
            root.title("Password Manager")

            # Window size
            width, height = 700, 550
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()

            # Calculate position to center window
            x = (screen_width - width) // 2
            y = (screen_height - height) // 2

            root.geometry(f"{width}x{height}+{x}+{y}")
            root.configure(bg="#f0f0f0") # Light background color

            # Set window icon
            root.iconbitmap(default="./Images/logo.ico")

            # Bind the reset_timer function to user activity events
            root.bind_all("<Button-1>", reset_timer)
            root.bind_all("<Key>", reset_timer)

            # Create a container frame that will hold both the nav bar and the scrollable content
            container = tk.Frame(root)
            container.pack(fill=tk.BOTH, expand=True)

            # Create a navigation bar as a Frame - packed in container, not root
            global nav_bar
            nav_bar = tk.Frame(container, bg="#333333", height=50)
            nav_bar.pack(side=tk.TOP, fill=tk.X)

            # Navigation options
            home_label = tk.Label(nav_bar, text="Home", fg="white", bg="#333333", font=("Arial", 12), cursor="hand2")
            home_label.pack(side=tk.LEFT, padx=10)
            home_label.bind("<Button-1>", lambda e: show_home_content())

            password_health_label = tk.Label(nav_bar, text="Password Health", fg="white", bg="#333333", font=("Arial", 12), cursor="hand2")
            password_health_label.pack(side=tk.LEFT, padx=10)
            password_health_label.bind("<Button-1>", lambda e: show_password_health_content())

            settings_label = tk.Label(nav_bar, text="Settings", fg="white", bg="#333333", font=("Arial", 12), cursor="hand2")
            settings_label.pack(side=tk.LEFT, padx=10)
            settings_label.bind("<Button-1>", lambda e: show_settings_content())

            # Create a main frame with scrollbar - packed in container, below nav_bar
            global main_frame
            main_container = tk.Frame(container, bg="#f0f0f0")
            main_container.pack(fill=tk.BOTH, expand=True)
            
            # Create a canvas for scrolling
            canvas = tk.Canvas(main_container, bg="#f0f0f0", highlightthickness=0)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Add scrollbar
            scrollbar = tk.Scrollbar(main_container, orient=tk.VERTICAL, command=canvas.yview)
            
            # Configure the canvas
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            
            # Create main frame inside the canvas
            main_frame = tk.Frame(canvas, bg="#f0f0f0")
            canvas.create_window((0, 0), window=main_frame, anchor="nw")

            # Add this after creating the main_frame
            def on_frame_configure(event):
                # Update the scrollregion to encompass the inner frame
                canvas.configure(scrollregion=canvas.bbox("all"))
                # Center the content if the frame is smaller than the canvas
                if main_frame.winfo_reqwidth() < canvas.winfo_width():
                    canvas.itemconfigure(1, width=canvas.winfo_width())  # 1 is the tag for the window

            main_frame.bind("<Configure>", on_frame_configure)

            # Initial bindings
            bind_to_mousewheel(root)
            bind_to_mousewheel(canvas)
            bind_to_mousewheel(main_frame)

            # Create a timer label
            global timer_label
            timer_label = tk.Label(main_frame, text="", bg="#f0f0f0")
            timer_label.pack()

            # Reset the last activity time after successful login
            reset_timer()

            schedule_backups()

            show_home_content()

            # Start checking for inactivity
            check_inactivity()

            # Start the main event loop
            root.mainloop()

        show_login_screen()

if __name__ == "__main__":
    main()