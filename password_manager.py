from io import StringIO
from pysqlitecipher import sqlitewrapper
import sqlite3
import signal
import tkinter as tk 
from tkinter import messagebox, simpledialog, filedialog, Menu
from tkinter import ttk
import math
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
import win32event
import win32api
import winerror

# Constants
DB_FILE = "passwords.db"

# Global variable to track the last activity time
last_activity_time = time.time()

# Add these global variables at the top
inactivity_after_id = None
password_health_after_id = None

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
    master_password = ask_initial_master_password(root)
    if not master_password:
        messagebox.showerror("Error", "Master password is required.")
        return None

    return master_password

# Ask for the master password for the first time
def ask_initial_master_password(root):
    while True:
        master_password = simpledialog.askstring("Master Password", "Enter the master password:\t\t\t", show="*")
        if master_password is None:  # User pressed "Cancel" or closed the dialog
            root.destroy()
        elif not master_password:
            messagebox.showwarning("Input Error", "Master password is required.")
        else:
            return master_password
        
# Ask for the master password
def ask_master_password(root):
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

def on_closing(root):
    global inactivity_after_id, password_health_after_id, current_countdown_id
    
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        # Cancel all scheduled tasks
        if inactivity_after_id:
            root.after_cancel(inactivity_after_id)
        if password_health_after_id:
            root.after_cancel(password_health_after_id)
        if current_countdown_id:
            root.after_cancel(current_countdown_id)
        
        # Proper termination sequence
        root.quit()
        root.destroy()
        
        # Force exit all threads
        os._exit(0)  # Use instead of sys.exit()

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
    global sqlite_obj
    
    """Hash and store the master password using sqlitewrapper"""
    # Generate salt and derive key
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    
    # Store salt + key together
    hashed_password = base64.b64encode(salt + key).decode()
    
    # Delete any existing master passwords
    # First get all IDs in the table
    result = sqlite_obj.getDataFromTable("master_password", raiseConversionError=True, omitID=False)
    
    if result[1]:  # If there are rows in the table
        # Delete each row by ID
        for row in result[1]:  # result[1] contains the actual data
            id_value = int(row[0])
            sqlite_obj.deleteDataInTable("master_password", id_value, commit=True, updateId=True)
    
    # Insert the new master password
    sqlite_obj.insertIntoTable("master_password", [hashed_password], commit=True)

def verify_master_password(entered_password):
    """Verify if the entered master password is correct and return the key."""
    global sqlite_obj

    # Fetch the hashed password from the "master_password" table
    result = sqlite_obj.getDataFromTable("master_password", raiseConversionError=True, omitID=False)
    
    if not result[1]:  # No master password set
        return None

    stored_hashed_password = result[1][0][1]  # The first row (0), second column (1) is the hashed password

    # Decode the base64-encoded hashed password
    try:
        stored_hashed_password = base64.b64decode(stored_hashed_password)
    except Exception as e:
        print(f"Error decoding hashed password: {e}")
        return None

    # Extract the salt and stored key
    salt = stored_hashed_password[:16]  # Extract the salt
    stored_key = stored_hashed_password[16:]  # Extract the stored key

    # Derive the key from the entered password
    entered_key = derive_key(entered_password, salt)

    if entered_key == stored_key:
        return entered_key  # Return the actual key if the password is correct
    return None  # Return None if the password is incorrect

# Get recovery keys from the database
def get_recovery_keys():
    global sqlite_obj
    """Retrieve the hashed recovery keys from the database."""
    try:
        # Fetch hashed recovery keys from the database using sqlite_obj
        result = sqlite_obj.getDataFromTable(
            "recovery_keys", 
            raiseConversionError=True,
            omitID=False
        )
        
        # Extract the hashed recovery keys from the result
        if result[1]:
            hashed_recovery_keys = [row[1] for row in result[1]]
        else:
            hashed_recovery_keys = []
        return hashed_recovery_keys

    except Exception as e:
        print(f"Error fetching recovery keys: {e}")
        return []
    
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
    """Initialize the encrypted database with the database password"""
    global sqlite_obj

    """Create tables using pysqlitecipher"""
    # Master password table
    col_list = [
        # ["id", "INT PRIMARY KEY AUTOINCREMENT"],
        ["hashed_password", "TEXT"]
    ]
    sqlite_obj.createTable("master_password", col_list, makeSecure=True, commit=True)

    # Recovery keys table
    col_list = [
        ["hashed_key", "TEXT"]
    ]
    sqlite_obj.createTable("recovery_keys", col_list, makeSecure=True, commit=True)

    # Insert default keys if empty
    result = sqlite_obj.getDataFromTable("recovery_keys", raiseConversionError=False, omitID=False)
    
    if not result[1]:  # If there are no rows in the table
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )    
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )        
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )        
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )        
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )        
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )        
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )       
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )        
        sqlite_obj.insertIntoTable("recovery_keys", [""],
            commit=True
        )

    # Passwords table
    col_list = [
        ["platformName", "TEXT"],
        ["platformLabel", "TEXT"],
        ["platformUser", "TEXT"],
        ["encryptedPassword", "TEXT"],  # Will be automatically encrypted
        ["platformURL", "TEXT"],
        ["platformNote", "TEXT"],
        ["createdAt", "TEXT"],
        ["updatedAt", "TEXT"],
        ["aes_bits", "INT"],
        ["mp_reprompt", "BOOLEAN"],
        ["isFavourite", "BOOLEAN"],
        ["isDeleted", "BOOLEAN"],
        ["deletedAt", "TEXT"]
    ]
    sqlite_obj.createTable("passwords", col_list, makeSecure=True, commit=True)

    # Password criteria table
    col_list = [
        ["length", "INTEGER"],
        ["include_uppercase", "BOOLEAN"],
        ["include_lowercase", "BOOLEAN"],
        ["include_digits", "BOOLEAN"],
        ["include_minus", "BOOLEAN"],
        ["include_underline", "BOOLEAN"],
        ["include_space", "BOOLEAN"],
        ["include_special", "BOOLEAN"],
        ["include_brackets", "BOOLEAN"],
        ["include_latin1", "BOOLEAN"]
    ]
    sqlite_obj.createTable("password_criteria", col_list, makeSecure=True, commit=True)

    # Insert default criteria if empty
    result = sqlite_obj.getDataFromTable("password_criteria", raiseConversionError=False, omitID=True)
    
    if not result[1]:  # If there are no rows in the table
        sqlite_obj.insertIntoTable("password_criteria", [12, True, True, True, True, True, False, True, True, False],
            commit=True
        )

    # Settings table
    col_list = [
        ["mfa", "BOOLEAN"],
        ["alerts", "BOOLEAN"],
        ["backup", "BOOLEAN"],
        ["autologout", "INTEGER"],
        ["clipboard_timer", "INTEGER"],
        ["otp_secret", "TEXT"],
        ["backup_path", "TEXT"]
    ]
    sqlite_obj.createTable("settings", col_list, makeSecure=True, commit=True)
    
    # Insert default settings if empty
    result = sqlite_obj.getDataFromTable("settings", raiseConversionError=False, omitID=True)
    
    if not result[1]:  # If there are no rows in the table
        sqlite_obj.insertIntoTable(
            "settings",
            [False, True, False, 3500, 10, "", "./Backup"],
            commit=True
        )

    # Attack settings table
    col_list = [
        ["dictionary_path", "TEXT"],
        ["rainbow_table_path", "TEXT"],
        ["guess_per_sec", "INTEGER"],
        ["thread_count", "INTEGER"],
        ["guess_per_sec_threshold", "INTEGER"],
        ["default_dictionary_path", "TEXT"],
        ["default_rainbow_table_path", "TEXT"],
        ["default_guess_per_sec", "INTEGER"],
        ["default_thread_count", "INTEGER"],
        ["default_guess_per_sec_threshold", "INTEGER"]
    ]
    sqlite_obj.createTable("attack_settings", col_list, makeSecure=True, commit=True)
    
    # Insert default attack settings if empty
    result = sqlite_obj.getDataFromTable("attack_settings", raiseConversionError=False, omitID=True)
    
    if not result[1]:  # If there are no rows in the table
        sqlite_obj.insertIntoTable(
            "attack_settings",
            ["./Dictionary", "./Rainbow_Table", 3000000, 1, 10000000, 
             "./Dictionary", "./Rainbow_Table", 3000000, 1, 10000000],
            commit=True
        )

    # Rainbow crack time table
    col_list = [
        ["length", "INTEGER PRIMARY KEY"],
        ["base_time", "REAL"]
    ]
    sqlite_obj.createTable("rainbow_crack_time", col_list, makeSecure=True, commit=True)
    
    # Insert default attack settings if empty
    result = sqlite_obj.getDataFromTable("rainbow_crack_time", raiseConversionError=False, omitID=True)
    
    if not result[1]:  # If there are no rows in the table
        sqlite_obj.insertIntoTable(
            "rainbow_crack_time",
            [1, 323.77],
            commit=True
        )
        sqlite_obj.insertIntoTable(
            "rainbow_crack_time",
            [2, 388.49],
            commit=True
        )        
        sqlite_obj.insertIntoTable(
            "rainbow_crack_time",
            [3, 237.52],
            commit=True
        )        
        sqlite_obj.insertIntoTable(
            "rainbow_crack_time",
            [4, 268.34],
            commit=True
        )       
        sqlite_obj.insertIntoTable(
            "rainbow_crack_time",
            [5, 1748.55],
            commit=True
        )        
        sqlite_obj.insertIntoTable(
            "rainbow_crack_time",
            [6, 1750],
            commit=True
        )
        sqlite_obj.insertIntoTable(
            "rainbow_crack_time",
            [7, 1750],
            commit=True
        )

    # Login attempts table
    col_list = [
        ["attempts", "INTEGER"],
        ["last_attempt", "TIMESTAMP"],
        ["lockout_until", "TIMESTAMP"]
    ]
    sqlite_obj.createTable("login_attempts", col_list, makeSecure=True, commit=True)
    
    # Initialize login attempts if empty
    result = sqlite_obj.getDataFromTable("login_attempts", raiseConversionError=False, omitID=True)
    
    if not result[1]:  # If there are no rows in the table
        sqlite_obj.insertIntoTable("login_attempts", [0, None, None], commit=True)

def reset_timer(event=None):
    global last_activity_time
    last_activity_time = time.time()

def check_inactivity(root):
    global last_activity_time, inactivity_after_id
    current_time = time.time()
    inactivity_period = current_time - last_activity_time

    if inactivity_period > int(settings[3]):
        lock_system(root)

    # Store the after ID
    inactivity_after_id = root.after(1000, lambda: check_inactivity(root))

def lock_system(root):
    # Destroy existing main window if it exists
    if root:
        root.destroy()
        root = None

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

def open_password_generation_form(parent_window):
    global sqlite_obj
    if hasattr(open_password_generation_form, "password_config_window") and \
       open_password_generation_form.password_config_window.winfo_exists():
        open_password_generation_form.password_config_window.lift()
        open_password_generation_form.password_config_window.focus()
        return

    password_config_window = tk.Toplevel(parent_window)
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

    # Fetch password criteria using sqlite_obj
    try:
        # Fetch the latest criteria from the database using sqlite_obj
        result = sqlite_obj.getDataFromTable(
            "password_criteria",
            raiseConversionError=True,
            omitID=True
        )

        # Extract values if found, otherwise use default values
        if result[1]:
            criteria = result[1][0]  # Get the first row
            length = criteria[0]
            include_uppercase = criteria[1]
            include_lowercase = criteria[2]
            include_digits = criteria[3]
            include_minus = criteria[4]
            include_underline = criteria[5]
            include_space = criteria[6]
            include_special = criteria[7]
            include_brackets = criteria[8]
            include_latin1 = criteria[9]
        else:
            # Default values if no criteria found
            length = 12
            include_uppercase = True
            include_lowercase = True
            include_digits = True
            include_minus = True
            include_underline = True
            include_space = False
            include_special = True
            include_brackets = True
            include_latin1 = False

    except Exception as e:
        print(f"Error fetching password criteria: {e}")
        # Default values in case of an error
        length = 12
        include_uppercase = True
        include_lowercase = True
        include_digits = True
        include_minus = True
        include_underline = True
        include_space = False
        include_special = True
        include_brackets = True
        include_latin1 = False

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

            # Update password criteria using sqlite_obj
            try:
                result = sqlite_obj.getDataFromTable("password_criteria", raiseConversionError = True , omitID = False)
                id_value = result[1][0][0]

                # Perform the update using sqlite_objted
                sqlite_obj.updateInTable("password_criteria", id_value, "length", values[0], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_uppercase", values[1], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_lowercase", values[2], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_digits", values[3], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_minus", values[4], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_underline", values[5], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_space", values[6], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_special", values[7], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_brackets", values[8], commit=True, raiseError=True)
                sqlite_obj.updateInTable("password_criteria", id_value, "include_latin1", values[9], commit=True, raiseError=True)
                messagebox.showinfo("Success", "Password criteria saved successfully!")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to save password criteria: {e}")


        except ValueError as ve:
            messagebox.showerror("Validation Error", str(ve))
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))

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
            result = sqlite_obj.getDataFromTable("password_criteria", raiseConversionError = True , omitID = False)
            id_value = result[1][0][0]

            # Perform the update using sqlite_objted
            sqlite_obj.updateInTable("password_criteria", id_value, "length", 12, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_uppercase", True, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_lowercase", True, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_digits", True, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_minus", True, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_underline", True, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_space", False, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_special", True, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_brackets", True, commit=True, raiseError=True)
            sqlite_obj.updateInTable("password_criteria", id_value, "include_latin1", False, commit=True, raiseError=True)
        
            messagebox.showinfo("Reset", "Password criteria reset to default.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

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
    global sqlite_obj
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
    try:
        # Fetch the latest password criteria from the database
        result = sqlite_obj.getDataFromTable(
            "password_criteria", 
            raiseConversionError=True,
            omitID=True
        )
        
        if result[1]:
            criteria = result[1][0]  # Get the first (and only) row
            length, include_uppercase, include_lowercase, include_digits, include_minus, \
            include_underline, include_space, include_special, include_brackets, include_latin1 = criteria[0:]
        else:
            messagebox.showwarning("Criteria Error", "No password generation criteria found.", parent=parent_window)
            return

    except Exception as e:
        messagebox.showerror("Database Error", f"Failed to load password criteria: {e}", parent=parent_window)
        return

    # Build character set
    characters = ""
    if include_uppercase == 'True':  characters += string.ascii_uppercase
    if include_lowercase == 'True':  characters += string.ascii_lowercase
    if include_digits == 'True':     characters += string.digits
    if include_minus == 'True':      characters += "-"
    if include_underline == 'True':  characters += "_"
    if include_space == 'True':      characters += " "
    if include_special == 'True':    characters += "!\"#$%&'*+,-./:;=?@\\^_`|~"
    if include_brackets == 'True':   characters += "[]{}()<>"
    if include_latin1 == 'True':     characters += ''.join(chr(i) for i in range(160, 256))

    if not characters:
        messagebox.showwarning("Selection Error", "Please select at least one character type.", parent=parent_window)
        return

    max_attempts = 1000  # Limit attempts to avoid infinite loop
    for _ in range(max_attempts):
        new_password = generate_password(int(length), characters)
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
    global sqlite_obj
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

    # Load current settings using sqlite_obj
    try:
        # Fetch the settings from the database using sqlite_obj
        result = sqlite_obj.getDataFromTable(
            "attack_settings", 
            raiseConversionError=True,
            omitID=True
        )

        if result[1]:
            # Extract the settings values from the result
            current_guess_per_sec = result[1][0][2]
            current_thread_count  = result[1][0][3] 
            current_threshold = result[1][0][4] 
            default_guess_per_sec = result[1][0][7]
            default_thread_count = result[1][0][8]
            default_threshold = result[1][0][9]
        else:
            # Set default values if no settings are found
            current_guess_per_sec = default_guess_per_sec = 3000000
            current_thread_count = default_thread_count = 1
            current_threshold = default_threshold = 10000000

    except Exception as e:
        print(f"Error fetching attack settings: {e}")
        # Set default values in case of an error
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
            # Reset attack settings
            try:
                result = sqlite_obj.getDataFromTable("attack_settings", raiseConversionError = True , omitID = False)
                id = result[1][0][0]

                sqlite_obj.updateInTable("attack_settings" , id , "guess_per_sec" , default_guess_per_sec , commit = True , raiseError = True)
                sqlite_obj.updateInTable("attack_settings" , id , "thread_count" , default_thread_count , commit = True , raiseError = True)
                sqlite_obj.updateInTable("attack_settings" , id , "guess_per_sec_threshold" , default_threshold , commit = True , raiseError = True)
            except Exception as e:
                print(f"Error resetting attack settings: {e}")

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

            def brute_force(limit, chunk, pwd, attack_stop_flag):
                for guesses, g in enumerate(itertools.product(chunk, repeat=len(pwd)), 1):
                    if attack_stop_flag and attack_stop_flag.is_set():
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

                # Update attack settings
                try:
                    result = sqlite_obj.getDataFromTable("attack_settings", raiseConversionError = True , omitID = False)
                    id = result[1][0][0]

                    sqlite_obj.updateInTable("attack_settings" , id , "guess_per_sec" , guess_per_sec , commit = True , raiseError = True)
                    sqlite_obj.updateInTable("attack_settings" , id , "thread_count" , thread_count , commit = True , raiseError = True)
                    sqlite_obj.updateInTable("attack_settings" , id , "guess_per_sec_threshold" , threshold , commit = True , raiseError = True)
                except Exception as e:
                    print(f"Error updating attack settings: {e}")

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
            # Check if the directory exists and contains .rti2 files
            if not os.path.exists(rainbow_path) or not any(file.endswith('.rti2') for file in os.listdir(rainbow_path)):
                results["Rainbow Table"] = "No valid rainbow table (.rti2) files found in the specified directory."
            else:
                # Continue with the rainbow table time estimation logic
                rainbow_result = sqlite_obj.getDataFromTable(
                    "rainbow_crack_time", 
                    raiseConversionError=True,
                    omitID=True
                )

                base_time = None
                if rainbow_result[1]:
                    for row in rainbow_result[1]:
                        if int(row[0]) == len(password):  # First column is length
                            base_time = row[1]  # Second column is base_time
                            break

                if base_time is None:
                    results["Rainbow Table"] = "No estimate for this password length"
                else:
                    # Get thread_count from attack_settings
                    attack_result = sqlite_obj.getDataFromTable(
                        "attack_settings",
                        raiseConversionError=True,
                        omitID=True
                    )

                    threads = 1
                    if attack_result[1]:
                        try:
                            # Thread count is 4th column (index 3)
                            threads = max(1, int(attack_result[1][0][3]))
                        except (TypeError, ValueError):
                            pass  # Keep default value if conversion fails

                    adjusted_time = base_time / threads
                    crack_time = format_time(adjusted_time)
                    results["Rainbow Table"] = crack_time

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
    global sqlite_obj
    """Open file dialog to select dictionary path and save it to the database."""
    
    # Open the file dialog to select a folder
    path = filedialog.askdirectory(title="Select Dictionary Folder")
    
    if path:
        # Update the entry widget with the selected path
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)
        window.lift()

        # Save the selected path to the database
        try:
            result = sqlite_obj.getDataFromTable(
                "attack_settings", 
                raiseConversionError=True,
                omitID=False
            )
            
            if result[1]:
                id = result[1][0][0]  # Get the ID from the query result
                
                # Update the dictionary path in the database
                sqlite_obj.updateInTable("attack_settings", id, "dictionary_path", path, commit=True, raiseError=True)
                messagebox.showinfo("Success", "Dictionary path saved successfully.")
            else:
                messagebox.showwarning("Warning", "No dictionary path found in the database.")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving dictionary path: {e}")

def browse_rainbow_path(entry_widget, window):
    global sqlite_obj
    """Open file dialog to select rainbow table path and save it to the database, ensuring the folder contains .rti2 files."""
    
    # Open the file dialog to select a folder
    path = filedialog.askdirectory(title="Select Rainbow Table Folder")
    
    if path:
        # Check if the folder contains any .rti2 files
        if not any(file.endswith(".rti2") for file in os.listdir(path)):
            # Show a message box if no .rti2 files are found
            messagebox.showerror("Invalid Folder", "The selected folder does not contain any .rti2 files.")
            return  # Exit if no .rti2 files are found

        # Update the entry widget with the selected path
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)
        window.lift()
        
        # Save the selected path to the database
        try:
            result = sqlite_obj.getDataFromTable(
                "attack_settings", 
                raiseConversionError=True,
                omitID=False
            )
            
            if result[1]:
                id = result[1][0][0]  # Get the ID from the query result
                
                # Update the rainbow table path in the database
                sqlite_obj.updateInTable("attack_settings", id, "rainbow_table_path", path, commit=True, raiseError=True)
                messagebox.showinfo("Success", "Rainbow table path saved successfully.")
            else:
                messagebox.showwarning("Warning", "No rainbow table path found in the database.")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving rainbow table path: {e}")

def refresh_form(parent_window, dict_path_entry, rainbow_path_entry, ui_context):
    global sqlite_obj
    """Reloads the dictionary and rainbow table paths."""
    try:
        # Fetch the dictionary and rainbow table paths from the database
        result = sqlite_obj.getDataFromTable(
            "attack_settings", 
            raiseConversionError=True,
            omitID=True
        )
        
        # Refresh the path values
        dict_path_entry.delete(0, tk.END)
        rainbow_path_entry.delete(0, tk.END)
        
        if result[1]:
            dict_path_entry.insert(0, result[1][0][0])  # First column: dictionary_path
            rainbow_path_entry.insert(0, result[1][0][1])  # Second column: rainbow_table_path
        else:
            dict_path_entry.insert(0, "")  # Default empty if no result
            rainbow_path_entry.insert(0, "")  # Default empty if no result
        
        update_password_strength(ui_context)
        parent_window.lift()
        parent_window.focus()
    
    except Exception as e:
        print(f"Error fetching paths for refresh: {e}")

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
    global sqlite_obj
    if hasattr(open_attack_window, "attack_win") and \
    open_attack_window.attack_win.winfo_exists():
        open_attack_window.attack_win.lift()
        open_attack_window.attack_win.focus()
        return

    # Get attack settings from database
    try:
        # Fetch the settings from the database using
        result = sqlite_obj.getDataFromTable(
            "attack_settings", 
            raiseConversionError=True,
            omitID=True
        )

        if result[1]:
            # Extract the settings values from the result
            dict_path = result[1][0][0]
            rainbow_path = result[1][0][1]
            guess_per_sec = result[1][0][2]
            thread_count  = result[1][0][3] 
            guess_per_sec_threshold = result[1][0][4] 
        else:
            print("No attack settings found in the database. Using defaults.")
            dict_path = "./Dictionary"  # Default dictionary path
            rainbow_path = "./Rainbow_Table"  # Default rainbow table path
            guess_per_sec = 3000000  # Default guess rate
            thread_count = 1  # Default thread count
            guess_per_sec_threshold = 10000000  # Default threshold
                    
    except Exception as e:
        print(f"Error fetching attack settings: {e}")
        dict_path = "./Dictionary"  # Default dictionary path
        rainbow_path = "./Rainbow_Table"  # Default rainbow table path
        guess_per_sec = 3000000  # Default guess rate
        thread_count = 1  # Default thread count
        guess_per_sec_threshold = 10000000  # Default threshold

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

    def stop_attack(attack_stop_flag):
        attack_stop_flag.set()
        attack_started_flag.clear() 
        cli_output.config(state=tk.NORMAL)
        cli_output.insert(tk.END, "🛑 Attack stopped by user\n")
        cli_output.see(tk.END)
        cli_output.config(state=tk.DISABLED)

    def start_attack(method, threads_str, password, aes_bit, dict_path, rainbow_path, cli, start_button, stop_button, attack_stop_flag):
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
        attack_stop_flag.clear()
        attack_started_flag.set()
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

        attack_thread = threading.Thread(
            target=simulate_attack,
            args=(method, threads, password, dict_path, rainbow_path, message_queue, start_button, stop_button, attack_stop_flag),
            daemon=True
        )
        attack_thread.start()

    def simulate_attack(method, threads, password, dict_path, rainbow_path, queue, start_button, stop_button, attack_stop_flag): 
        def post(message):
            queue.put(message)

        # 💬 Show these first
        post(f"🚀 Starting {method} attack on: '{password}'")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        post(f"⏰ Start time: {current_time}")
        post(f"🔧 Using {threads} threads")

        def brute_force_worker(start_chars, charset, target, found_event, attempt_counter, attack_stop_flag, length_status_callback):
            max_len = len(target) + 1
            for length in range(1, max_len + 1):
                length_status_callback(length)
                for first in start_chars:
                    for combo in itertools.product(charset, repeat=length - 1):
                        if found_event.is_set() or attack_stop_flag.is_set():
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
                    args=(start_chars, charset, password, found_event, attempt_counter, attack_stop_flag, length_status_callback),
                    daemon=True
                )
                workers.append(t)
                t.start()

            for t in workers:
                t.join()

            if not found_event.is_set() and not attack_stop_flag.is_set():
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
            attempt_counter = [0]  # reuse outer attack_stop_flag — do NOT redefine

            def aes_brute_worker(start_chars, charset, key_length, found_event, attempt_counter, attack_stop_flag):
                for first_char in start_chars:
                    for tail in itertools.product(charset, repeat=key_length - 1):
                        if found_event.is_set() or attack_stop_flag.is_set():
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
                    args=(start_chars, charset, key_length, found_event, attempt_counter, attack_stop_flag),
                    daemon=True
                )
                workers.append(t)
                t.start()

            for t in workers:
                t.join()

            if not found_event.is_set() and not attack_stop_flag.is_set():
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
                    if found_event.is_set() or attack_stop_flag.is_set():
                        return

                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            display_path = os.path.relpath(file_path, dict_path) if os.path.isdir(dict_path) else os.path.basename(file_path)
                            with lock:
                                post(f"📄 Scanning dictionary file: {display_path}")

                            for line_num, line in enumerate(f, 1):
                                if found_event.is_set() or attack_stop_flag.is_set():
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
                if not attack_stop_flag.is_set():
                    post(f"❌ Password not found in any dictionary file (searched {dict_size[0]} words)")
                    post("⚡ Proceeding with brute-force excluding tried words...")

                    # Brute-force but skip tried_set
                    charset = string.ascii_letters + string.digits + string.punctuation
                    found_event = threading.Event()

                    def filtered_brute_force_worker(start_chars, charset, target, found_event, attempt_counter, attack_stop_flag):
                        max_len = len(target) + 1
                        for length in range(1, max_len + 1):
                            for first in start_chars:
                                for combo in itertools.product(charset, repeat=length - 1):
                                    if found_event.is_set() or attack_stop_flag.is_set():
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
                            args=(start_chars, charset, password, found_event, attempt_counter, attack_stop_flag),
                            daemon=True
                        )
                        workers.append(t)
                        t.start()

                    for t in workers:
                        t.join()

                    if not found_event.is_set() and not attack_stop_flag.is_set():
                        post("❌ Password not found even after brute-force")

        else:  # Rainbow Table
            try:
                # Check if the rainbow table path contains .rti2 files
                if not os.path.exists(rainbow_path) or not any(file.endswith('.rti2') for file in os.listdir(rainbow_path)):
                    post("❌ No valid rainbow table (.rti2) files found in the specified directory.")
                    attack_stop_flag.set()
                    attack_started_flag.clear() 
                    cli_output.config(state=tk.NORMAL)
                    cli_output.insert(tk.END, "🛑 Attack stopped due to the error above.\n\n")
                    cli_output.see(tk.END)
                    cli_output.config(state=tk.DISABLED)
                    attack_win.after(0, lambda: [
                        start_btn.config(state=tk.NORMAL),
                        stop_btn.config(state=tk.DISABLED),
                        attack_started_flag.clear()
                    ])
                    return  # Stop the attack immediately
                
                # Execute command in the Crack_Rainbow_Table directory  
                crack_dir = "./Crack_Rainbow_Table"
                rcracki_mt_path = os.path.join(crack_dir, "rcracki_mt.exe")  # Specify the executable file path

                # Check if the directory exists and if the rcracki_mt.exe file is present
                if not os.path.exists(crack_dir) or not os.path.exists(rcracki_mt_path):
                    if not os.path.exists(crack_dir):
                        post(f"❌ Directory not found: {crack_dir}")
                    if not os.path.exists(rcracki_mt_path):
                        post(f"❌ rcracki_mt.exe not found in the directory: {crack_dir}")
                    
                    attack_stop_flag.set()
                    attack_started_flag.clear()
                    cli_output.config(state=tk.NORMAL)
                    cli_output.insert(tk.END, "🛑 Attack stopped due to missing directory or executable.\n\n")
                    cli_output.see(tk.END)
                    cli_output.config(state=tk.DISABLED)
                    
                    attack_win.after(0, lambda: [
                        start_btn.config(state=tk.NORMAL),
                        stop_btn.config(state=tk.DISABLED),
                        attack_started_flag.clear()
                    ])
                    return

                # Generate MD5 hash of the password
                post("🔨 Generating MD5 hash...")
                md5_hash = hashlib.md5(password.encode()).hexdigest()
                post(f"🔑 MD5 hash: {md5_hash}")

                # Prepare rcracki_mt command
                command = f"rcracki_mt -h {md5_hash} -t {threads} {rainbow_path}"
                post(f"🖥️ Executing: {command}")
                
                # Cross-platform solution for executing command
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
                    if attack_stop_flag.is_set():
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
                if not attack_stop_flag.is_set():  # Only check if not stopped by user
                    if return_code == 0:
                        post("✅ Password found in rainbow table!")
                    else:
                        post("❌ Password not found in rainbow tables")
                else:
                    post("🔇 All Processes Terminated")

            except Exception as e:
                post(f"⚠️ Error during rainbow table attack: {str(e)}")

        elapsed_time = time.time() - start_time
        if not attack_stop_flag.is_set():
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
    
# Function to show context menu for home items
def show_item_context_menu(event, password_id, root):
    global selected_password_id, sqlite_obj
    selected_password_id = password_id
    
    # Find the item frame to select
    for widget in items_container.winfo_children():
        if hasattr(widget, 'password_id') and widget.password_id == password_id:
            select_item(None, password_id, widget, root)
            break
    
    # Check if item is in trash
    try:
        # Fetch the 'isDeleted' status from the 'passwords' table using sqlite_obj
        result = sqlite_obj.getDataFromTable(
            "passwords", 
            raiseConversionError=True,
            omitID=False
        )
        
        if result[1]:
            for row in result[1]:
                if int(row[0]) == password_id:
                    # Retrieve the 'isDeleted' value from the result
                    is_deleted = row[12]
        else:
            is_deleted = False  # Default to False if no result found
    except Exception as e:
        print(f"Error fetching item status: {e}")
        is_deleted = False  # Default to False if there's an error

    # Create context menu based on trash status
    context_menu = Menu(root, tearoff=0)
    
    # Always include copy commands
    context_menu.add_command(label="Copy Platform", command=lambda: copy_item_value('platform', root))
    context_menu.add_command(label="Copy Label", command=lambda: copy_item_value('label', root))
    context_menu.add_command(label="Copy Username", command=lambda: copy_item_value('username', root))
    context_menu.add_command(label="Copy Password", command=lambda: copy_item_value('password', root))
    context_menu.add_command(label="Copy URL", command=lambda: copy_item_value('url', root))
    context_menu.add_command(label="Copy Notes", command=lambda: copy_item_value('notes', root))
    context_menu.add_separator()
    
    if is_deleted == 'True':
        # In trash: show restore and permanent delete
        context_menu.add_command(label="Restore Entry", command=lambda: restore_selected_home_entry(root))
        context_menu.add_command(label="Delete Permanently", command=lambda: delete_permanently_selected_home_entry(root))
    else:
        # Not in trash: show regular delete
        context_menu.add_command(label="Delete Entry", command=lambda: delete_selected_home_entry(root))
    
    context_menu.post(event.x_root, event.y_root)

def restore_selected_home_entry(root):
    global selected_password_id, sqlite_obj
    if selected_password_id is None:
        messagebox.showinfo("Info", "No item selected")
        return
    
    # Restore entry
    try:
        # Perform the update using sqlite_obj
        sqlite_obj.updateInTable("passwords", selected_password_id , "isDeleted" , 'False' , commit = True , raiseError = True)
        sqlite_obj.updateInTable("passwords", selected_password_id , "deletedAt" , '' , commit = True , raiseError = True)
        messagebox.showinfo("Success", "Entry restored")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to restore entry: {e}")

    # Refresh the view
    selected_password_id = None
    show_home_content(root)

def delete_permanently_selected_home_entry(root):
    global selected_password_id, sqlite_obj
    if selected_password_id is None:
        messagebox.showinfo("Info", "No item selected")
        return

    # Confirm permanent deletion
    if not messagebox.askyesno("Confirm Permanent Deletion", 
                              "Are you sure you want to permanently delete this entry?\nThis action cannot be undone."):
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        sqlite_obj.deleteDataInTable("passwords", selected_password_id , commit = True , raiseError = True , updateId = True)
        messagebox.showinfo("Success", "Entry permanently deleted")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete entry: {e}")

    # Refresh the view
    selected_password_id = None
    show_home_content(root)

# Function to copy item values using sqlite_obj
def copy_item_value(field, root):
    global selected_password_id, sqlite_obj
    if selected_password_id is None:
        messagebox.showinfo("Info", "No item selected")
        return

    try:
        # Fetch the item details from the database using sqlite_obj
        result = sqlite_obj.getDataFromTable(
            "passwords", 
            raiseConversionError=True,
            omitID=False
        )

        if result[1]:
            for row in result[1]:
                print(row[0])
                if int(row[0]) == selected_password_id:
                    # Retrieve the item details
                    detail = row
                    break
            # Extract the values from the detail
            platform = detail[1]
            label = detail[2]
            username = detail[3]
            encrypted_pw = detail[4]
            url = detail[5]
            notes = detail[6]
            aes_bits = detail[9]
        else:
            messagebox.showerror("Error", "Item not found")
            return

        # Process the field and copy the value
        try:
            if field == 'password':
                value = decrypt_things(encrypted_pw, key, aes_bits)
            elif field == 'platform':
                value = platform
            elif field == 'label':
                value = label
            elif field == 'username':
                value = username
            elif field == 'url':
                value = url
            elif field == 'notes':
                value = notes
            else:
                value = ""
            
            copy_value(value, root)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get value: {e}")
    
    except Exception as e:
        messagebox.showerror("Error", f"Database error: {str(e)}")

# Function to check if clipboard history is enabled
def is_clipboard_history_enabled():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard")
        value, _ = winreg.QueryValueEx(key, "EnableClipboardHistory")
        winreg.CloseKey(key)
        # Clipboard history enabled
        return value == 1
    except Exception as e:
        # Clipboard history disabled or not found
        return False


previous_info_window = None
current_countdown_id = None

def copy_value(value, root):  
    global previous_info_window, current_countdown_id
    
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
        win32clipboard.SetClipboardText(value, win32clipboard.CF_UNICODETEXT)
        # Close the clipboard
        win32clipboard.CloseClipboard()

        # Custom messagebox using Toplevel window
        def close_window():
            global previous_info_window
            if previous_info_window:
                previous_info_window.destroy()  # Close the previous info_window if it exists
            info_window.destroy()  # Close the current info_window when OK is clicked
            previous_info_window = None  # Reset the reference

        # Create a custom Toplevel window to show the "Copied" message
        info_window = tk.Toplevel(root)
        info_window.title("Copied")
        info_window.configure(bg="#f0f0f0")

        # Set window size and position it in the center of the screen
        window_width = 300
        window_height = 120
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_left = int(screen_width / 2 - window_width / 2)
        info_window.geometry(f"{window_width}x{window_height}+{position_left}+{position_top}")

        # Label to display message
        message_label = tk.Label(info_window, text="Value copied to clipboard!", font=("Arial", 12), bg="#f0f0f0")
        message_label.pack(pady=20)

        # OK Button to close the messagebox with better styling
        ok_button = tk.Button(info_window, text="OK", command=close_window, font=("Arial", 10, "bold"),
                              relief="raised", bg="#4CAF50", fg="white", width=10, height=1)
        ok_button.pack(pady=10)

        # Focus on the OK button when the window is opened
        ok_button.focus_set()

        # Bind the window to close when it loses focus (click outside)
        info_window.bind("<FocusOut>", lambda event: close_window())

        # Store the current info_window as the previous one
        previous_info_window = info_window

        # Auto-close the window after 5 seconds (5000 milliseconds)
        info_window.after(5000, close_window)

        # Start the countdown function
        countdown(int(settings[4]), clipboard_history_enabled, root)

    except Exception as e:
        print(f"Error copying value: {e}")
        messagebox.showerror("Error", f"Failed to copy value: {e}")

def countdown(seconds, clipboard_history_enabled, root):
    global current_countdown_id  # Access global countdown ID

    # Cancel any ongoing countdown
    if current_countdown_id is not None:
        root.after_cancel(current_countdown_id)
        current_countdown_id = None

    def update_countdown(remaining):
        global current_countdown_id
        if remaining > 0:
            timer_label.config(text=f"Copied item will be cleared in {remaining} seconds...")
            # Store the new countdown ID
            current_countdown_id = root.after(1000, update_countdown, remaining - 1)
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
                # Clear message after 3 seconds
                root.after(3000, lambda: timer_label.config(text=""))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear clipboard: {e}")
            finally:
                current_countdown_id = None  # Reset countdown ID

    update_countdown(seconds)

# Delete entry for home content
def delete_selected_home_entry(root): 
    global selected_password_id, sqlite_obj
    
    if selected_password_id is None:
        messagebox.showinfo("Info", "No item selected")
        return
    
    # Show confirmation dialog
    confirm_delete = messagebox.askyesno(
        "Confirm Deletion", 
        "Are you sure you want to delete this entry? This action cannot be undone."
    )
    
    if not confirm_delete:
        return  # User canceled the deletion
    
    # Now soft-delete the entry using sqlite_obj
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Perform the update
        sqlite_obj.updateInTable("passwords", selected_password_id , "isDeleted" , 'True' , commit = True , raiseError = True)
        sqlite_obj.updateInTable("passwords", selected_password_id , "deletedAt" , current_time , commit = True , raiseError = True)
        messagebox.showinfo("Success", "Entry moved to trash")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete entry: {e}")
    
    # Refresh the view
    selected_password_id = None
    show_home_content(root)

def select_item(e, id, item_frame, root):
    global selected_item_widget, details_placeholder, selected_password_id, unsaved_changes

    if not item_frame.winfo_exists():
        return

    # Check for unsaved changes before switching
    if unsaved_changes and not confirm_discard_changes():
        return
        
    # Reset unsaved changes when proceeding
    unsaved_changes = False

    if selected_item_widget and selected_item_widget.winfo_exists():
        selected_item_widget.config(bg="#ffffff")

    item_frame.config(bg="#e0f7fa")
    selected_item_widget = item_frame
    selected_password_id = id

    # Remove details placeholder
    details_placeholder.destroy()
    show_password_details(root, id)

# Global variable to track unsaved changes
unsaved_changes = False

# Global variable declaration
item_context_menu = None
selected_password_id = None

# Function to truncate text with ellipses
def truncate_text(text, max_length=20):
    if len(text) > max_length:
        return text[:max_length-3] + "..."
    return text

def show_home_content(root):
    global sqlite_obj   
    global unsaved_changes, timer_label, selected_item_frame, selected_item_widget, items_container, details_placeholder, main_frame
    global selected_password_id  # Add this
    selected_password_id = None  # Reset selected item ID
    selected_item_widget = None  # Track selected widget
    unsaved_changes = False

    # Hide the main scrollbar for home content
    toggle_scrollbar(False)
    toggle_scrolling(False, root)

    # Check for unsaved changes before proceeding
    if unsaved_changes and not confirm_discard_changes():
        return
    
    # Reset unsaved changes flag when navigating away
    unsaved_changes = False

    # Initialize current filter state
    current_filter_type = None
    current_filter_value = None

    # Clear existing widgets
    for widget in main_frame.winfo_children():
        if widget != timer_label:
            widget.destroy()

    try:
        add_icon_path = "Images/add_b.png"
        if os.path.exists(add_icon_path):
            original_icon = Image.open(add_icon_path)
            resized_icon = original_icon.resize((30, 30))
            add_icon = ImageTk.PhotoImage(resized_icon)
        else:
            add_icon = None
    except Exception as e:
        print(f"Error loading add icon: {e}")
        add_icon = None
    
    try:
        search_icon_path = "Images/search_b.png"
        if os.path.exists(search_icon_path):
            original_search_icon = Image.open(search_icon_path)
            resized_search_icon = original_search_icon.resize((30, 30))
            search_icon = ImageTk.PhotoImage(resized_search_icon)
        else:
            search_icon = None
    except Exception as e:
        print(f"Error loading search icon: {e}")
        search_icon = None

    # Create main container
    main_container = tk.Frame(main_frame, bg="#f4f4f9")
    main_container.pack(fill=tk.BOTH, expand=True)
    main_container.config(width=root.winfo_width(), height=root.winfo_height() - 70)  # Dynamically update container size
    main_container.pack_propagate(False)  # Prevent the frame from resizing to fit its contents

    # Sidebar frame
    sidebar_frame = tk.Frame(main_container, width=200, bg="#2c3e50")
    sidebar_frame.pack(side=tk.LEFT, fill=tk.BOTH)

    # Bottom border frame setup - Use this or bd=1, relief=tk.SOLID at tk.Frame
    bottom_border_frame = tk.Frame(sidebar_frame, bg="black", height=1)  # Black bottom border
    bottom_border_frame.pack(side=tk.BOTTOM, fill=tk.X)

    # Right border frame setup
    right_border_frame = tk.Frame(sidebar_frame, bg="black", height=1)  # Black bottom border
    right_border_frame.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Content frame - already good
    content_frame = tk.Frame(main_container, bg="#f0f0f0")
    content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Add search bar and icons at the top of content_frame
    search_frame = tk.Frame(content_frame, bg="#f0f0f0")
    search_frame.pack(side=tk.TOP, fill=tk.X, pady=10)

    # Create the search bar and search icon
    search_entry = tk.Entry(search_frame, bg="#ffffff", font=("Arial", 10), width=30)
    search_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

    if search_icon:
        search_button = tk.Button(search_frame, image=search_icon, bg="#f0f0f0", borderwidth=0, highlightthickness=0,
                                  activebackground="#f0f0f0", cursor="hand2")
        search_button.image = search_icon
        search_button.pack(side=tk.LEFT)

    # Create clear 'X' icon button
    def clear_search():
        search_entry.delete(0, tk.END)
        search_function()  # Re-trigger search when cleared

    clear_icon = Image.open("Images/clear_b.png")  # Replace with the actual path to the 'X' icon image
    clear_icon_resized = clear_icon.resize((20, 20))
    clear_icon = ImageTk.PhotoImage(clear_icon_resized)

    clear_button = tk.Button(search_frame, image=clear_icon, command=clear_search, bg="#f0f0f0", borderwidth=0,
                             highlightthickness=0, activebackground="#f0f0f0", cursor="hand2")
    clear_button.image = clear_icon
    clear_button.pack(side=tk.RIGHT, padx=5)
    clear_button.pack_forget()  # Hide the clear button initially

    # Define the search function
    def search_function(event=None):    
        search_query = search_entry.get().strip().lower()
        
        # Show/hide clear button
        if search_query:
            clear_button.pack(side=tk.RIGHT, padx=5)
        else:
            clear_button.pack_forget()
        
        # Clear UI elements
        for widget in items_container.winfo_children():
            widget.destroy()
        
        selected_item_widget = None
        selected_password_id = None
        for child in details_frame.winfo_children():
            if isinstance(child, tk.Frame) and child.winfo_height() == 50:
                child.destroy()
        for widget in selected_item_frame.winfo_children():
            widget.destroy()
        
        details_placeholder = tk.Label(selected_item_frame,
                                    text="No item selected. Select an item to view details.",
                                    bg="#ffffff", fg="#666666",
                                    font=("Arial", 10), wraplength=400)
        details_placeholder.pack(expand=True, fill=tk.BOTH, padx=40, pady=40)
        
        # Fetch all items using sqlite_obj
        try:
            result = sqlite_obj.getDataFromTable(
                "passwords", 
                raiseConversionError=True, 
                omitID=False
            )
            
            passwords = []
            if result[1]:
                for row in result[1]:
                    # Extract columns: 
                    password_id = int(row[0])
                    platform_name = row[1]
                    platform_label = row[2]
                    platform_user = row[3]
                    updated_at = row[8]
                    
                    # Check if search query matches any field
                    if (search_query in platform_name.lower() or
                        search_query in platform_label.lower() or
                        search_query in platform_user.lower() or
                        search_query in updated_at.lower()):
                        passwords.append((password_id, platform_name, platform_label, platform_user, updated_at))
            
            # Sort by platform name
            passwords.sort(key=lambda x: x[1].lower())
            
            # Display results
            if passwords:
                for pwd in passwords:
                    create_item_widget(*pwd)
            else:
                placeholder = tk.Label(
                    items_container,
                    text="No matching items found.",
                    bg="#ffffff", fg="#666666",
                    font=("Arial", 10), wraplength=200
                )
                placeholder.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
        except Exception as e:
            print(f"Database error during search: {e}")
            messagebox.showerror("Search Error", "Failed to perform search")

    # Bind the search bar to automatically trigger the search when typing
    search_entry.bind("<KeyRelease>", search_function)

    # Create add button with icon and pack it to the far right
    if add_icon:
        add_button = tk.Button(search_frame, image=add_icon, command=lambda: open_add_password_form(root),
                             bg="#f0f0f0", borderwidth=0, highlightthickness=0,
                             activebackground="#f0f0f0", cursor="hand2")
        add_button.image = add_icon
        add_button.pack(side=tk.RIGHT, padx=10)
    
    # Items list frame setup - MODIFIED: added expand=True
    items_list_frame = tk.Frame(content_frame, bg="#ffffff")
    items_list_frame.pack(side=tk.LEFT, fill=tk.BOTH)

    # Top border frame setup
    top_border_frame = tk.Frame(items_list_frame, bg="black", height=1)  # Black bottom border
    top_border_frame.pack(side=tk.TOP, fill=tk.X)

    # Bottom border frame setup
    bottom_border_frame = tk.Frame(items_list_frame, bg="black", height=1)  # Black bottom border
    bottom_border_frame.pack(side=tk.BOTTOM, fill=tk.X)

    # Right border frame setup
    right_border_frame = tk.Frame(items_list_frame, bg="black", height=1)  # Black bottom border
    right_border_frame.pack(side=tk.RIGHT, fill=tk.Y)

    # Details frame setup - MODIFIED: added expand=True
    global details_frame
    details_frame = tk.Frame(content_frame, bg="#ffffff", bd=1, relief=tk.SOLID)
    details_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Selected item frame - already good
    selected_item_frame = tk.Frame(details_frame, bg="#ffffff")
    selected_item_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Details placeholder - same format as filled items
    details_placeholder = tk.Label(selected_item_frame, text="No item selected. Select an item to view details.",
                                   bg="#ffffff", fg="#666666", font=("Arial", 10), wraplength=400)
    details_placeholder.pack(expand=True, fill=tk.BOTH, padx=40, pady=40)

    def on_sidebar_enter(e):
        e.widget.config(bg="#34495e", cursor="hand2")

    def on_sidebar_leave(e):
        e.widget.config(bg="#2c3e50")

    # Function to filter items
    def filter_items(filter_type=None, filter_value=None):
        global unsaved_changes, selected_item_widget, selected_password_id, details_placeholder
        
        # Check for unsaved changes before proceeding
        if unsaved_changes and not confirm_discard_changes():
            return
        
        # Reset unsaved changes flag when proceeding
        unsaved_changes = False
        
        # Reset selection
        selected_item_widget = None
        selected_password_id = None
        
        # Clear existing items
        for widget in items_container.winfo_children():
            widget.destroy()
        
        # Remove bottom frame from details_frame
        for child in details_frame.winfo_children():
            if isinstance(child, tk.Frame) and child.winfo_height() == 50:
                child.destroy()
        
        # Clear details view and show placeholder
        for widget in selected_item_frame.winfo_children():
            widget.destroy()
        
        # Recreate the placeholder
        details_placeholder = tk.Label(selected_item_frame, text="No item selected. Select an item to view details.",
                                    bg="#ffffff", fg="#666666", font=("Arial", 10), wraplength=400)
        details_placeholder.pack(expand=True, fill=tk.BOTH, padx=40, pady=40)
        
        # Fetch all passwords from database
        try:
            result = sqlite_obj.getDataFromTable(
                "passwords",
                raiseConversionError=True,
                omitID=False
            )
            all_passwords = result[1] if result[0] and result[1] else []
        except Exception as e:
            print(f"Database error: {e}")
            all_passwords = []
        
        # Filter passwords based on criteria
        passwords = []
        for row in all_passwords:
            # Row structure: [id, platformName, platformLabel, platformUser, ... , isDeleted, isFavourite, ...]
            platform_label = row[2]
            is_favourite = row[11]
            is_deleted = row[12]
            if filter_type == "trash":
                if is_deleted == 'True':
                    passwords.append(row)
            elif filter_type == "favorites":
                if is_deleted == 'False' and is_favourite == 'True':
                    passwords.append(row)
            elif filter_type == "type":
                if is_deleted == 'False' and platform_label == filter_value:
                    passwords.append(row)
            else:  # Show all active passwords
                if is_deleted == 'False':
                    passwords.append(row)
        
        # Sort by platformName
        passwords.sort(key=lambda row: row[1].lower())  # platformName at index 1
        
        # Display placeholder if no items
        if not passwords:
            placeholder = tk.Label(items_container, text="No items found. Click the '+' button to add a new item.",
                                bg="#ffffff", fg="#666666", font=("Arial", 10), wraplength=200)
            placeholder.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            # Display filtered items
            for row in passwords:
                # Extract needed fields: id, platformName, platformUser, updatedAt, platformLabel
                password_id = int(row[0])
                platform_name = row[1]
                label = row[2]  
                username = row[3] 
                modified = row[8]  

                create_item_widget(password_id, platform_name, label, username, modified)

    def create_item_widget(password_id, platform, label, username, modified):  
        item_frame = tk.Frame(items_container, bg="#ffffff", bd=1, relief=tk.RIDGE)
        item_frame.pack(fill=tk.BOTH, pady=0, padx=0, anchor="w")
        item_frame.password_id = password_id

        content = tk.Frame(item_frame, bg="#ffffff")
        content.pack(fill=tk.BOTH, padx=5, pady=15)

        if label:
            try:
                label_color = get_label_color(label)
                tag = tk.Label(content, text=label, bg=label_color, fg="white",
                            font=("Arial", 8), padx=5, bd=1, relief=tk.RAISED)
                tag.pack(anchor="w")
            except Exception as e:
                print(f"Error creating label: {e}")

        # Set a minimum and maximum width for the platform label
        platform_label = tk.Label(content, text=truncate_text(platform), bg="#ffffff",
                                font=("Arial", 10), anchor="w", width=17)
        platform_label.pack(fill=tk.X)

        user_mod_frame = tk.Frame(content, bg="#ffffff")
        user_mod_frame.pack(fill=tk.X, padx=0)

        # Set minimum and maximum width for the user label
        user_label = tk.Label(user_mod_frame, text=truncate_text(username), bg="#ffffff", fg="#666666", 
                            font=("Arial", 9), anchor="w", justify="left", width=17)
        user_label.pack(fill=tk.X, anchor="w")

        # Set minimum and maximum width for the modified label
        mod_label = tk.Label(user_mod_frame, text=truncate_text(modified), bg="#ffffff", fg="#999999", 
                            font=("Arial", 8), anchor="w", justify="left", width=17)
        mod_label.pack(fill=tk.X, anchor="w")

        # Make the entire item clickable and right-clickable
        for widget in [item_frame, content, platform_label, user_mod_frame, user_label, mod_label]:
            widget.bind("<Button-1>", lambda e, password_id=password_id, frame=item_frame: select_item(e, password_id, frame, root))
            widget.bind("<Button-3>", lambda e, password_id=password_id: show_item_context_menu(e, password_id, root))
            if widget not in [item_frame, content]:  # Don't change cursor for container frames
                widget.config(cursor="hand2")
      
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
    create_filter_button(sidebar_frame, "All Entries", 
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
    items_canvas.pack(side="left", fill="both", expand=True)  # Make canvas expandable

    # Initial load with all items
    filter_items()

def create_bottom_frame(parent, root, password_id, is_deleted, save_callback):
    bottom_frame = tk.Frame(parent, bg="#f0f0f0", height=50, relief="sunken", bd=1)
    bottom_frame.pack(side="bottom", fill="x", padx=0, pady=0)
    bottom_frame.pack_propagate(False)  # Keep fixed height

    # Create a container frame for buttons on the right side
    button_container = tk.Frame(bottom_frame, bg="#f0f0f0")
    button_container.pack(side=tk.RIGHT, padx=10, pady=5)

    # For items in trash
    if is_deleted == 'True' and password_id is not None:
        restore_btn = tk.Button(button_container, text="Restore", bg="#4CAF50", fg="white", 
                               padx=20, pady=5, command=lambda: restore_selected_home_entry(root))
        restore_btn.pack(side=tk.RIGHT, padx=10)

        delete_perm_btn = tk.Button(button_container, text="Delete Permanently", bg="#f44336", fg="white", 
                                   padx=20, pady=5, command=lambda: delete_permanently_selected_home_entry(root))
        delete_perm_btn.pack(side=tk.RIGHT, padx=10)
    
    # For normal items
    else:
        save_button = tk.Button(button_container, text="Save", bg="#4CAF50", fg="white", padx=20, pady=5,
                                command=save_callback)  # Use the callback
        save_button.pack(side=tk.RIGHT, padx=10)
        
        cancel_button = tk.Button(button_container, text="Cancel", bg="#f44336", fg="white", 
                                padx=20, pady=5, command=on_cancel)
        cancel_button.pack(side=tk.RIGHT, padx=10)
        
        # Only show delete button for existing items (not in add mode)
        if password_id is not None:
            delete_button = tk.Button(button_container, text="Delete", bg="#ff9800", fg="white", 
                                    padx=20, pady=5, command=lambda: delete_selected_home_entry(root))
            delete_button.pack(side=tk.RIGHT, padx=10)

    return bottom_frame

def show_password_details(root, password_id=None):
    global unsaved_changes, selected_item_frame, details_frame, sqlite_obj
    
    # Check for unsaved changes if switching items
    if unsaved_changes and not confirm_discard_changes():
        return
        
    # Reset unsaved changes flag when opening a new form
    unsaved_changes = False

    # Remove existing bottom frames in details_frame
    for child in details_frame.winfo_children():
        if isinstance(child, tk.Frame) and child.winfo_height() == 50:  # Identify bottom frame
            child.destroy()

    is_edit_mode = password_id is not None

    # First pack the details frame if it's not already visible
    if not details_frame.winfo_ismapped():
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Clear previous details
    for widget in selected_item_frame.winfo_children():
        widget.destroy()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Fetch the password details from the database using sqlite_obj
    if is_edit_mode:
        try:
            # Get all password entries (ID is first column due to makeSecure=True)
            result = sqlite_obj.getDataFromTable(
                "passwords", 
                raiseConversionError=True, 
                omitID=False
            )
            
            if not result[1]:  # No data found
                row = [None] * 13
                decrypted_password = ''
            else:
                row = []
                # Find the row that matches the password_id
                for entry in result[1]:
                    if int(entry[0]) == password_id:  # Matching the password_id (assumed that entry[0] is the actual ID)
                        row = entry
                        break
                
                if row:
                    # Check if master password is required
                    if row[10] == 'True':  # mp_reprompt is True
                        if not require_master_password():  # If user cancels or enters wrong password
                            return  # Cancel the operation

                    # Decrypt password
                    try:
                        decrypted_password = decrypt_things(row[4], key, row[9])
                    except Exception as e:
                        decrypted_password = "Error decrypting"
                else:
                    row = [None] * 13
                    decrypted_password = ''
        except Exception as e:
            print(f"Error fetching password details: {e}")
            row = [None] * 13
            decrypted_password = ''
    else:
        row = [None] * 13
        decrypted_password = ''

    # Create StringVars for password and confirm password fields
    pass_var = tk.StringVar(value=decrypted_password)
    confirm_pass_var = tk.StringVar(value=decrypted_password)

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
    title_text = "EDIT ENTRY" if is_edit_mode else "ADD NEW ENTRY"
    ttk.Label(scrollable_details_frame, text=title_text, font=("Arial", 10, "bold"), 
            style="Normal.TLabel").pack(fill='x', padx=20, pady=(0, 20))

    # --- Platform Name Row ---
    name_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    name_row.pack(fill='x', padx=20, pady=(0, 0))
    label_frame = tk.Frame(name_row, bg=normal_color)
    label_frame.pack(anchor='w')
    ttk.Label(label_frame, text="Platform Name:", style="Normal.TLabel").pack(side='left')
    tk.Label(label_frame, text="*", fg="red", bg=normal_color).pack(side='left')
    
    name_frame = tk.Frame(name_row, bg=normal_color)
    name_frame.pack(fill='x')
    name_entry = tk.Entry(name_frame, fg="#000000", bg=normal_color, relief="flat")
    name_entry.insert(0, row[1] if row[1] else "")
    name_entry.pack(side='left', fill='x', expand=True)
    
    # Add copy button for name field
    if is_edit_mode:
        try:
            copy_icon = tk.PhotoImage(file="Images/copy_b.png").subsample(3, 3)
            name_copy_btn = tk.Button(name_frame, image=copy_icon, bg=normal_color, bd=0)
            name_copy_btn.pack(side='left', padx=5)
            name_copy_btn.bind("<Button-1>", lambda e: copy_value(name_entry.get(), root))
            name_copy_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Copy platform name"))
            name_copy_btn.bind("<Leave>", lambda e: hide_tooltip())
            name_copy_btn.image = copy_icon
        except:
            pass
        
        # Add context menu for name field
        def name_context_menu(e):
            menu = tk.Menu(root, tearoff=0)
            menu.add_command(label="Copy", command=lambda: copy_value(name_entry.get(), root))
            menu.add_command(label="Empty", command=lambda: name_entry.delete(0, tk.END))
            menu.tk_popup(e.x_root, e.y_root)
        
        name_entry.bind("<Button-3>", name_context_menu)
        name_entry.bind("<Control-c>", lambda e: copy_value(name_entry.get(), root))
    
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
    label_var = tk.StringVar(value=row[2] if row[2] else "Work")
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
    
    user_frame = tk.Frame(user_row, bg=normal_color)
    user_frame.pack(fill='x')
    user_entry = tk.Entry(user_frame, fg="#000000", bg=normal_color, relief="flat")
    user_entry.insert(0, row[3] if row[3] else "")
    user_entry.pack(side='left', fill='x', expand=True)
    
    # Add copy button for username field
    if is_edit_mode:
        try:
            copy_icon = tk.PhotoImage(file="Images/copy_b.png").subsample(3, 3)
            user_copy_btn = tk.Button(user_frame, image=copy_icon, bg=normal_color, bd=0)
            user_copy_btn.pack(side='left', padx=5)
            user_copy_btn.bind("<Button-1>", lambda e: copy_value(user_entry.get(), root))
            user_copy_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Copy username"))
            user_copy_btn.bind("<Leave>", lambda e: hide_tooltip())
            user_copy_btn.image = copy_icon
        except:
            pass
        
        # Add context menu for username field
        def user_context_menu(e):
            menu = tk.Menu(root, tearoff=0)
            menu.add_command(label="Copy", command=lambda: copy_value(user_entry.get(), root))
            menu.add_command(label="Empty", command=lambda: user_entry.delete(0, tk.END))
            menu.tk_popup(e.x_root, e.y_root)
        
        user_entry.bind("<Button-3>", user_context_menu)
        user_entry.bind("<Control-c>", lambda e: copy_value(user_entry.get(), root))
    
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
    pass_entry = tk.Entry(pass_frame, width=30, show="*", relief="flat", bg=normal_color, textvariable=pass_var)
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

    # Add copy button for password field (placed AFTER generate button)
    if is_edit_mode:
        try:
            copy_icon = tk.PhotoImage(file="Images/copy_b.png").subsample(3, 3)
            pass_copy_btn = tk.Button(pass_frame, image=copy_icon, bg=normal_color, bd=0)
            pass_copy_btn.pack(side='left', padx=5)
            pass_copy_btn.bind("<Button-1>", lambda e: copy_value(pass_var.get(), root))
            pass_copy_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Copy password"))
            pass_copy_btn.bind("<Leave>", lambda e: hide_tooltip())
            pass_copy_btn.image = copy_icon
        except:
            pass
        
        # Add context menu for password field
        def pass_context_menu(e):
            menu = tk.Menu(root, tearoff=0)
            menu.add_command(label="Copy", command=lambda: copy_value(pass_var.get(), root))
            menu.add_command(label="Empty", command=lambda: pass_var.set(""))
            menu.tk_popup(e.x_root, e.y_root)
        
        pass_entry.bind("<Button-3>", pass_context_menu)
        pass_entry.bind("<Control-c>", lambda e: copy_value(pass_var.get(), root))

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
    confirm_pass_entry = tk.Entry(confirm_pass_frame, width=30, show="•", relief="flat", bg=normal_color, textvariable=confirm_pass_var)
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
    aes_bit_var = tk.StringVar(value=str(row[9]) if row[9] else "256")
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
    strength_row.pack(fill='x', padx=25, pady=5)

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
    
    url_frame = tk.Frame(url_row, bg=normal_color)
    url_frame.pack(fill='x')
    url_entry = tk.Entry(url_frame, fg="#000000", bg=normal_color, relief="flat")
    url_entry.insert(0, row[5] if row[5] else "")
    url_entry.pack(side='left', fill='x', expand=True)
    
    # Add copy button for URL field
    if is_edit_mode:
        try:
            copy_icon = tk.PhotoImage(file="Images/copy_b.png").subsample(3, 3)
            url_copy_btn = tk.Button(url_frame, image=copy_icon, bg=normal_color, bd=0)
            url_copy_btn.pack(side='left', padx=5)
            url_copy_btn.bind("<Button-1>", lambda e: copy_value(url_entry.get(), root))
            url_copy_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Copy URL"))
            url_copy_btn.bind("<Leave>", lambda e: hide_tooltip())
            url_copy_btn.image = copy_icon
        except:
            pass
        
        # Add context menu for URL field
        def url_context_menu(e):
            menu = tk.Menu(root, tearoff=0)
            menu.add_command(label="Copy", command=lambda: copy_value(url_entry.get(), root))
            menu.add_command(label="Empty", command=lambda: url_entry.delete(0, tk.END))
            menu.tk_popup(e.x_root, e.y_root)
        
        url_entry.bind("<Button-3>", url_context_menu)
        url_entry.bind("<Control-c>", lambda e: copy_value(url_entry.get(), root))
    
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))

    # --- Notes Row ---
    notes_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    notes_row.pack(fill='x', padx=20)
    notes_lframe = tk.Frame(notes_row, bg=normal_color)
    notes_lframe.pack(anchor='w')
    ttk.Label(notes_lframe, text="Notes:", style="Normal.TLabel").pack(side='left')
    
    notes_frame = tk.Frame(notes_row, bg=normal_color)
    notes_frame.pack(fill='x')
    notes_text = tk.Text(notes_frame, height=4, width=22, fg="#000000", bg=normal_color, relief="flat")
    notes_text.insert("1.0", row[6] if row[6] else "")
    notes_text.pack(side='left', fill='x', expand=True)
    
    # Add copy button for notes field
    if is_edit_mode:
        try:
            copy_icon = tk.PhotoImage(file="Images/copy_b.png").subsample(3, 3)
            notes_copy_btn = tk.Button(notes_frame, image=copy_icon, bg=normal_color, bd=0)
            notes_copy_btn.pack(side='left', padx=5)
            notes_copy_btn.bind("<Button-1>", lambda e: copy_value(notes_text.get("1.0", "end-1c"), root))
            notes_copy_btn.bind("<Enter>", lambda e: show_tooltip(e.widget, "Copy notes"))
            notes_copy_btn.bind("<Leave>", lambda e: hide_tooltip())
            notes_copy_btn.image = copy_icon
        except:
            pass
        
        # Add context menu for notes field
        def notes_context_menu(e):
            menu = tk.Menu(root, tearoff=0)
            menu.add_command(label="Copy", command=lambda: copy_value(notes_text.get("1.0", "end-1c"), root))
            menu.add_command(label="Empty", command=lambda: notes_text.delete("1.0", tk.END))
            menu.tk_popup(e.x_root, e.y_root)
        
        notes_text.bind("<Button-3>", notes_context_menu)
        notes_text.bind("<Control-c>", lambda e: copy_value(notes_text.get("1.0", "end-1c"), root))
    
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))

    # --- Master Password Reprompt Row ---
    mp_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    mp_row.pack(fill='x', padx=20, pady=(0, 5))
    ttk.Label(mp_row, text="Master Password Reprompt:", style="Normal.TLabel").pack(side='left', padx=(0, 5))
    mp_reprompt_var = tk.BooleanVar(value=row[10] if row[10] is not None else False)
    mp_check = tk.Checkbutton(mp_row, variable=mp_reprompt_var, bg=normal_color)
    mp_check.pack(side='left')
    tk.Frame(scrollable_details_frame, height=1, bg="#cccccc").pack(fill='x', padx=20, pady=(0, 10))
	
    # --- Favourite Row ---
    fav_row = tk.Frame(scrollable_details_frame, bg=normal_color)
    fav_row.pack(fill='x', padx=20, pady=(0, 5))
    ttk.Label(fav_row, text="Favourite:", style="Normal.TLabel").pack(side='left', padx=(0, 5))
    is_favourite_var = tk.BooleanVar(value=row[11] if row[11] is not None else False)
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

    # --- Add this flag ---
    initial_comparison_done = False

    # --- Moved below trace setup ---
    # Capture original values for comparison AFTER setting up traces
    # MODIFIED: Initialize differently for add vs edit mode
    original_values = {
        'name': name_entry.get() if is_edit_mode else "",
        'label': label_var.get() if is_edit_mode else "Work",
        'user': user_entry.get() if is_edit_mode else "",
        'password': pass_var.get() if is_edit_mode else "",
        'confirm_password': confirm_pass_var.get() if is_edit_mode else "",
        'url': url_entry.get() if is_edit_mode else "",
        'notes': notes_text.get("1.0", "end-1c") if is_edit_mode else "",
        'aes_bit': aes_bit_var.get() if is_edit_mode else "256",
        'mp_reprompt': mp_reprompt_var.get() if is_edit_mode else False,
        'is_favourite': is_favourite_var.get() if is_edit_mode else False
    }

    # Track changes in all input fields
    def check_for_changes(*args):
        global unsaved_changes
        if not initial_comparison_done:
            return
            
        # For add mode: any non-empty field sets the flag
        if not is_edit_mode:
            unsaved_changes = any([
                name_entry.get().strip(),
                user_entry.get().strip(),
                pass_var.get().strip(),
                confirm_pass_var.get().strip(),
                url_entry.get().strip(),
                notes_text.get("1.0", "end-1c").strip(),
                mp_reprompt_var.get(),
                is_favourite_var.get()
            ])
            return
            
        current_values = collect_current_values()
        
        # Compare current values with original values
        unsaved_changes = current_values != original_values
    
    # Bind to all input fields
    for widget in [name_entry, user_entry, url_entry, notes_text, label_combobox]:
        if isinstance(widget, tk.Text):
            widget.bind("<<Modified>>", lambda e: check_for_changes())
        else:
            widget.bind("<KeyRelease>", lambda e: check_for_changes())

    # Add trace bindings for the password variables
    pass_var.trace_add("write", lambda *args: check_for_changes())
    confirm_pass_var.trace_add("write", lambda *args: check_for_changes())
    
    # Bind to checkbuttons
    mp_reprompt_var.trace_add("write", lambda *args: check_for_changes())
    is_favourite_var.trace_add("write", lambda *args: check_for_changes())
    
    # Bind to comboboxes
    label_combobox.bind("<<ComboboxSelected>>", lambda e: check_for_changes())
    aes_bit_combobox.bind("<<ComboboxSelected>>", lambda e: check_for_changes())

    # Schedule initial comparison after UI settles
    def perform_initial_comparison():
        nonlocal initial_comparison_done
        # Update original_values to current state after initialization
        original_values.update({
            'name': name_entry.get(),
            'label': label_var.get(),
            'user': user_entry.get(),
            'password': pass_var.get(),
            'confirm_password': confirm_pass_var.get(),
            'url': url_entry.get(),
            'notes': notes_text.get("1.0", "end-1c"),
            'aes_bit': aes_bit_var.get(),
            'mp_reprompt': mp_reprompt_var.get(),
            'is_favourite': is_favourite_var.get()
        })
        initial_comparison_done = True
    
    selected_item_frame.after_idle(perform_initial_comparison)

    # Function to collect current values
    def collect_current_values():
        return {
            'name': name_entry.get().strip(),
            'label': label_var.get().strip(),
            'user': user_entry.get().strip(),
            'password': pass_var.get(),
            'confirm_password': confirm_pass_var.get(),
            'url': url_entry.get().strip(),
            'notes': notes_text.get("1.0", "end-1c").strip(),
            'aes_bit': aes_bit_var.get(),
            'mp_reprompt': mp_reprompt_var.get(),
            'is_favourite': is_favourite_var.get()
        }
    
    # Create the bottom frame
    is_deleted = row[12] if row else False

    # Define save callback function
    def save_callback():
        current_vals = collect_current_values()
        if is_edit_mode:
            save_and_reset_flag(password_id, current_vals['name'], current_vals['label'],
                            current_vals['user'], current_vals['password'], 
                            current_vals['confirm_password'], current_vals['url'], 
                            current_vals['notes'], int(current_vals['aes_bit']),
                            current_vals['mp_reprompt'], current_vals['is_favourite'], 
                            root=root)
        else:
            save_and_reset_flag(None, current_vals['name'], current_vals['label'],
                            current_vals['user'], current_vals['password'], 
                            current_vals['confirm_password'], current_vals['url'], 
                            current_vals['notes'], int(current_vals['aes_bit']),
                            current_vals['mp_reprompt'], current_vals['is_favourite'], 
                            root=root)

    # Create bottom frame with callback
    create_bottom_frame(details_frame, root, password_id, is_deleted, save_callback)

    # Now pack the bottom_frame at the bottom of the screen.
    details_frame.update_idletasks()  # Ensure the details_frame is fully drawn before packing
    details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

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

def open_add_password_form(root):
    show_password_details(root)  # Call without password_id to enter add mode

def save_and_reset_flag(password_id, *args, root=None):
    """Save changes and reset unsaved flag"""
    global unsaved_changes
    if password_id is not None:
        if save_password_changes(password_id, *args, root=root):
            unsaved_changes = False
            show_home_content(root)  # Only call show_home_content if save is successful
    else:
        if save_new_password(*args, root=root):
            unsaved_changes = False
            show_home_content(root)  # Only call show_home_content if save is successful

def on_cancel():
    """Handle cancel action with unsaved changes check"""
    global unsaved_changes
    if not unsaved_changes or confirm_discard_changes():
        details_frame.pack_forget()
        unsaved_changes = False

def confirm_discard_changes():
    """Show confirmation dialog for unsaved changes"""
    return messagebox.askyesno(
        "Unsaved Changes",
        "You have unsaved changes. Discard changes?",
        icon='warning'
    )

def is_valid_input(text, max_length=255, required=True):  
    """Basic sanitization check for input fields with a length limit. URL and Notes fields are not required."""
    if required and not text.strip():
        return False, f"Field is required and cannot be empty."
    elif len(text.strip()) > max_length:
        return False, f"Maximum length exceeded. Please keep it under {max_length} characters."
    return True, ""

def save_new_password(name, label, user, password, confirm_password, url, notes, aes_bits, mp_reprompt, is_favourite, root):
    global sqlite_obj

    # Validate input fields with specific max lengths
    is_valid, message = is_valid_input(name, 50)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Platform Name: {message}")
        return False

    is_valid, message = is_valid_input(label, 50)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Label: {message}")
        return False

    is_valid, message = is_valid_input(user, 50)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Username: {message}")
        return False

    is_valid, message = is_valid_input(password, 100)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Password: {message}")
        return False

    is_valid, message = is_valid_input(confirm_password, 100)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Confirm Password: {message}")
        return False

    is_valid, message = is_valid_input(url, 255, required=False)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid URL: {message}")
        return False

    is_valid, message = is_valid_input(notes, 512, required=False)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Notes: {message}")
        return False
    
    # Validate that password and confirm password match
    if password != confirm_password:
        messagebox.showerror("Error", "Password and Confirm Password do not match")
        return False
    
    # Encryption logic
    encrypted_password = encrypt_things(password, key, aes_bits)
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Database insertion
    try:
        # Prepare the data to be inserted
        insert_data = [
            name,
            label,
            user,
            encrypted_password,
            url,
            notes,
            current_time,
            current_time,
            aes_bits,
            mp_reprompt,
            is_favourite,
            'False', 
            ''
        ]
        
        # Perform the insertion using sqlite_obj
        sqlite_obj.insertIntoTable("passwords", insert_data, commit=True)
        # After successful database operation, update the UI
        root.after(0, lambda: update_nav_bar_password_health(root))
        messagebox.showinfo("Success", "Password saved successfully")
        return True  # Return success to trigger show_home_content
    except Exception as e:
        messagebox.showerror("Database Error", f"Error saving password: {str(e)}")
        return False  # Return failure, prevent further actions

def save_password_changes(password_id, name, label, user, password, confirm_password, url, notes, aes_bits, mp_reprompt, is_favourite, root): 
    global sqlite_obj

    # Validate input fields with specific max lengths
    is_valid, message = is_valid_input(name, 50)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Platform Name: {message}")
        return False

    is_valid, message = is_valid_input(label, 50)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Label: {message}")
        return False

    is_valid, message = is_valid_input(user, 50)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Username: {message}")
        return False

    is_valid, message = is_valid_input(password, 100)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Password: {message}")
        return False

    is_valid, message = is_valid_input(confirm_password, 100)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Confirm Password: {message}")
        return False

    is_valid, message = is_valid_input(url, 255, required=False)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid URL: {message}")
        return False

    is_valid, message = is_valid_input(notes, 512, required=False)
    if not is_valid:
        messagebox.showerror("Error", f"Invalid Notes: {message}")
        return False
    
    # Validate that password and confirm password match
    if password != confirm_password:
        messagebox.showerror("Error", "Password and Confirm Password do not match")
        return False
    
    # Ask for confirmation before saving changes
    confirm_save = messagebox.askyesno(
        "Confirm Save", 
        "Are you sure you want to save these changes?"
    )
    
    if not confirm_save:
        return  # User canceled saving changes
    
    # Encrypt the password before saving
    encrypted_password = encrypt_things(password, key, aes_bits)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        sqlite_obj.updateInTable("passwords", password_id , "platformName" , name, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "platformLabel" , label, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "platformUser" , user, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "encryptedPassword" , encrypted_password, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "platformURL" , url, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "platformNote" , notes, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "updatedAt" , current_time, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "aes_bits" , aes_bits, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "mp_reprompt" , mp_reprompt, commit=True, raiseError=True)
        sqlite_obj.updateInTable("passwords", password_id , "isFavourite" , is_favourite, commit=True, raiseError=True)
        
        # After successful database operation, update the UI
        root.after(0, lambda: update_nav_bar_password_health(root))
        messagebox.showinfo("Success", "Password updated successfully")
        return True  # Return success to trigger show_home_content
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save changes: {str(e)}")
        return False  # Return failure, prevent further actions
    
def open_aes_evaluation_window(parent_window, current_password, aes_bit_var):
    global sqlite_obj
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

    # Show/Hide Password Button
    show_password_icon = tk.PhotoImage(file="Images/show_password_b.png").subsample(3, 3)
    hide_password_icon = tk.PhotoImage(file="Images/hide_password_b.png").subsample(3, 3)
    settings_icon = tk.PhotoImage(file="Images/settings_b.png").subsample(3, 3)

    # Master Password Test Field
    tk.Label(main_frame, text="Test Master Password:", bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    master_pw_entry = tk.Entry(main_frame, show="*")
    master_pw_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    # Show/Hide for Master Password
    def toggle_master_visibility():
        if master_pw_entry.cget('show') == '*':
            master_pw_entry.config(show='')
            master_eye_icon.config(image=show_password_icon)
        else:
            master_pw_entry.config(show='*')
            master_eye_icon.config(image=hide_password_icon)

    master_eye_icon = tk.Label(main_frame, image=hide_password_icon, cursor="hand2", bg="#f0f0f0")
    master_eye_icon.grid(row=0, column=2, padx=5, pady=5, sticky="e")
    master_eye_icon.bind("<Button-1>", lambda e: toggle_master_visibility())
    master_eye_icon.bind("<Enter>", lambda e: show_tooltip(e.widget, "Toggle password visibility"))
    master_eye_icon.bind("<Leave>", lambda e: hide_tooltip())

    # Target Password Input
    tk.Label(main_frame, text="Target Password:", bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    password_entry = tk.Entry(main_frame, show="*")
    password_entry.insert(0, current_password)
    password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

    def toggle_password_visibility():
        if password_entry.cget('show') == '*':
            password_entry.config(show='')
            password_eye_icon.config(image=show_password_icon)
        else:
            password_entry.config(show='*')
            password_eye_icon.config(image=hide_password_icon)

    password_eye_icon = tk.Label(main_frame, image=hide_password_icon, cursor="hand2", bg="#f0f0f0")
    password_eye_icon.grid(row=1, column=2, padx=5, pady=5, sticky="e")
    password_eye_icon.bind("<Button-1>", lambda e: toggle_password_visibility())
    password_eye_icon.bind("<Enter>", lambda e: show_tooltip(e.widget, "Toggle password visibility"))
    password_eye_icon.bind("<Leave>", lambda e: hide_tooltip())

    # Get current values for guess_per_sec from the database
    try:
        result = sqlite_obj.getDataFromTable(
            "attack_settings", 
            raiseConversionError=True,
            omitID=True
        )
        guess_per_sec = result[1][0][2] if result[1] else 3000000
    except Exception as e:
        print(f"Error fetching attack settings: {e}")
        guess_per_sec = 3000000

    # Guess Rate
    tk.Label(main_frame, text="Guess Rate (per sec):", bg="#f0f0f0").grid(row=2, column=0, padx=5, pady=5, sticky="w")
    guess_sec_entry = tk.Entry(main_frame)
    guess_sec_entry.insert(0, str(guess_per_sec))
    guess_sec_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

    # Configure Guess Rate Button
    config_guess_rate_button = tk.Label(main_frame, image=settings_icon, cursor="hand2", bg="#f0f0f0")
    config_guess_rate_button.grid(row=2, column=2, padx=5, pady=5, sticky="w")
    config_guess_rate_button.bind("<Button-1>", lambda e: open_guess_rate_window(eval_win, guess_sec_entry))
    config_guess_rate_button.image = settings_icon
    config_guess_rate_button.bind("<Enter>", lambda e: show_tooltip(config_guess_rate_button, "Configure guess rate settings"))
    config_guess_rate_button.bind("<Leave>", lambda e: hide_tooltip())

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
                             master_pw_entry.get(),
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

def start_evaluation(master_password, target_password, enc_time, dec_time, mem_usage, throughput, entropy,
                     est_aes, guess_sec, cli_output, aes_bit_var, eval_win):

    cli_output.config(state=tk.NORMAL)

    if not master_password:
        cli_output.insert(tk.END, "Error: Master password is required\n")
        cli_output.config(state=tk.DISABLED)
        return

    if not target_password:
        cli_output.insert(tk.END, "Error: Target password is required\n")
        cli_output.config(state=tk.DISABLED)
        return

    results = {}
    
    cli_output.insert(tk.END, f"\nUsing master password to derive keys...")
    cli_output.insert(tk.END, f"\nEncrypting/decrypting target password for metrics...\n")

    for bits in ["128", "192", "256"]:
        cli_output.insert(tk.END, f"\n=== Evaluating AES-{bits} ===")
        
        perf = {}
        if enc_time or dec_time:
            perf = test_aes_performance(
                int(bits), master_password, target_password, 
                enc_time, dec_time,
                mem_usage, throughput, entropy
            )
        
        # Estimated crack times
        est_times = estimate_crack_times_evaluation(target_password, int(bits), est_aes, guess_sec)
                
        results[bits] = {
            'performance': perf,
            'estimates': est_times
        }

    # Performance Summary Tables
    if enc_time:
        cli_output.insert(tk.END, "\n\n=== Encryption Performance ===")
        cli_output.insert(tk.END, "\nKey Size | Time (ms) | Memory (MB) | Throughput (ops/s)")
        cli_output.insert(tk.END, "\n--------------------------------------------------------")
        for bits in ["128", "192", "256"]:
            perf = results[bits]['performance']
            cli_output.insert(tk.END, 
                f"\nAES-{bits.ljust(4)} | "
                f"{perf.get('encryption_time', 0):9.6f} | "
                f"{perf.get('encryption_memory', 0):10.6f} | "
                f"{perf.get('encryption_throughput', 0):17.2f}")

    if dec_time:
        cli_output.insert(tk.END, "\n\n=== Decryption Performance ===")
        cli_output.insert(tk.END, "\nKey Size | Time (ms) | Memory (MB) | Throughput (ops/s)")
        cli_output.insert(tk.END, "\n--------------------------------------------------------")
        for bits in ["128", "192", "256"]:
            perf = results[bits]['performance']
            cli_output.insert(tk.END, 
                f"\nAES-{bits.ljust(4)} | "
                f"{perf.get('decryption_time', 0):9.6f} | "
                f"{perf.get('decryption_memory', 0):10.6f} | "
                f"{perf.get('decryption_throughput', 0):17.2f}")

    # Security Summary
    cli_output.insert(tk.END, "\n\n=== Security Summary ===")
    cli_output.insert(tk.END, "\nKey Size | Entropy (bits) | Estimated Crack Time")
    cli_output.insert(tk.END, "\n-------------------------------------------------")
    for bits in ["128", "192", "256"]:
        perf = results[bits]['performance']
        est_times = results[bits]['estimates']
        entropy_val = perf.get('encryption_entropy', "N/A")
        crack_time = est_times.get("AES Brute-Force", "N/A")
        cli_output.insert(tk.END, f"\nAES-{bits.ljust(4)} | {entropy_val:14} | {crack_time}")

    # Recommendation
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
    
def test_aes_performance(bits, master_password, target_password, test_enc, test_dec, test_mem, test_throughput, test_entropy):
    results = {}
    plaintext = target_password.encode()
    iterations = 1000  # Number of operations to measure

    # Derive key from master password
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    
    # Truncate key based on AES bits
    if bits == 128:
        key_used = key[:16]
    elif bits == 192:
        key_used = key[:24]
    else:  # 256
        key_used = key

    # Encryption metrics
    if test_enc:
        try:
            # Pre-generate IVs
            ivs = [os.urandom(12) for _ in range(iterations)]
            
            start_time = time.perf_counter()
            if test_mem:
                tracemalloc.start()

            for iv in ivs:
                cipher = Cipher(algorithms.AES(key_used), modes.GCM(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            if test_mem:
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                results['encryption_memory'] = peak / (1024 ** 2)  # MB
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            results['encryption_time'] = (total_time / iterations) * 1000  # ms per operation
            results['encryption_throughput'] = iterations / total_time  # operations per second
            
            if test_entropy:
                results['encryption_entropy'] = round(calculate_entropy(ciphertext), 2)
                
        except Exception as e:
            print(f"Encryption test error: {str(e)}")

    # Decryption metrics
    if test_dec:
        try:
            # Generate valid ciphertext for decryption
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key_used), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag
            combined = iv + tag + ciphertext

            start_time = time.perf_counter()
            if test_mem:
                tracemalloc.start()

            for _ in range(iterations):
                iv_part = combined[:12]
                tag_part = combined[12:28]
                ciphertext_part = combined[28:]
                cipher = Cipher(algorithms.AES(key_used), modes.GCM(iv_part, tag_part), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext_part) + decryptor.finalize()

            if test_mem:
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                results['decryption_memory'] = peak / (1024 ** 2)  # MB
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            results['decryption_time'] = (total_time / iterations) * 1000  # ms per operation
            results['decryption_throughput'] = iterations / total_time  # operations per second
            
        except Exception as e:
            print(f"Decryption test error: {str(e)}")

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

# Function to identify password issues
def identify_password_issues():
    result = sqlite_obj.getDataFromTable("passwords", raiseConversionError=True, omitID=False)

    if not result[0] or not result[1]:
        return [], [], [], []

    passwords = result[1]
    passwords = [pwd for pwd in passwords if pwd[12] != 'True']  # Exclude deleted passwords

    weak_passwords = []
    old_passwords = []
    reused_passwords = []
    breached_passwords = []

    decrypted_passwords = []
    for pwd in passwords:
        decrypted = decrypt_things(pwd[4], key, pwd[9])
        decrypted_passwords.append(decrypted)

    password_count = {}
    for decrypted in decrypted_passwords:
        password_count[decrypted] = password_count.get(decrypted, 0) + 1

    current_time = datetime.now()

    for i, pwd in enumerate(passwords):
        decrypted_password = decrypted_passwords[i]

        # Weak password check
        if (len(decrypted_password) < 8 or 
            not re.search(r"[A-Z]", decrypted_password) or 
            not re.search(r"[a-z]", decrypted_password) or 
            not re.search(r"[0-9]", decrypted_password)):
            weak_passwords.append(pwd)

        # Old password check
        updated_at = datetime.strptime(pwd[8], "%Y-%m-%d %H:%M:%S")
        if (current_time - updated_at).days > 365:
            old_passwords.append(pwd)

        # Reused password check
        if password_count[decrypted_password] > 1:
            reused_passwords.append(pwd)

        # Breached password check
        breach_msg, count, error = check_pwned_password(decrypted_password)
        if not error and count is not None and count > 0:
            breached_passwords.append(pwd)

    return weak_passwords, old_passwords, reused_passwords, breached_passwords

# Function to update the nav bar based on password issues (to be called from another thread)
def update_nav_bar_password_health(root):
    # Start the password check in a separate thread to avoid UI blocking
    def check_and_update():
        weak_passwords, old_passwords, reused_passwords, breached_passwords = identify_password_issues()
        has_issues = any([weak_passwords, old_passwords, reused_passwords, breached_passwords])

        # Schedule the UI update to run in the main thread
        root.after(0, lambda: update_gui(has_issues))

    def update_gui(has_issues):
        # Only update if the window still exists
        if root.winfo_exists():
            if has_issues:
                password_health_label.config(text="Password Health")
                exclamation_label.config(text="⚠️", fg="red")
            else:
                password_health_label.config(text="Password Health", fg="white")
                exclamation_label.config(text="", fg="white")

    # Run the check in a separate thread
    threading.Thread(target=check_and_update, daemon=True).start()

def periodic_update_nav_bar_password_health(root):
    update_nav_bar_password_health(root)
    
    if root.winfo_exists():
        global password_health_after_id
        # Store the after ID
        password_health_after_id = root.after(10000, periodic_update_nav_bar_password_health, root)

def show_password_health_content(root): 
    global sqlite_obj
    toggle_scrollbar(True)
    toggle_scrolling(True, root)

    # Clear existing widgets in main_frame
    for widget in main_frame.winfo_children():
        if widget != timer_label:  # Do not destroy the timer label
            widget.destroy()

    # Create a container frame with a modern look
    container = tk.Frame(main_frame, bg="#f4f4f9")
    container.pack(fill=tk.BOTH, expand=True)

    # Title with clean typography
    tk.Label(container, text="Password Health Checker", font=("Helvetica", 18, "bold"), bg="#f4f4f9", fg="#333333").pack(pady=10)
    tk.Label(container, text="Identify weak, old or reused passwords. Click to take action now!", font=("Helvetica", 12), bg="#f4f4f9", fg="#777777").pack(pady=3)

    # Perform the check in the background thread
    def show_entries():
        weak_passwords, old_passwords, reused_passwords, breached_passwords = identify_password_issues()

        def show_entries(entries):
            for widget in main_frame.winfo_children():
                widget.destroy()

            # Back arrow to return to main menu
            back_arrow = tk.Label(main_frame, text="←", font=("Helvetica", 18), cursor="hand2", bg="#f4f4f9")
            back_arrow.pack(anchor="w", padx=10, pady=5)
            back_arrow.bind("<Button-1>", lambda e: show_password_health_content(root))

            # Display password entries with modern design
            for entry in entries:
                entry_frame = tk.Frame(main_frame, relief=tk.RAISED, borderwidth=2, bg="#ffffff")
                entry_frame.config(width=350, height=100)
                entry_frame.pack_propagate(False)
                entry_frame.pack(padx=10, pady=10)

                # Label for password type with modern color scheme
                label_color = get_label_color(entry[2])
                tag = tk.Label(entry_frame, text=entry[2], bg=label_color, fg="white", font=("Helvetica", 10), padx=5, bd=1, relief=tk.RAISED)
                tag.grid(row=0, column=0, padx=10, pady=5, sticky="w")

                # Platform label with aligned and easy-to-read font
                platform_name = tk.Label(entry_frame, text=f"Platform: {truncate_text(entry[1])}", bg="white", anchor="w", width=25, font=("Helvetica", 11))
                platform_name.grid(row=1, column=0, padx=10, pady=5, sticky="w")

                # Username label with soft color
                user_label = tk.Label(entry_frame, text=f"Username: {truncate_text(entry[3])}", bg="white", fg="#666666", anchor="w", width=25, font=("Helvetica", 10))
                user_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

                # Date modified with subtle design
                date_modified = tk.Label(entry_frame, text=truncate_text(entry[8]), bg="white", fg="#999999", anchor="w", width=25, font=("Helvetica", 10))
                date_modified.grid(row=3, column=0, padx=10, pady=5, sticky="w")

                # Buttons container aligned nicely
                buttons_frame = tk.Frame(entry_frame, bg="white")
                buttons_frame.grid(row=0, column=1, rowspan=4, padx=10, pady=5, sticky="ns")

                # Change Password button with modern style
                change_button = tk.Button(buttons_frame, text="Change Password", 
                                        command=lambda e=entry: change_password_from_health(e[0], root), bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"))
                change_button.pack(pady=5, fill="x")

                # Delete button with contrast color
                delete_button = tk.Button(buttons_frame, text="Delete", command=lambda e=entry: delete_selected_entry(e[0], root), bg="#f44336", fg="white", font=("Helvetica", 10, "bold"))
                delete_button.pack(pady=5, fill="x")

            main_frame.update_idletasks()

        # Sections for weak, old, reused, and breached passwords with enhanced clarity
        sections = [
            ("Weak Passwords", len(weak_passwords), weak_passwords, "No weak passwords found.", "Weak passwords found. Click to view."),
            ("Old Passwords", len(old_passwords), old_passwords, "No old passwords found.", "Old passwords found. Click to view."),
            ("Reused Passwords", len(reused_passwords), reused_passwords, "No reused passwords found.", "Reused passwords found. Click to view."),
            ("Breached Passwords", len(breached_passwords), breached_passwords, "No breached passwords found.", "Breached passwords found. Click to view.")
        ]

        # Create a container for sections with uniform spacing
        section_container = tk.Frame(container, bg="#f4f4f9")
        section_container.pack(pady=10, padx=20)

        for section in sections:
            cursor_type = "hand2" if section[1] > 0 else ""  # Set cursor to "hand2" only if there are passwords
            frame = tk.Frame(section_container, relief=tk.RAISED, borderwidth=2, bg="white", cursor=cursor_type)
            frame.config(width=350, height=80)
            frame.pack_propagate(False)
            frame.pack(pady=10, padx=10, fill="x", expand=True)

            # Content frame inside each section for modern layout
            content_frame = tk.Frame(frame, bg="white")
            content_frame.pack(fill="both", expand=True, padx=12, pady=8)

            count_color = "green" if section[1] == 0 else "red"
            count_label = tk.Label(content_frame, text=f"{section[1]}", font=("Helvetica", 16, "bold"), fg=count_color, bg="white")
            count_label.pack(side=tk.TOP, pady=(6, 2))

            description = section[3] if section[1] == 0 else section[4]
            label = tk.Label(content_frame, text=description, font=("Helvetica", 12), bg="white")
            label.pack(side=tk.TOP, pady=(2, 6))

            # Right arrow for action
            arrow = tk.Label(frame, text="→", font=("Helvetica", 16), cursor="hand2", bg="white")
            if section[1] == 0:
                arrow.place_forget()  # Hide arrow if no passwords
            else:
                arrow.place(relx=0.95, rely=0.5, anchor="e")

            # Binding events for click actions
            if section[1] > 0:
                frame.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
                content_frame.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
                count_label.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
                label.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
                arrow.bind("<Button-1>", lambda e, entries=section[2]: show_entries(entries))
        
    threading.Thread(target=show_entries, daemon=True).start()
    def change_password_from_health(password_id, root):
        show_home_content(root)
        item_frame = None
        for widget in items_container.winfo_children():
            if hasattr(widget, 'password_id') and widget.password_id == password_id:
                item_frame = widget
                break

        if item_frame:
            root.after(100, lambda: select_item(None, password_id, item_frame, root))
        root.after(100, lambda: show_password_details(root, password_id))

def delete_selected_entry(password_id, root):
    global sqlite_obj
    confirm = messagebox.askyesno("Delete Entry", "Are you sure you want to delete this entry?")
    if confirm:
        # Now soft-delete the entry
        try:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Perform the update
            sqlite_obj.updateInTable("passwords", password_id , "isDeleted" , 'True' , commit = True , raiseError = True)
            sqlite_obj.updateInTable("passwords", password_id , "deletedAt" , current_time , commit = True , raiseError = True)
            messagebox.showinfo("Success", "Entry moved to trash in home page")
            show_password_health_content(root)  # Refresh the password list
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete entry: {e}")
        
def show_settings_content(root): 
    global sqlite_obj
    toggle_scrollbar(False)
    toggle_scrolling(False, root)

    # Function to display settings content
    for widget in main_frame.winfo_children():
        if widget != timer_label:  # Do not destroy the timer label
            widget.destroy()

    # Create a container frame that will center its contents
    container = tk.Frame(main_frame, bg="#f4f4f9")
    container.pack(fill=tk.BOTH, expand=True)
    container.config(width=root.winfo_width() - 50, height=root.winfo_height() - 75)  # Dynamically update container size
    container.pack_propagate(False)  # Prevent the frame from resizing to fit its contents

    # Create the sidebar and content area within the container
    sidebar = tk.Frame(container, width=220, bg="#f8f9fa", bd=1, relief="solid")
    sidebar.pack(side=tk.LEFT, fill=tk.Y)

    # Add sidebar header
    sidebar_header = tk.Frame(sidebar, bg="#e9ecef", height=40)
    sidebar_header.pack(fill=tk.X, pady=(0, 10))
    tk.Label(sidebar_header, text="SETTINGS", font=("Helvetica", 12, "bold"), 
            bg="#e9ecef", fg="#495057").pack(pady=10)

    # Create a frame to hold both content and scrollbar
    content_frame = tk.Frame(container, bd=1, relief="solid")
    content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
    
    # Create canvas and scrollbar
    canvas = tk.Canvas(content_frame, bg="white")
    scrollbar = tk.Scrollbar(content_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="white")
    
    # Configure scroll region
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    # Add scrollable frame to canvas
    canvas.create_window((0, 0), window=scrollable_frame, anchor="n")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Pack canvas and scrollbar
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    
    # Set content_area to the scrollable_frame for future content
    content_area = scrollable_frame

    # Display initial message - centered in the content area
    initial_msg_frame = tk.Frame(content_area, bg="white")
    initial_msg_frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(initial_msg_frame, 
             text="Here is the settings page. Click any option from the left sidebar to configure individual settings.", 
             font=("Helvetica", 14), 
             wraplength=400, 
             justify="center", fg="#495057").pack(pady=20, expand=True)

    # Sidebar options with icons (using text icons for simplicity)
    options = [
        {"name": "MFA", "icon": "🔒"},
        {"name": "Alerts", "icon": "🔔"},
        {"name": "Recovery Keys", "icon": "🔑"},
        {"name": "Backup & Restore", "icon": "💾"},
        {"name": "Autologout", "icon": "⏱️"},
        {"name": "Clipboard Timer", "icon": "📋"}
    ]

    # Global to track active button
    global active_settings_button
    active_settings_button = None
    
    # Function to handle button clicks
    def on_button_click(button, option_name):
        global active_settings_button
        
        # Reset previous active button
        if active_settings_button:
            active_settings_button.config(bg="#f8f9fa", fg="#495057", relief="flat")
        
        # Set new active button
        button.config(bg="#e2e6ea", fg="#0d6efd", relief="sunken")
        active_settings_button = button
        
        # Execute the corresponding function
        if option_name == "MFA":
            show_mfa_settings()
        elif option_name == "Alerts":
            show_alerts_settings()
        elif option_name == "Recovery Keys":
            show_recovery_keys_settings()
        elif option_name == "Backup & Restore":
            show_backup_settings()
        elif option_name == "Autologout":
            show_autologout_settings()
        elif option_name == "Clipboard Timer":
            show_clipboard_timer_settings()

    # Create sidebar buttons
    for option in options:
        btn_frame = tk.Frame(sidebar, bg="#f8f9fa")
        btn_frame.pack(fill=tk.X, padx=5, pady=2)
        
        button = tk.Button(btn_frame, 
                          text=f"  {option['icon']}  {option['name']}", 
                          anchor="w", 
                          font=("Helvetica", 11),
                          bg="#f8f9fa",
                          fg="#495057",
                          bd=0,
                          relief="flat",
                          padx=15,
                          pady=10)
        button.pack(fill=tk.X)
        
        # Bind hover effects
        button.bind("<Enter>", lambda e, b=button: b.config(bg="#e9ecef"))
        button.bind("<Leave>", lambda e, b=button: 
                   b.config(bg="#f8f9fa") if b != active_settings_button else None)
        
        # Bind click event
        button.config(command=lambda b=button, opt=option['name']: on_button_click(b, opt))

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

        try:
            # Prepare the update data as a dictionary
            result = sqlite_obj.getDataFromTable("settings", raiseConversionError=True, omitID=False)
            id = result[1][0][0] 
            # Perform the update using sqlite_obj
            sqlite_obj.updateInTable("settings", id , setting_name , setting_value, commit = True , raiseError = True)
            # Reload settings after saving
            global settings
            settings = load_settings()
            messagebox.showinfo("Success", "Settings saved successfully!")
            if callback:
                callback()

        except Exception as e:
            print(f"Database error: {e}")

    def show_mfa_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
        
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(center_frame, text="MFA Settings", font=("Helvetica", 16, "bold"), bg="white").pack(pady=10)
        
        # Settings container
        settings_frame = tk.LabelFrame(center_frame, text="Multi-Factor Authentication", 
                                     bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        settings_frame.pack(fill=tk.X, pady=10)
        
        mfa_var = tk.BooleanVar(value=settings[0])
        tk.Checkbutton(settings_frame, text="Enable MFA", variable=mfa_var, 
                      bg="white", font=("Helvetica", 11)).pack(anchor="w", pady=5)
        
        # Save button container
        btn_frame = tk.Frame(center_frame, bg="white")
        btn_frame.pack(pady=10)
        
        def show_qr_and_otp():
            otp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(otp_secret)
            qr_code = qrcode.make(totp.provisioning_uri("", issuer_name="Password Manager"))
            
            # Reduce the size of the QR code
            qr_code = qr_code.resize((200, 200), Image.LANCZOS)
            
            qr_code_img = ImageTk.PhotoImage(qr_code)
            
            # Place the setup key before the QR code
            tk.Label(settings_frame, text=f"Setup Key: {otp_secret}", font=("Helvetica", 10)).pack(pady=5)
            qr_label = tk.Label(settings_frame, image=qr_code_img)
            qr_label.image = qr_code_img
            qr_label.pack(pady=10)
            
            # Instructions for the user
            tk.Label(settings_frame, text="Use an authenticator app to scan the QR code or enter the setup key.", 
                    font=("Helvetica", 9), wraplength=500, justify="left").pack(pady=5)
            
            # OTP entry field
            tk.Label(settings_frame, text="Enter the OTP code from your authenticator app:", 
                    font=("Helvetica", 12)).pack(pady=10)
            otp_entry = tk.Entry(settings_frame, font=("Helvetica", 10), justify="center")
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

            verify_button = tk.Button(settings_frame, text="Verify and Save", 
                                    font=("Helvetica", 9), command=verify_and_save)
            verify_button.pack(pady=10)
            
            # Bind the Enter key to the verify_and_save function
            otp_entry.bind('<Return>', lambda event: verify_and_save())

        def save_mfa_setting():
            if settings[0] =='True' and mfa_var.get():  # MFA is already enabled
                messagebox.showinfo("MFA Already Enabled", "MFA is already enabled and cannot be re-enabled.")   
                return

            if mfa_var.get():  # Enabling MFA
                global password_verified
                # Only require master password once for backup settings
                if not password_verified:
                    if not require_master_password():
                        return
                    password_verified = True  # Set the flag after verifying the password
                save_btn.pack_forget()  # Hide the Save button
                show_qr_and_otp()
            else:  # Disabling MFA
                save_settings('mfa', 0, show_mfa_settings)
                save_settings('otp_secret', '', show_mfa_settings)  # Clear OTP secret
                messagebox.showinfo("Success", "MFA settings disabled.")

        save_btn = tk.Button(btn_frame, text="Save Settings", font=("Helvetica", 11, "bold"), 
                            bg="#4CAF50", fg="white", padx=10, pady=5, command=save_mfa_setting)
        save_btn.pack()

    def show_alerts_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
        
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(center_frame, text="Alerts Settings", font=("Helvetica", 16, "bold"), bg="white").pack(pady=10)
        
        # Settings container
        settings_frame = tk.LabelFrame(center_frame, text="Security Alerts", 
                                     bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        settings_frame.pack(fill=tk.X, pady=10)
        
        alerts_var = tk.BooleanVar(value=settings[1])
        tk.Checkbutton(settings_frame, text="Enable Security Alerts", variable=alerts_var, 
                      bg="white", font=("Helvetica", 11)).pack(anchor="w", pady=5)
        
        # Save button
        btn_frame = tk.Frame(center_frame, bg="white")
        btn_frame.pack(pady=10)
        
        save_btn = tk.Button(btn_frame, text="Save Settings", font=("Helvetica", 11, "bold"), 
                            bg="#4CAF50", fg="white", padx=10, pady=5,
                            command=lambda: save_settings('alerts', alerts_var.get(), show_alerts_settings))
        save_btn.pack()

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
        try:
            # Fetch existing recovery keys
            result = sqlite_obj.getDataFromTable("recovery_keys", raiseConversionError=True, omitID=False)

            if result[1]:  # Check if there are existing keys
                for idx, row in enumerate(result[1]):
                    row_id = int(row[0])  # Get the ID of the current row
                    # Update the hashed_key in the table for each row
                    sqlite_obj.updateInTable(
                        "recovery_keys", 
                        row_id, 
                        "hashed_key", 
                        hashed_recovery_keys[idx],  # Update with the corresponding new hashed key
                        commit=True, 
                        raiseError=True
                    )
        except Exception as e:
            print(f"Failed to save recovery keys: {e}")
            messagebox.showerror("Error", f"Failed to save recovery keys: {e}")
        # Display the new keys to the user
        for widget in keys_frame.winfo_children():
            widget.destroy()

        all_keys = ', '.join(new_keys)
        key_grid = tk.Frame(keys_frame, bg="white")
        key_grid.pack(fill=tk.BOTH, expand=True)
        # Display keys in a grid format
        for i in range(0, len(new_keys), 2):
            row_frame = tk.Frame(key_grid, bg="white")
            row_frame.pack(fill=tk.X, pady=2)
            tk.Label(row_frame, text=new_keys[i], font=("Helvetica", 11), 
                    bg="white", width=12, anchor="w").pack(side=tk.LEFT, padx=10)
            if i + 1 < len(new_keys):
                tk.Label(row_frame, text=new_keys[i + 1], font=("Helvetica", 11), 
                        bg="white", width=12, anchor="w").pack(side=tk.LEFT, padx=10)

        # Add a button to copy all keys
        copy_all_button = tk.Button(key_grid, text="Copy All Keys", font=("Helvetica", 11),
                                   command=lambda: copy_value(all_keys, root))
        copy_all_button.pack(pady=10)
        messagebox.showinfo("Recovery Keys Generated", "New recovery keys have been successfully generated.")

    def show_recovery_keys_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
        
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(center_frame, text="Recovery Keys", font=("Helvetica", 16, "bold"), bg="white").pack(pady=10)
        
        # Key management frame
        key_frame = tk.LabelFrame(center_frame, text="Key Management", 
                                bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        key_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(key_frame, text="Generate New Recovery Keys", font=("Helvetica", 11), 
                 command=generate_recovery_keys).pack(pady=10)
        
        # Display area
        display_frame = tk.LabelFrame(center_frame, text="Current Keys", 
                                    bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        display_frame.pack(fill=tk.X, pady=10)
        
        global keys_frame
        keys_frame = tk.Frame(display_frame, bg="white")
        keys_frame.pack(fill=tk.BOTH, expand=True)

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
        entry = tk.Entry(path_frame, textvariable=backup_path_var, font=("Helvetica", 11), width=40)
        entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        tk.Button(path_frame, text="Browse...", font=("Helvetica", 11),
                 command=lambda: browse_backup_dir(backup_path_var)).pack(side=tk.LEFT)

        # Save Button
        btn_frame = tk.Frame(center_frame, bg="white")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Save Settings", font=("Helvetica", 11, "bold"), bg="#4CAF50", fg="white", padx=10, pady=5,
                command=lambda: (
                    save_settings("backup", int(backup_var.get()), show_backup_settings),
                    save_settings("backup_path", backup_path_var.get(), show_backup_settings)
                )).pack()

        # Manual Backup
        manual_frame = tk.LabelFrame(center_frame, text="Manual Operations", bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        manual_frame.pack(fill=tk.X, pady=10)

        tk.Label(manual_frame, text="Manual Backup:", font=("Helvetica", 11), bg="white").pack(anchor="w", pady=(0, 5))
        tk.Button(manual_frame, text="Backup Now", font=("Helvetica", 11), command=manual_backup).pack(anchor="w", pady=5)

        tk.Label(manual_frame, text="Manual Restore:", font=("Helvetica", 11), bg="white").pack(anchor="w", pady=(10, 5))
        tk.Button(manual_frame, text="Restore Now", font=("Helvetica", 11), command=manual_restore).pack(anchor="w", pady=5)

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
        center_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(center_frame, text="Auto-Logout Settings", font=("Helvetica", 16, "bold"), bg="white").pack(pady=10)
        
        # Settings container
        settings_frame = tk.LabelFrame(center_frame, text="Inactivity Timeout", 
                                     bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        settings_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(settings_frame, text="Lock workspace after inactivity (seconds):", 
                font=("Helvetica", 11), bg="white").pack(anchor="w", pady=5)
        
        input_frame = tk.Frame(settings_frame, bg="white")
        input_frame.pack(fill=tk.X, pady=5)
        
        autologout_var = tk.IntVar(value=settings[3])
        validate_cmd = center_frame.register(validate_integer)
        spinbox = tk.Spinbox(input_frame, from_=0, to=3600, textvariable=autologout_var, 
                            width=5, font=("Helvetica", 11), 
                            validate='key', validatecommand=(validate_cmd, '%P'))
        spinbox.pack(side=tk.LEFT)
        tk.Label(input_frame, text="seconds", font=("Helvetica", 11), bg="white").pack(side=tk.LEFT, padx=5)
        
        # Save button
        btn_frame = tk.Frame(center_frame, bg="white")
        btn_frame.pack(pady=10)
        
        save_btn = tk.Button(btn_frame, text="Save Settings", font=("Helvetica", 11, "bold"), 
                            bg="#4CAF50", fg="white", padx=10, pady=5,
                            command=lambda: save_settings('autologout', autologout_var.get(), show_autologout_settings))
        save_btn.pack()

    def show_clipboard_timer_settings():
        for widget in content_area.winfo_children():
            widget.destroy()
            
        center_frame = tk.Frame(content_area, bg="white")
        center_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(center_frame, text="Clipboard Settings", font=("Helvetica", 16, "bold"), bg="white").pack(pady=10)
        
        # Settings container
        settings_frame = tk.LabelFrame(center_frame, text="Clipboard Clear Timer", 
                                     bg="white", font=("Helvetica", 12, "bold"), padx=10, pady=10)
        settings_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(settings_frame, text="Clear clipboard after (seconds):", 
                font=("Helvetica", 11), bg="white").pack(anchor="w", pady=5)
        
        input_frame = tk.Frame(settings_frame, bg="white")
        input_frame.pack(fill=tk.X, pady=5)
        
        seconds_var = tk.IntVar(value=settings[4])
        validate_cmd = center_frame.register(validate_integer)
        spinbox = tk.Spinbox(input_frame, from_=0, to=3600, textvariable=seconds_var, 
                            width=5, font=("Helvetica", 11), 
                            validate='key', validatecommand=(validate_cmd, '%P'))
        spinbox.pack(side=tk.LEFT)
        tk.Label(input_frame, text="seconds", font=("Helvetica", 11), bg="white").pack(side=tk.LEFT, padx=5)
        
        # Save button
        btn_frame = tk.Frame(center_frame, bg="white")
        btn_frame.pack(pady=10)
        
        save_btn = tk.Button(btn_frame, text="Save Settings", font=("Helvetica", 11, "bold"), 
                            bg="#4CAF50", fg="white", padx=10, pady=5,
                            command=lambda: save_settings('clipboard_timer', seconds_var.get(), show_clipboard_timer_settings))
        save_btn.pack()

    # Load current settings
    global settings
    settings = load_settings()

    # Sidebar buttons
    for option in options:
        load_settings()
        if option == "MFA":
            button = tk.Button(sidebar, text=option, anchor="w", font=("Helvetica", 11),
                             command=show_mfa_settings)
        elif option == "Alerts":
            button = tk.Button(sidebar, text=option, anchor="w", font=("Helvetica", 11),
                             command=show_alerts_settings)
        elif option == "Recovery Keys":
            button = tk.Button(sidebar, text=option, anchor="w", font=("Helvetica", 11),
                             command=show_recovery_keys_settings)
        elif option == "Backup & Restore":
            button = tk.Button(sidebar, text=option, anchor="w", font=("Helvetica", 11),
                             command=show_backup_settings)
        elif option == "Autologout":
            button = tk.Button(sidebar, text=option, anchor="w", font=("Helvetica", 11),
                             command=show_autologout_settings)
        elif option == "Clipboard Timer":
            button = tk.Button(sidebar, text=option, anchor="w", font=("Helvetica", 11),
                             command=show_clipboard_timer_settings)
        button.pack(fill=tk.X, pady=5, padx=5)

def automatic_backup():
    global sqlite_obj
    
    # Fetch backup enabled status and backup path from the "settings" table
    result = sqlite_obj.getDataFromTable("settings", raiseConversionError=True, omitID=True)
    
    if not result[1]:  # If no settings found, return early
        print("Settings not found.")
        return
    
    # Get the backup settings (enabled and path)
    enabled= result[1][0][2] 
    path = result[1][0][6]

    if enabled  == 'True':
        try:
            os.makedirs(path, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(path, f"backup_{timestamp}.db")
            shutil.copy(DB_FILE, backup_file)
            # Optional: Add backup rotation here
            print(f"Backup successfully created at {backup_file}")
        except Exception as e:
            print(f"Backup failed: {str(e)}")

def schedule_backups():
    automatic_backup()
    # Run daily (86400 seconds)
    threading.Timer(86400, schedule_backups).start()


def load_settings():
    global sqlite_obj

    # Fetch the settings from the "settings" table
    result = sqlite_obj.getDataFromTable("settings", raiseConversionError=True, omitID=True)
    
    # Get the first row of settings
    settings = result[1][0]  # Assuming the first row contains the settings
    return settings

def increment_login_attempt():
    global sqlite_obj
    
    # Fetch the current attempts and lockout_until from the "login_attempts" table
    result = sqlite_obj.getDataFromTable("login_attempts", raiseConversionError=True, omitID=False)
    
    if not result[1]:  # If there are no rows, initialize the login attempts data
        sqlite_obj.insertIntoTable("login_attempts", [0, None, None], commit=True)
        return 1  # The first login attempt
    
    # Get the first row (attempts, lockout_until) and its ID
    id_value, current_attempts, last_attempt, lockout_until_str = result[1][0]  # The first element is the ID
    print(f"Current attempts: {current_attempts}, Last attempt: {last_attempt}, Lockout until: {lockout_until_str}")
    new_attempts = int(current_attempts) + 1
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if new_attempts >= 5:
        # Lock the account for 1 hour
        lockout_until = datetime.now() + timedelta(hours=1)
        sqlite_obj.updateInTable("login_attempts", id_value, "attempts", new_attempts, commit=True, raiseError=True)
        sqlite_obj.updateInTable("login_attempts", id_value, "last_attempt", current_time, commit=True, raiseError=True)
        sqlite_obj.updateInTable("login_attempts", id_value, "lockout_until", lockout_until.isoformat(), commit=True, raiseError=True)
    else:
        # No lockout, just increment the attempts and update the last attempt time
        sqlite_obj.updateInTable("login_attempts", id_value, "attempts", new_attempts, commit=True, raiseError=True)
        sqlite_obj.updateInTable("login_attempts", id_value, "last_attempt", current_time, commit=True, raiseError=True)
    
    return new_attempts

def check_lockout_status():
    global sqlite_obj
    
    # Fetch login attempts and lockout_until values from the "login_attempts" table
    result = sqlite_obj.getDataFromTable("login_attempts", raiseConversionError=True, omitID=False)
    
    if not result[1]:  # If there are no rows, assume no lockout
        return False, None
    
    # Get the first row (attempts, lockout_until) and its ID
    id_value, attempts, last_attempt, lockout_until_str = result[1][0]  # The first element is the ID
    lockout_until = None
    
    if lockout_until_str and lockout_until_str != 'None':
        lockout_until = datetime.fromisoformat(lockout_until_str)
        if datetime.now() < lockout_until:
            # Lockout is still active
            return True, lockout_until
        else:
            # Reset expired lockout by using updateInTable
            sqlite_obj.updateInTable("login_attempts", id_value, "attempts", 0, commit=True, raiseError=True)
            sqlite_obj.updateInTable("login_attempts", id_value, "lockout_until", None, commit=True, raiseError=True)
    
    # If no lockout, return False
    return False, None

def reset_login_attempts():
    global sqlite_obj
    
    # Fetch the ID of the row in the "login_attempts" table
    result = sqlite_obj.getDataFromTable("login_attempts", raiseConversionError=True, omitID=False)
    
    if not result[1]:  # If there are no rows, we can't reset attempts
        return
    
    # Get the ID from the first row
    id_value = result[1][0][0]  # Assuming the first column is the ID

    # Reset the attempts and lockout_until fields to 0 and NULL respectively
    sqlite_obj.updateInTable("login_attempts", id_value, "attempts", 0, commit=True, raiseError=True)
    sqlite_obj.updateInTable("login_attempts", id_value, "lockout_until", None, commit=True, raiseError=True)

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
def toggle_scrolling(enable, root):
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

def transform_key(seed: int) -> str:
    """Generate a dynamic key using mathematical transformations"""
    key = []
    # Multi-step transformation using bitwise operations
    a = (seed ^ 0xDEADBEEF) + 0x2F7A83C
    b = (a << 3) | (a >> 29)
    c = b ^ 0x8C9A6B5
    d = (c * 0x2D) & 0xFFFFFFFF
    
    # Convert to characters using selective bit masking
    for i in range(12):
        val = d >> (i * 3) & 0x7F
        if 33 <= val <= 126:  # Printable ASCII range
            key.append(chr(val))
        else:
            key.append(chr((val % 93) + 33))
    
    return ''.join(key)

def decode_password(encoded: bytes, key: str) -> str:
    """XOR decoding with key rotation"""
    # Perform XOR operation
    decoded_bytes = bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(encoded)])
    
    # Convert to string, but filter non-printable characters
    decoded_str = ''.join(chr(b) for b in decoded_bytes if 32 <= b <= 126)  # Printable ASCII range
    
    return decoded_str

def get_db_password() -> str:
    """Retrieve password through multiple obfuscation layers"""
    # Layer 1: Encoded byte sequence (appears as random bytes)
    encoded = b'\x44\x44\xd9\xb9\x2e\x25\xd6\xec\x99\x7f\x19\x3f\xf5\x31\x51\x74'

    # Layer 2: Dynamic key generation from mathematical seed
    key_seed = 0x323755325C495F553F75286E # Appears as a random constant
    dynamic_key = transform_key(key_seed)
    
    # Layer 3: Multiple decoding passes
    temp = decode_password(encoded, dynamic_key)
    final = decode_password(temp.encode(), dynamic_key[::-1])
    
    # Layer 4: Final transformation
    return final.swapcase().translate(str.maketrans('s5!3', '$S%3'))

def create_directories():
    # Check if Backup folder exists, if not, create it
    if not os.path.exists("Backup"):
        os.makedirs("Backup")

    # Check if Rainbow_Table folder exists, if not, create it
    if not os.path.exists("Rainbow_Table"):
        os.makedirs("Rainbow_Table")

def main():
    # Create a mutex to prevent multiple instances (only once per process)
    if not hasattr(main, "mutex_created"):
        mutex = win32event.CreateMutex(None, False, "PasswordManagerAppMutex")
        last_error = win32api.GetLastError()
        
        # Check if another instance is already running
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            # Use ctypes to show message box without initializing Tkinter
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, 
                                            "Another instance of the Password Manager is already running.", 
                                            "Error", 
                                            0x10)  # 0x10 = MB_ICONERROR
            return
        
        # Mark mutex as created for this process
        main.mutex_created = True

    global master_password
    global sqlite_obj
    global db_password 

    # Create the necessary directories
    create_directories()

    # Get password through obfuscation layers
    db_password = get_db_password()

    # Define all inner functions at the top level of main()
    def show_login_screen():
        global login_root
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
                    # Retrieve the stored key using sqlite_obj
                    try:
                        result = sqlite_obj.getDataFromTable(
                            "master_password",
                            raiseConversionError=True,
                            omitID=True
                        )

                        if result[1]:
                            stored_hashed_password = base64.b64decode(result[1][0][0])
                            key = stored_hashed_password[16:]
                            master_password = recovery_key
                            login_root.withdraw()
                            check_mfa_and_show_main_window()
                            return
                        else:
                            messagebox.showerror("Error", "No recovery key found! Please enter a valid recovery key.")
                            login_root.destroy()
                            show_login_screen()
                            return

                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to retrieve recovery key: {e}")
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

            login_root.withdraw()
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

        def on_closing_login():
            login_root.quit()  # This stops the Tkinter main loop
            login_root.destroy()  # Destroys the Tkinter window
            os._exit(0)   # Terminates the program completely
            exit()

        login_root.bind('<Return>', on_enter)
        login_root.protocol("WM_DELETE_WINDOW", on_closing_login)

        login_root.after(100, login_root.focus_force)
        login_root.after(200, lambda: master_password_entry.focus())
        login_root.mainloop()

    def check_mfa_and_show_main_window():
        global settings
        settings = load_settings()
        if settings[0] == 'True': # MFA is enabled
            encrypted_otp_secret = settings[5]
            if verify_otp(encrypted_otp_secret):
                show_main_window()
                if 'login_root' in globals() and login_root:
                    login_root.destroy()  # Close login window if MFA is successful
            else:
                show_login_screen()
        else:
            show_main_window()
            login_root.destroy()

    def show_main_window():
        global canvas, scrollbar, scroll_enabled, item_context_menu
        root = tk.Toplevel()
        root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))
        root.title("Password Manager")
        root.minsize(700, 550) 
        root.configure(bg="#f0f0f0") # Light background color

        # Set window icon
        root.iconbitmap(default="./Images/logo.ico")

        # Bind the reset_timer function to user activity events
        root.bind_all("<Button-1>", reset_timer)
        root.bind_all("<Key>", reset_timer)

        # Create a container frame that will hold both the nav bar and the scrollable content
        container = tk.Frame(root, bg="#f4f4f9")
        container.pack(fill=tk.BOTH, expand=True)

        # Create a navigation bar as a Frame - packed in container, not root
        global nav_bar
        nav_bar = tk.Frame(container, bg="#333333", height=50)
        nav_bar.pack(side=tk.TOP, fill=tk.X)

        # Add a placeholder to maintain height
        placeholder = tk.Frame(nav_bar, width=30, height=30, bg="#333333")
        placeholder.pack(side=tk.RIGHT, padx=10)

        # Navigation options
        home_label = tk.Label(nav_bar, text="Home", fg="white", bg="#333333", font=("Arial", 12), cursor="hand2")
        home_label.pack(side=tk.LEFT, padx=10)
        home_label.bind("<Button-1>", lambda e: show_home_content(root))

        # Password Health label with dynamic text and icon
        global password_health_label, exclamation_label
        password_health_label = tk.Label(nav_bar, text="Password Health", fg="white", bg="#333333", font=("Arial", 12), cursor="hand2")
        password_health_label.pack(side=tk.LEFT)
        password_health_label.bind("<Button-1>", lambda e: show_password_health_content(root))

        # Exclamation mark (⚠️) label with dynamic red color
        exclamation_label = tk.Label(nav_bar, text="", fg="white", bg="#333333", font=("Arial", 12), cursor="hand2")
        exclamation_label.pack(side=tk.LEFT)
        exclamation_label.bind("<Button-1>", lambda e: show_password_health_content(root))

        settings_label = tk.Label(nav_bar, text="Settings", fg="white", bg="#333333", font=("Arial", 12), cursor="hand2")
        settings_label.pack(side=tk.LEFT, padx=10)
        settings_label.bind("<Button-1>", lambda e: show_settings_content(root))

        # Create a main frame with scrollbar - packed in container, below nav_bar
        global main_frame
        main_container = tk.Frame(container, bg="#f4f4f9")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create a canvas for scrolling
        canvas = tk.Canvas(main_container, bg="#f4f4f9", highlightthickness=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(main_container, orient=tk.VERTICAL, command=canvas.yview)
        
        # Configure the canvas
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # Create main frame inside the canvas
        main_frame = tk.Frame(canvas, bg="#f4f4f9")
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

        # Create a footer frame for the timer label
        footer_frame = tk.Frame(container, bg="#f4f4f9", height=40)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)

        # Create a timer label inside the footer frame
        global timer_label
        timer_label = tk.Label(footer_frame, text="", bg="#f4f4f9", font=("Arial", 10))
        timer_label.pack(side=tk.BOTTOM, padx=10, pady=5)

        # Reset the last activity time after successful login
        reset_timer()

        schedule_backups()

        # Center window
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() - width) // 2
        y = (root.winfo_screenheight() - height) // 2
        root.geometry(f"+{x}+{y}")

        # Store references to periodic tasks
        global inactivity_after_id, password_health_after_id
        inactivity_after_id = None
        password_health_after_id = None
        
        # Start tasks and store their IDs
        inactivity_after_id = root.after(1000, lambda: check_inactivity(root))
        password_health_after_id = root.after(0, periodic_update_nav_bar_password_health, root)

        show_home_content(root)

        # Start checking for inactivity
        check_inactivity(root)

        # Check for password issues and update the nav bar
        periodic_update_nav_bar_password_health(root)

        # Start the main event loop
        root.mainloop()

    # Check if the database exists
    if not os.path.exists(DB_FILE):
        master_password = initial_setup()
        if master_password is None:
            return  # Exit if user cancels

        sqlite_obj = sqlitewrapper.SqliteCipher(
            dataBasePath=DB_FILE,
            checkSameThread=False,
            password=db_password
        )

        # Setup the new database
        setup_database()
        store_master_password(master_password)
        messagebox.showinfo("Success", "New password database created successfully!")
        
        # Now call show_login_screen since we've defined it above
        show_login_screen()
    else:
        sqlite_obj = sqlitewrapper.SqliteCipher(
            dataBasePath=DB_FILE,
            checkSameThread=False,
            password=db_password
        )
        show_login_screen()

if __name__ == "__main__":
    main()