# 🔒 Password Manager – Secure Offline Password Solution

This Password Manager is a secure, offline solution designed to help users manage and protect their passwords effectively. It encrypts stored credentials using **AES encryption**, with keys securely derived through **PBKDF2**, ensuring strong resistance against brute-force attacks.

### 📺 Demo Video  
Watch a full demo of the system:  
👉 [Watch on YouTube](https://youtu.be/w1cOuZHBx-M)

The system addresses common password security concerns—such as weak, reused, or compromised credentials—by integrating features like:

- 🔑 **Password Generator** for strong, random password creation  
- 🛡️ **Breach Checker** using the [Pwned Passwords API](https://github.com/lionheart/pwnedpasswords)  
- 🔐 **Multi-Factor Authentication (MFA)** and a **Recovery Key** to reduce the risk of total lockout  
- 🧠 **Password Strength Tester** that simulates real-world cracking techniques:
  - Brute-force
  - AES brute-force
  - Dictionary attacks (using [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords))
  - Rainbow table attacks (powered by [`rcracki_mt`](https://github.com/foreni-packages/rcracki_mt))

The app is fully offline, except for optional breach checks, offering full user data control. It also includes **performance/security analysis** tools to help users understand trade-offs in password encryption techniques.

---

## 🛠️ Password Manager Installation Guide

### Prerequisites

- Windows 10 or 11
- Minimum 400 MB of free disk space
- Optional: 100+ GB for Rainbow Tables (if using the Rainbow Table attack feature)

---

### 1. Download the Latest Version

- Navigate to the **[Releases section](https://github.com/Rakoim/FYP_Password_Manager/releases)**.
- Download:
  - `password-manager-installer.exe`
  - `User_Manual.pdf` (for usage instructions and screenshots)

---

### 2. Run the Installer

- Double-click `password-manager-installer.exe`
- Follow the on-screen installation instructions

---

### 🔐 SmartScreen Warning Explained

Windows Defender SmartScreen may show:

> "Windows protected your PC"

This warning appears because the installer is **not digitally signed**.  
Due to **budget limitations**, a trusted code-signing certificate was not purchased.

✅ To proceed:
- Click **“More info”**
- Click **“Run anyway”**

This is common for new and unsigned applications. The installer is safe.

---

### 🛡️ Virus Scan Verification

The installer has been scanned using **VirusTotal** and is **safe to use**.

- 📊 [VirusTotal Scan Report](https://www.virustotal.com/gui/file/a618a6b8e7c14ee556dca3d979e437c22f666574785ca82b0fe801ba290ccdd9/detection)
- Detection: **1 / 70** (Bkav Pro)
- 🧪 [Bkav false-positive details](https://hackerdose.com/malware/w32-aidetectmalware-bkav-pro/)

The single alert is a **false positive**, commonly seen in unsigned applications.

---

### ⚠️ Important Installation Notice

**Do NOT install the app into protected system directories:**
- `C:\Program Files`
- `C:\Program Files (x86)`

✅ Instead, install in user-accessible folders such as:
- `C:\Users\YourName\Downloads\PasswordManager`
- `C:\Users\YourName\Documents\PasswordManager`
- `C:\Users\YourName\Videos\PasswordManager`

This avoids permission issues and ensures smooth operation.

---

### 3. Launch the App

- Navigate to the installation folder
- Run `password_manager.exe`

---

## Optional: Enabling Rainbow Table Attack Feature

If you want to use the **Rainbow Table** attack method for estimating crack time, follow these additional steps:

### 4. Install BitTorrent Web
To use the Rainbow Table attack, you will need **BitTorrent Web**:

- Download it from [https://www.bittorrent.com/downloads/windows/](https://www.bittorrent.com/downloads/windows/)
- Follow the on-screen instructions to install.

### 5. Download Rainbow Tables
- Visit [https://freerainbowtables.com/download](https://freerainbowtables.com/download)
- Download the **MD5 hash rainbow tables**:
  - Recommended set: `mixalpha-numeric-symbol32-space#1-7`
  - Supports password lengths of 1–7 characters with uppercase, lowercase, digits, and special characters.

**Recommended Download:**
- **File Size:** ~86 GB total
- **Parts:** Part 0, Part 1, Part 2, Part 3
- Download each `.torrent` file for these parts.

### 6. Open `.torrent` Files in BitTorrent Web
- Double-click each `.torrent` file to open it in **BitTorrent Web**.
- Start and complete the download process.

### 7. Store Rainbow Tables
- Once downloaded, **move the rainbow tables** into the `Rainbow_Table` folder inside the Password Manager installation directory.

### 8. (Optional) Change Rainbow Table Path
To specify a different folder for the rainbow tables:

1. Launch `password_manager.exe`.
2. Click the **"+"** button to add a new password entry or edit an existing one.
3. Click **Test** beside the password strength indicator.
4. From the **Attack Method** dropdown, choose **Rainbow Table Attack**.
5. Set a new **Rainbow Table Path** using the file browser.
6. The new path will be saved automatically.

---

## Conclusion

You’ve now successfully installed the Password Manager and optionally enabled the Rainbow Table attack feature.

If you encounter any issues, feel free to:
- Open an issue on this repository
- Refer to the included documentation
- 📖 **Refer to the `User_Manual.pdf` you downloaded** for additional help and screenshots

**Happy password managing! 🛡️**

