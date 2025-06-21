# Password Manager Installation Guide

## Prerequisites

Before installing the Password Manager, please ensure your system meets the following requirements:

- **Windows 10 or 11** operating system.
- **Default Storage Requirement**: At least **400 MB** of available storage for the Password Manager application.
- **Rainbow Table Attack Feature (Optional)**:
  - Requires **at least 100 GB** of available storage for downloading and storing the Rainbow Tables.

## Installation Steps

### 1. Download the Latest Version
- Navigate to the top of the **Releases** section on the right side of this page.
- Find the latest version of the `password-manager-installer.exe` file and **click on it** to download it.

### 2. Run the Installer
- After downloading the installer, **double-click** it to run.
- Follow the **on-screen instructions** to complete the installation process.

> ⚠️ **Important:** Do **NOT** install the application in default system folders like:
> - `C:\Program Files`
> - `C:\Program Files (x86)`
>
> Instead, install it in a user-accessible directory such as:
> - `C:\Users\YourName\Downloads\PasswordManager`
> - `C:\Users\YourName\Documents\PasswordManager`
> - `C:\Users\YourName\Videos\PasswordManager`

### 3. Launch the Password Manager
- Once the installation is complete, navigate to the installation folder and **launch `password_manager.exe`** to start the program.

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

**Happy password managing! 🛡️**