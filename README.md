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
- Find the latest version of the **password-manager-installer.exe** file and **click on it** to download it.

### 2. Run the Installer
- After downloading the installer, **double-click** it to run.
- Follow the **on-screen instructions** to complete the installation process.

### 3. Launch the Password Manager
- Once the installation is complete, navigate to the installation folder and **launch `password_manager.exe`** to start the program.

---

## Optional: Enabling Rainbow Table Attack Feature

If you want to use the **Rainbow Table** attack method for estimating the crack time and actual attack crack time, follow these additional steps:

### 4. Install BitTorrent Web
To use the Rainbow Table attack, you will need **BitTorrent Web**:
- Download BitTorrent Web from [here](https://www.bittorrent.com/downloads/windows/).
- Follow the **on-screen instructions** to install it.

### 5. Download Rainbow Tables
- Visit [Free Rainbow Tables](https://freerainbowtables.com/download).
- Download the **MD5 hash rainbow tables** from the available options. The system by default uses the **"mixalpha-numeric-symbol32-space#1-7"** rainbow table, which supports password lengths from 1 to 7 characters and includes lowercase, uppercase, digits, and special characters.

**Recommended Download:**
- **File Size**: **86 GB** (4 parts: Part 0, Part 1, Part 2, Part 3).
- To download, click on **Part 0**, **Part 1**, **Part 2**, and **Part 3** to get the `.torrent` files.

### 6. Open .torrent Files in BitTorrent Web
- Once the `.torrent` files are downloaded, navigate to the folder where they are located.
- **Double-click** each `.torrent` file to open it in **BitTorrent Web**.
- Follow the **on-screen instructions** to start the download and wait for the process to complete.

### 7. Store Rainbow Tables
- Once all parts of the rainbow tables have been downloaded, **move** them to the `Rainbow_Table` folder inside the Password Manager installation directory.
  
### 8. Optional: Change the Rainbow Table Path
If you want to change the default location of the Rainbow Tables:
- Launch `password_manager.exe`.
- Click the **"+"** button to **add a new password entry** or click on an existing password entry.
- Click the **Test** button beside the password strength indicator.
- Enter a test password, and then from the **Attack Method dropdown**, select **Rainbow Table Attack**.
- In the **Rainbow Table Path** field, browse to the folder where you downloaded the rainbow tables.
- The new path will be automatically saved.

---

## Conclusion

After completing these steps, you will have successfully installed the Password Manager and set up the Rainbow Table attack functionality if desired.

For any issues or questions, feel free to open an issue or refer to the documentation provided in the repository.

Happy password managing! 🛡️
