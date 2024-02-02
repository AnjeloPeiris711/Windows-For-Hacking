# Bunny 
```rust
    (\_/)
    (. .) BUNNY!
  C('')('') 0.1.0
```
$${\color{red}For \space Only \space Educational \space purposes }$$

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
  - [Command Line Options](#command-line-options)
  - [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)


## Installation
> Bunny 0.1.0 Installation Guide

Follow these steps to install Bunny version 0.1.0 on your system.

>> Step 1: Download Bunny 0.1.0

Go to the [Releases](https://github.com/your-username/bunny/releases) section on GitHub and download the `bunny0.1.0.zip` file.

>> Step 2: Extract the ZIP File

After downloading, extract the contents of `bunny0.1.0.zip` to a directory of your choice.

>> Step 3: Install npcap.exe

Navigate to the extracted directory, and you will find the `npcap.exe` file. This executable is required for Bunny to function properly. Follow the steps below to install it:

1. Double-click on `npcap.exe`.
2. To complete the installation process, follow the on-screen instructions as outlined below:
   
Press `Yes` when prompted.
![1](https://github.com/AnjeloPeiris711/Windows-For-Hacking/assets/51872510/07a43637-5745-4ff6-ba6a-a954373a0954)
Press `I Agree` to accept the terms and conditions.

![2](https://github.com/AnjeloPeiris711/Windows-For-Hacking/assets/51872510/280566d8-609d-4ac3-9db1-d082ea8c53e6)

---
**NOTE**
Please ensure to check the following two boxes before proceeding: 
- [X] Support raw 802.11 traffic (and monitor mode) for wireless adapters
- [x] Install Npcap in WinPcap API-compatible Mode

    After checking the boxes, click on `Install`.
---
![3](https://github.com/AnjeloPeiris711/Windows-For-Hacking/assets/51872510/b6554095-3d99-4bfc-bffa-ae6f2b9a8824)
![4](https://github.com/AnjeloPeiris711/Windows-For-Hacking/assets/51872510/9035efff-8fd4-4e0a-b9c1-b2de8502ca0c)

Click on `Next` when prompted to proceed

Finally, click on `Finish` to complete the installation process.

![5](https://github.com/AnjeloPeiris711/Windows-For-Hacking/assets/51872510/516c85c9-f545-40dd-81f0-928ef65dc33f)

>> Step 4: Verify Installation

Once the installation is complete, open a `PowerShell ` using `Administrator Privileges` and navigate to the extracted directory run the following command to verify that `bunny, npcap ` are working correctly:


## Usage
```bash
🐰\your_directory>.\bunny.exe -h


        (\_/)
        (. .) BUNNY!
       C('')('') 0.1.0


Usage: bunny.exe [OPTIONS] [COMMAND]

Commands:
  -C    crack the password
  -D    Dump Packets
  -M    Change the interface Mode
  help  Print this message or the help of the given subcommand(s)

Options:
  -i, --interface  Identify Network interface
  -n, --npcap      Check the Npcap is Installed
  -d, --dump       Dump the Packets
  -h, --help       Print help
  -V, --version    Print version
```
Execute the command `.\bunny.exe -n`, and you will observe an output similar to the following:
```bash
Npcap version: Npcap version 1.78, based on libpcap version 1.10.4
```
### Command Line Options:
``` bash
-C, --crack
Crack the Password:
   Initiates the password cracking process.

-D, --Dump
Dump Packets:
   Captures and Save network packets for analysis.

-M, --mode
Change the Interface Mode:
   Allows dynamic switching of the network interface mode.

-help
Print this Message or the Help of the Given Subcommand(s):
   Displays the general help message or specific help for provided subcommands.

> Options:

-i, --interface
Identify Network Interface:
   Provides information about the available network interfaces.

-n, --npcap
Check if Npcap is Installed:
   Verifies the presence of the Npcap software.

-d, --dump
Dump the Packets:
   Display packet details.

-h, --help
Print Help:
   Displays information about the usage and options.

-V, --version
Print Version:
   Outputs the version information of the application.
```
