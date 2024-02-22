# Active Directory Manager
 A PowerShell script designed to streamline and expedite Active Directory tasks.

## Overview

This PowerShell script provides a user interface for interacting with Active Directory, allowing users to search for and manage user and computer objects. It includes features such as displaying user properties, moving users and computers to different OUs, and retrieving BitLocker information.

## Prerequisites

- Windows PowerShell
- Active Directory PowerShell Module

## Usage

1. **Search for User or Computer:**
   - Enter the user's first and last name or LogonName to search for users.
   - Enter the computer name to search for computers.
   - Choose the search type from the dropdown menu.

2. **View/Search Results:**
   - View user or computer properties in the output box.
   - User groups are displayed in a checklist.

3. **Manage Users and Computers:**
   - Move users or computers to different OUs using the provided button.
   - Retrieve and display BitLocker information for computers.

4. **Buttons:**
   - Various buttons for specific actions like unlocking domains, setting expiration, retrieving LAPS passwords, and more.

## Features

- Search for users and computers in Active Directory.
- Display and manage user and computer properties.
- Move users and computers to different OUs.
- Retrieve BitLocker information for computers.
- LAPS password retrieval for computers.

## Installation

No installation is required. Ensure that you have the required prerequisites installed.

## How to Run

1. Open PowerShell.
2. Navigate to the directory containing the script.
3. Run the script: `.\Manager.ps1`

    > **Note:** If you prefer, you can also run the script by right-clicking on it in File Explorer and selecting "Run with PowerShell."


## Notes

- The script dynamically connects to Active Directory when a search is initiated, so it might take a moment.
- Ensure that you have the necessary permissions to perform the intended actions.

- Before running the script, set the following variables manually (located on lines 13-15):

    - `$domain`: Specify the Active Directory domain.
    - `$computerOUPath`: Set the default Organizational Unit (OU) path for computer objects.
    - `$userOUPath`: Set the default Organizational Unit (OU) path for user objects.

## Limitations

- **Performance Context:**
  - This script was developed to address the sluggish performance of the Active Directory GUI in my specific work context. For users in environments where the Active Directory GUI is more feature-rich and performs optimally, this script may not provide significant advantages.

- **Limited Support for Computer Object Groups:**
  - The script does not natively support managing computer object groups. This limitation is based on the specific practices in my current position, where computers are not assigned to specific groups.

- **Single Domain Focus:**
  - The script does not support changing domains for logon names. This limitation is intentional, as my current position utilizes only one domain. Support for multiple domains is not included to keep the script focused on its primary use case.

- **Purposeful Scope:**
  - This script is not intended to be an all-encompassing tool for Active Directory management. Instead, it serves as a tailored solution for the specific Active Directory tasks required in my current position. Its design is focused on streamlining and enhancing the specific functionalities needed for daily tasks.
