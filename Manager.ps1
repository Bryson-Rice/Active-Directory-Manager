# Check if the script is running with administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    # Start a new PowerShell process with administrator privileges
    $arg = "-NoProfile -WindowStyle Hidden -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell -Verb RunAs -ArgumentList $arg

    # Exit the current script
    exit
}

#Variables for different domains and OUs for others to config to their need
$domain = "ENTER_DOMAIN_HERE" 
$computerOUPath = "ENTER_OU_PATH_FOR_COMPUTERS_HERE"
$userOUPath = "ENTER_OU_PATH_FOR_USERS_HERE"

# Load Windows Forms assembly
Add-Type -AssemblyName System.Windows.Forms

# Create a form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Active Directory Manager v1.2.5"
$form.Size = New-Object System.Drawing.Size(970, 500)

# Create labels for instructions
$inputLabelUser = New-Object System.Windows.Forms.Label
$inputLabelUser.Text = "User's First and Last name:"
$inputLabelUser.Size = New-Object System.Drawing.Size(200, 20)
$inputLabelUser.Location = New-Object System.Drawing.Point(50, 5)

$inputLabelLogonName = New-Object System.Windows.Forms.Label
$inputLabelLogonName.Text = "User's LogonName:"
$inputLabelLogonName.Size = New-Object System.Drawing.Size(200, 20)
$inputLabelLogonName.Location = New-Object System.Drawing.Point(50, 5)
$inputLabelLogonName.Visible = $false

$inputLabelComputer = New-Object System.Windows.Forms.Label
$inputLabelComputer.Text = "Comptuer Name or last digits of serial number:"
$inputLabelComputer.Size = New-Object System.Drawing.Size(300, 20)
$inputLabelComputer.Location = New-Object System.Drawing.Point(50, 5)
$inputLabelComputer.Visible = $false

$groupLabel = New-Object System.Windows.Forms.Label
$groupLabel.Text = "Name of Group to add:"
$groupLabel.Size = New-Object System.Drawing.Size(200, 20)
$groupLabel.Location = New-Object System.Drawing.Point(750, 5)

# Create TextBox for input
$inputTextBox = New-Object System.Windows.Forms.TextBox
$inputTextBox.Size = New-Object System.Drawing.Size(300, 20)
$inputTextBox.Location = New-Object System.Drawing.Point(50, 25)

# Create TextBox for entering a new group
$newGroupTextBox = New-Object System.Windows.Forms.TextBox
$newGroupTextBox.Size = New-Object System.Drawing.Size(150, 20)
$newGroupTextBox.Location = New-Object System.Drawing.Point(750, 25)

# Create ComboBox for selecting search type
$searchTypeComboBox = New-Object System.Windows.Forms.ComboBox
$searchTypeComboBox.Items.AddRange(@("Name", "LogonName", "Computer Name"))
$searchTypeComboBox.SelectedIndex = 0
$searchTypeComboBox.Location = New-Object System.Drawing.Point(400, 25)

# Create a button for searching users
$searchUserButton = New-Object System.Windows.Forms.Button
$searchUserButton.Text = "Search User"
$searchUserButton.Location = New-Object System.Drawing.Point(550, 25)

# Create buttons above the output box
$enableAccountButton = New-Object System.Windows.Forms.Button
$enableAccountButton.Text = "Enable Account"
$enableAccountButton.Size = New-Object System.Drawing.Size(120, 23)
$enableAccountButton.Location = New-Object System.Drawing.Point(50, 70)

$unlockDomainButton = New-Object System.Windows.Forms.Button
$unlockDomainButton.Text = "Unlock Domain"
$unlockDomainButton.Size = New-Object System.Drawing.Size(120, 23)
$unlockDomainButton.Location = New-Object System.Drawing.Point(195, 70)

$setNeverExpireButton = New-Object System.Windows.Forms.Button
$setNeverExpireButton.Text = "Set Never Expire"
$setNeverExpireButton.Size = New-Object System.Drawing.Size(120, 23)
$setNeverExpireButton.Location = New-Object System.Drawing.Point(340, 70)

$moveToOUButton = New-Object System.Windows.Forms.Button
$moveToOUButton.Text = "Move to OU"
$moveToOUButton.Size = New-Object System.Drawing.Size(120,23)
$moveToOUButton.Location = New-Object System.Drawing.Point(485,70)

$addGroupButton = New-Object System.Windows.Forms.Button
$addGroupButton.Text = "Add Group"
$addGroupButton.Size = New-Object System.Drawing.Size(120, 23)
$addGroupButton.Location = New-Object System.Drawing.Point(630, 70)

$removeGroupButton = New-Object System.Windows.Forms.Button
$removeGroupButton.Text = "Remove Group"
$removeGroupButton.Size = New-Object System.Drawing.Size(120, 23)
$removeGroupButton.Location = New-Object System.Drawing.Point(775, 70)

$gatherLapsPasswordButton = New-Object System.Windows.Forms.Button
$gatherLapsPasswordButton.Text = "Gather LAPS"
$gatherLapsPasswordButton.Size = New-Object System.Drawing.Size(120, 23)
$gatherLapsPasswordButton.Location = New-Object System.Drawing.Point(195, 70)
$gatherLapsPasswordButton.Visible = $false

$gatherBitLockerPasswordButton = New-Object System.Windows.Forms.Button
$gatherBitLockerPasswordButton.Text = "Gather BitLocker"
$gatherBitLockerPasswordButton.Size = New-Object System.Drawing.Size(120, 23)
$gatherBitLockerPasswordButton.Location = New-Object System.Drawing.Point(340, 70)
$gatherBitLockerPasswordButton.Visible = $false


# Create TextBox to display output
$outputTextBox = New-Object System.Windows.Forms.TextBox
$outputTextBox.Multiline = $true
$outputTextBox.ScrollBars = 'Vertical'
$outputTextBox.Size = New-Object System.Drawing.Size(575, 300)
$outputTextBox.Location = New-Object System.Drawing.Point(50, 120)

# Create a checklist for groups
$groupsChecklist = New-Object System.Windows.Forms.CheckedListBox
$groupsChecklist.Size = New-Object System.Drawing.Size(250, 305)
$groupsChecklist.Location = New-Object System.Drawing.Point(650, 120)

# Create a button for editing user info
$editInfoButton = New-Object System.Windows.Forms.Button
$editInfoButton.Text = "Edit Info"
$editInfoButton.Location = New-Object System.Drawing.Point(650, 25)

# Create a popup form for editing user info
$editInfoForm = New-Object System.Windows.Forms.Form
$editInfoForm.Text = "Edit User Info"
$editInfoForm.Size = New-Object System.Drawing.Size(600, 250)
$editInfoForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
$editInfoForm.Location = $form.Location
$editInfoForm.MaximizeBox = $false  # Disable maximize button
$editInfoForm.MinimizeBox = $false  # Disable minimize button

# Create labels and textboxes for new logon name and email address
$newLogonNameLabel = New-Object System.Windows.Forms.Label
$newLogonNameLabel.Text = "Logon Name:"
$newLogonNameLabel.Size = New-Object System.Drawing.Size(100, 20)
$newLogonNameLabel.Location = New-Object System.Drawing.Point(10, 20)

$newLogonNameTextBox = New-Object System.Windows.Forms.TextBox
$newLogonNameTextBox.Size = New-Object System.Drawing.Size(150, 20)
$newLogonNameTextBox.Location = New-Object System.Drawing.Point(120, 20)

$newEmailAddressLabel = New-Object System.Windows.Forms.Label
$newEmailAddressLabel.Text = "Email Address:"
$newEmailAddressLabel.Size = New-Object System.Drawing.Size(110, 20)
$newEmailAddressLabel.Location = New-Object System.Drawing.Point(10, 50)

$newEmailAddressTextBox = New-Object System.Windows.Forms.TextBox
$newEmailAddressTextBox.Size = New-Object System.Drawing.Size(150, 20)
$newEmailAddressTextBox.Location = New-Object System.Drawing.Point(120, 50)

# New input fields for user name information
$firstNameLabel = New-Object System.Windows.Forms.Label
$firstNameLabel.Text = "First Name:"
$firstNameLabel.Size = New-Object System.Drawing.Size(100, 20)
$firstNameLabel.Location = New-Object System.Drawing.Point(10, 80)

$firstNameTextBox = New-Object System.Windows.Forms.TextBox
$firstNameTextBox.Size = New-Object System.Drawing.Size(150, 20)
$firstNameTextBox.Location = New-Object System.Drawing.Point(120, 80)

$lastNameLabel = New-Object System.Windows.Forms.Label
$lastNameLabel.Text = "Last Name:"
$lastNameLabel.Size = New-Object System.Drawing.Size(100, 20)
$lastNameLabel.Location = New-Object System.Drawing.Point(10, 110)

$lastNameTextBox = New-Object System.Windows.Forms.TextBox
$lastNameTextBox.Size = New-Object System.Drawing.Size(150, 20)
$lastNameTextBox.Location = New-Object System.Drawing.Point(120, 110)

$fullNameLabel = New-Object System.Windows.Forms.Label
$fullNameLabel.Text = "Full Name:"
$fullNameLabel.Size = New-Object System.Drawing.Size(100, 20)
$fullNameLabel.Location = New-Object System.Drawing.Point(280, 20)

$fullNameTextBox = New-Object System.Windows.Forms.TextBox
$fullNameTextBox.Size = New-Object System.Drawing.Size(150, 20)
$fullNameTextBox.Location = New-Object System.Drawing.Point(390, 20)

$preWindows2000Label = New-Object System.Windows.Forms.Label
$preWindows2000Label.Text = "Pre-Windows 2000:"
$preWindows2000Label.Size = New-Object System.Drawing.Size(110, 20)
$preWindows2000Label.Location = New-Object System.Drawing.Point(280, 50)

$preWindows2000TextBox = New-Object System.Windows.Forms.TextBox
$preWindows2000TextBox.Size = New-Object System.Drawing.Size(150, 20)
$preWindows2000TextBox.Location = New-Object System.Drawing.Point(390, 50)

$displayNameLabel = New-Object System.Windows.Forms.Label
$displayNameLabel.Text = "Display Name:"
$displayNameLabel.Size = New-Object System.Drawing.Size(100, 20)
$displayNameLabel.Location = New-Object System.Drawing.Point(280, 80)

$displayNameTextBox = New-Object System.Windows.Forms.TextBox
$displayNameTextBox.Size = New-Object System.Drawing.Size(150, 20)
$displayNameTextBox.Location = New-Object System.Drawing.Point(390, 80)

$saveChangesButton = New-Object System.Windows.Forms.Button
$saveChangesButton.Text = "Save Changes"
$saveChangesButton.Size = New-Object System.Drawing.Size(100, 30)
$saveChangesButton.Location = New-Object System.Drawing.Point(250, 150)

$sunSymbol = [char]0x2600
$moonSymbol = [char]0x263E

# Dark Mode Toggle Button
$darkModeToggleButton = New-Object System.Windows.Forms.Button
$darkModeToggleButton.Text = "$moonSymbol"
$darkModeToggleButton.Size = New-Object System.Drawing.Size(30, 30)
$darkModeToggleButton.Location = New-Object System.Drawing.Point(910, 420)
$darkModeToggleButton.Add_Click({Toggle-DarkMode})

# Define the action when the search button is clicked
$searchUserButton.Add_Click({

    # Get the user input from the TextBox
    $userInput = $inputTextBox.Text

    #Prevent blank searches
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        $outputTextBox.Text = "Please enter the User's / Computer's name before searching."
        #clear out userDistinguishedName so that other functions are not reading old user info
        $global:userDistinguishedName = $null
        $global:computerDistinguishedName = $null
        $global:computerName = $null
        $groupsChecklist.Items.Clear()
        return
    }

    # Determine which properties to include in the search
    $userProperties = @("Enabled", "HomeDirectory", "EmailAddress", "LockedOut", "Description", "AccountExpirationDate", "CanonicalName")
    $computerProperties = @("Enabled", "CanonicalName")

    # PowerShell command to execute based on the selected search type and properties
    switch ($searchTypeComboBox.SelectedItem) {
        "Name" {
            # Use a regular expression to split the input into first and last name parts
            $names = $userInput -split '\s+' | Where-Object { $_ -ne '' }
            $global:computerDistinguishedName = $null
            $global:computerName = $null

            if ($names.Count -ge 2) {
                $firstName = $names[0]
                $lastName = $names[1]
                $result = Get-ADUser -Filter "(GivenName -like ""$firstName*"") -and (Surname -like ""$lastName*"")" -Properties $userProperties
            } else {
                $result = Get-ADUser -Filter "GivenName -like ""$userInput*"" -or Surname -like ""$userInput*""" -Properties $userProperties
            }
        }
        "LogonName" {
            $result = Get-ADUser -Filter "UserPrincipalName -like '$userInput*'" -Properties $userProperties
            $global:computerDistinguishedName = $null
            $global:computerName = $null

        }
        "Computer Name" {
            $result = Get-ADComputer -Filter "Name -like '*$userInput*'" -Properties $computerProperties
            $global:computerDistinguishedName = $result.DistinguishedName
            $global:userDistinguishedName = $null
        }
    }

    # Check if any results were returned
    if ($result) {
        # If multiple users are found, show a dialog for user selection
        if ($result.Count -gt 1) {
            $userChoices = $result | ForEach-Object { "$($_.UserPrincipalName) - $($_.Name)" }
            $selectedUser = Show-UserSelectionDialog -userChoices $userChoices

            if (-not [string]::IsNullOrWhiteSpace($selectedUser)) {
                $result = $result | Where-Object { "$($_.UserPrincipalName) - $($_.Name)" -eq $selectedUser }
            } else {
                $outputTextBox.Text = "No user selected."
                $global:userDistinguishedName = $null
                $global:computerDistinguishedName = $null
                $global:computerName = $null
                $groupsChecklist.Items.Clear()
                return
            }
        }

        switch ($searchTypeComboBox.SelectedItem){
            "Name" {
                $global:userDistinguishedName = $result | Select-Object -ExpandProperty DistinguishedName
            }
            "LogonName" {
                $global:userDistinguishedName = $result | Select-Object -ExpandProperty DistinguishedName
            }
            "Computer Name" {
                $global:computerName = $result | Select-Object -ExpandProperty Name
                $global:computerDistinguishedName = $result | Select-Object -ExpandProperty DistinguishedName
            }

        }
        # # Extract and store the Distinguished Name | set to global because other functions were unable to read the variable
        # $global:userDistinguishedName = $result | Select-Object -ExpandProperty DistinguishedName
        # # Extract and store the Computer's Name | set to global because other functions were unable to read the variable
        # $global:computerName = $result | Select-Object -ExpandProperty Name

        # Display the output in the TextBox
        $result | ForEach-Object {
            if ($searchTypeComboBox.SelectedItem -eq "Computer Name"){
                $outputTextBox.Text = ("`r`nComputer Name $($_.Name)")
                if ($null -ne $_.AccountExpirationDate) {
                    $outputTextBox.AppendText("`r`nAccount Expiration Date: $($_.AccountExpirationDate)")
                } else {
                    $outputTextBox.AppendText("`r`nAccount Expiration Date: Account Does Not Expire")
                }
                $outputTextBox.AppendText("`r`nEnabled: $($_.Enabled)")
                $outputTextBox.AppendText("`r`nObject Path: $($_.CanonicalName)")
            } else {
            $outputTextBox.Text = ("`r`nName: $($_.Name)")
            $outputTextBox.AppendText("`r`nHome Directory: $($_.HomeDirectory)")
            $outputTextBox.AppendText("`r`nEmail Address: $($_.EmailAddress)")
            $outputTextBox.AppendText("`r`n")
            if ($null -ne $_.AccountExpirationDate) {
                $outputTextBox.AppendText("`r`nAccount Expiration Date: $($_.AccountExpirationDate)")
                } else {
                    $outputTextBox.AppendText("`r`nAccount Expiration Date: Account Does Not Expire")
                }
            $outputTextBox.AppendText("`r`nDescription: $($_.Description)")
            $outputTextBox.AppendText("`r`nEnabled: $($_.Enabled)")
            $outputTextBox.AppendText("`r`nLocked Out: $($_.LockedOut)")
            $outputTextBox.AppendText("`r`nLogon Name: $($_.UserPrincipalName)")
            $outputTextBox.AppendText("`r`nObject Path: $($_.CanonicalName)")
            }
        }

        # Retrieve and display user groups
        $userGroups = Get-UserGroups -userDistinguishedName $userDistinguishedName -searchType $searchTypeComboBox.SelectedItem
        $groupsChecklist.Items.Clear()

        # Sort the groups alphabetically
        $sortedGroups = $userGroups | ForEach-Object {
        $groups = ($_ -split ',')[0]
        $groupName = ($groups -split '=')[1]
        $groupName
        } | Sort-Object

        # Add the sorted groups to the checklist
        foreach ($groupName in $sortedGroups) {
        $groupsChecklist.Items.Add($groupName) | Out-Null
        }
    } else {
        # Display a message if no user was found
        $outputTextBox.Text = "No user or computer found for '$userInput'."
        # Clear the checklist
        $groupsChecklist.Items.Clear()
        $global:userDistinguishedName = $null
        $global:computerDistinguishedName = $null
        $global:computerName = $null

    }
})

# Define the action when the 'Edit Info' button is clicked
$editInfoButton.Add_Click({
    if (-not $userDistinguishedName) {
        $outputTextBox.Text = "Please search for a user before attempting to edit information."
        $global:userDistinguishedName = $null
        $global:computerDistinguishedName = $null
        $global:computerName = $null
        return
    }

    # Retrieve user information and fill in the textboxes
    $user = Get-ADUser -Identity $userDistinguishedName -Properties GivenName, SurName, DisplayName, SamAccountName, Name, UserPrincipalName, EmailAddress
    $firstNameTextBox.Text = $user.GivenName
    $lastNameTextBox.Text = $user.SurName
    $fullNameTextBox.Text = $user.Name
    $preWindows2000TextBox.Text = $user.SamAccountName
    $displayNameTextBox.Text = $user.DisplayName
    $newEmailAddressTextBox.Text = $user.EmailAddress
    $newLogonNameTextBox.Text = $user.UserPrincipalName.Split("@")[0] # Split on @ to only gather the LogonName

    # Show the edit info form
    $editInfoForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $editInfoForm.Location = $form.Location
    $result = $editInfoForm.ShowDialog()

    # Check if the 'Save Changes' button was clicked
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Get the new logon name, new email address, and additional user information from the textboxes
        $newLogonName = $newLogonNameTextBox.Text.Trim()
        $newEmailAddress = $newEmailAddressTextBox.Text.Trim()
        $newFirstName = $firstNameTextBox.Text.Trim()
        $newLastName = $lastNameTextBox.Text.Trim()
        $newFullName = $fullNameTextBox.Text.Trim()
        $newPreWindows2000 = $preWindows2000TextBox.Text.Trim()
        $newDisplayName = $displayNameTextBox.Text.Trim()

        try {
            # Update user information
            $updatedInfo = @()

            if ($newLogonName -ne $user.UserPrincipalName.Split("@")[0]) {
                Set-ADUser -Identity $userDistinguishedName -UserPrincipalName "$newLogonName@$domain"
                $updatedInfo += "Logon Name updated: $newLogonName"
            }

            if (-not ($newEmailAddress -ceq $user.EmailAddress)) {
                Set-ADUser -Identity $userDistinguishedName -EmailAddress $newEmailAddress
                $updatedInfo += "Email Address updated: $newEmailAddress"
            }

            if (-not ($newFirstName -ceq $user.GivenName)) {
                Set-ADUser -Identity $userDistinguishedName -GivenName $newFirstName
                $updatedInfo += "First Name updated: $newFirstName"
            }

            if (-not ($newLastName -ceq $user.SurName)) {
                Set-ADUser -Identity $userDistinguishedName -SurName $newLastName
                $updatedInfo += "Last Name updated: $newLastName"
            }

            if (-not ($newPreWindows2000 -ceq $user.SamAccountName)) {
                Set-ADUser -Identity $userDistinguishedName -SamAccountName $newPreWindows2000
                $updatedInfo += "Pre-Windows 2000 Name updated: $newPreWindows2000"
            }

            if (-not ($newDisplayName -ceq $user.DisplayName)) {
                Set-ADUser -Identity $userDistinguishedName -DisplayName $newDisplayName
                $updatedInfo += "Display Name updated: $newDisplayName"
            }

            if (-not ($newFullName -ceq $user.Name)) {
                Get-ADUser -Identity $userDistinguishedName | Rename-ADObject -NewName $newFullName
                $updatedInfo += "Full Name updated: $newFullName - After updating a users name you may have to search for them again."
            }

            # Display the updated information in the TextBox
            if ($updatedInfo.Count -gt 0) {
                $outputTextBox.AppendText("`n")
                $outputTextBox.AppendText("`r`nUpdated Information:")
                $updatedInfo | ForEach-Object {
                    $outputTextBox.AppendText("`r`n$_")
                }
            } else {
                $outputTextBox.AppendText("`r`nNo changes were made. The user information remains unchanged.")
            }
        } catch {
            $outputTextBox.AppendText("`r`nError updating user information: $_")
        }

        # Clear the input fields in the edit info form 
        $newLogonNameTextBox.Text = ""
        $newEmailAddressTextBox.Text = ""
        $firstNameTextBox.Text = ""
        $lastNameTextBox.Text = ""
        $fullNameTextBox.Text = ""
        $preWindows2000TextBox.Text = ""
        $displayNameTextBox.Text = ""
    }
})

$saveChangesButton.Add_Click({
    # Close the edit info form when "Save Changes" is clicked
    $editInfoForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $editInfoForm.Close()
})

$gatherLapsPasswordButton.Add_Click({
    try {
    $lapsPassword = Get-AdmPwdPassword -ComputerName $global:computerName
    $outputTextBox.AppendText("`r`n`r`nLAPS Password for $global:computerName : $($lapsPassword.Password)")
    } catch {
        $outputTextBox.AppendText("`r`n`r`nError gathering LAPS Password: $($_.Exception.Message)")
    }
})

$gatherBitLockerPasswordButton.Add_Click({
    try {
        $bitLockerRecoveryInfo = Get-ADObject -SearchBase $global:computerDistinguishedName -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -Properties 'msFVE-RecoveryPassword'
        $bitLockerPassword = $bitLockerRecoveryInfo.'msFVE-RecoveryPassword'
        $outputTextBox.AppendText("`r`n`r`nBitLocker Recovery Password for $computerName : $bitLockerPassword")
    } catch {
        $outputTextBox.AppendText("`r`n`r`nError getting Bitlocker Recovery Password for $computerName : $($_.Exception.Message)")
    }
})

# Event handler for search type combo box change
$searchTypeComboBox.Add_SelectedValueChanged({
    Toggle-Buttons
})

# Define the action when the 'Unlock Domain' button is clicked
$unlockDomainButton.Add_Click({
    # Unlock the AD account using the stored Distinguished Name
    try {
        Unlock-ADAccount -Identity $userDistinguishedName

        # Append a message to the output
        $outputTextBox.AppendText("`r`n`r`nAccount Unlocked: $userDistinguishedName")
    } catch {
        # Handle the error and append an error message to the output
        $outputTextBox.AppendText("`r`n`r`nError unlocking account: $_")
    }
})

# Define the action when the enable account button is clicked
$enableAccountButton.Add_Click({
    # Enable the AD account using the stored Distinguished Name
    try {
        if ([string]::IsNullOrWhiteSpace($computerDistinguishedName)) {
            Enable-ADAccount -Identity $userDistinguishedName
            $outputTextBox.AppendText("`r`n`r`nAccount Enabled: $userDistinguishedName")
        } else {
            Enable-ADAccount -Identity $computerDistinguishedName
            $outputTextBox.AppendText("`r`n`r`nAccount Enabled: $computerDistinguishedName")
            }
        } catch {
            $outputTextBox.AppendText("`r`n`r`nError enabling account: $_")
            }})

# Define the action when the never expire button is clicked
$setNeverExpireButton.Add_Click({
    # Set PasswordNeverExpires to true using the stored Distinguished Name
    try {
        Set-ADUser -Identity $userDistinguishedName -AccountExpirationDate $null

        # Append a message to the output
        $outputTextBox.AppendText("`r`n`r`nAccountExpirationDate set to never expire for: $userDistinguishedName")
    } catch {
        # Handle the error and append an error message to the output
        $outputTextBox.AppendText("`r`n`r`nError setting account to never expire: $_")
    }
})

# Define the action when the 'Add Group' button is clicked
$addGroupButton.Add_Click({
    # Get the group name from the TextBox
    $newGroup = $newGroupTextBox.Text.Trim()

    if (-not [string]::IsNullOrWhiteSpace($newGroup)) {
        try {
            Add-ADGroupMember -Identity $newGroup -Members $userDistinguishedName
            $outputTextBox.AppendText("`r`n`r`nUser added to group: $newGroup")

            # Refresh the group list
            Refresh-GroupList
        } catch {
            $outputTextBox.AppendText("`r`n`r`nError adding user to group: $_")
        }
    } else {
        $outputTextBox.AppendText("`r`n`r`nPlease enter a group name.")
    }
})

# Define the action when the 'Remove Group' button is clicked
$removeGroupButton.Add_Click({
    # Remove the selected groups from the user
    $selectedGroups = $groupsChecklist.CheckedItems

    if ($selectedGroups.Count -gt 0) {
        foreach ($selectedGroup in $selectedGroups) {
            try {
                # Use -Confirm:$false to automatically accept confirmation prompts, without this the agent will have to confirm every time they want to remove a group
                Remove-ADGroupMember -Identity $selectedGroup -Members $userDistinguishedName -Confirm:$false
                $outputTextBox.AppendText("`r`n`r`nUser removed from group: $selectedGroup")
            } catch {
                $outputTextBox.AppendText("`r`n`r`nError removing user from group '$selectedGroup': $_")
            }
        }

        # Refresh the group list after removing all selected groups
        Refresh-GroupList
    } else {
        $outputTextBox.AppendText("`r`n`r`nPlease select one or more groups to remove.")
    }
})

# Define the action when the Move to OU button is clicked
$moveToOUButton.Add_Click({
    # Check if a user or computer is selected
    if ([string]::IsNullOrWhiteSpace($userDistinguishedName) -and [string]::IsNullOrWhiteSpace($computerDistinguishedName)) {
        $outputTextBox.Text = "Please search for a user or computer before attempting to update OUs."
        return
    }

    # Determine the object type (User or Computer)
    $objectType = if ([string]::IsNullOrWhiteSpace($userDistinguishedName)) { "Computer" } else { "User" }

    # Define the OU options
    $ouOptions = @()

    # If moving a computer, gather OU options dynamically
    if ($objectType -eq "Computer") {
        $primaryOUs = Get-ADOrganizationalUnit -Filter * | Where-Object { $_.DistinguishedName -like "*${$computerOUPath}" }
        $ouOptions = $primaryOUs | ForEach-Object {
            $ouName = ($_.DistinguishedName -split ',OU=')[0] -replace '^OU='
            [PSCustomObject]@{ # I don't like having to use Custom Objects but its needed to have both a simple display name and the DistinguishedName stored together in memory
                DisplayValue = $ouName
                FullPath = $_.DistinguishedName
            }
        } | Sort-Object DisplayValue
    } else {
        # If moving a user, hard code OU options | The Job position where I ran this code only needed to move users between four OUs so it was more efficient to hardcode the values
        $ouOptions = @(
            [PSCustomObject]@{ DisplayValue = "Example"; FullPath = "OU=Users,DC=example" }
        )
    }

    <# If you wanted to gather User OUs dynamically you can use the following code and replace lines 601 - 606
    
    else {
            $userOUs = Get-ADOrganizationalUnit -Filter * | Where-Object { $_.DistinguishedName -like "*${$userOUPath}" }
            $ouOptions = $userOUs | ForEach-Object {
                $ouName = ($_.DistinguishedName -split ',OU=')[0] -replace '^OU='
                [PSCustomObject]@{
                    DisplayValue = $ouName
                    FullPath = $_.DistinguishedName
                }
            } | Sort-Object DisplayValue
        }

    #>


    # Show a dialog for OU selection
    $selectedOU = Show-OUMoveDialog -ouOptions $ouOptions

    if (-not [string]::IsNullOrWhiteSpace($selectedOU)) {
        $targetOUPath = $ouOptions | Where-Object { $_.DisplayValue -eq $selectedOU } | Select-Object -ExpandProperty FullPath

        # Run the Move-ADObject command based on the object type
        if ($objectType -eq "Computer") {
            Move-ADObject -Identity $computerDistinguishedName -TargetPath $targetOUPath
        } else {
            Move-ADObject -Identity $userDistinguishedName -TargetPath $targetOUPath
        }

        $outputTextBox.AppendText("`r`n`r`n$objectType successfully moved to $selectedOU. `r`nYou may have to search for the $objectType again to make further changes.")
    } else {
        $outputTextBox.AppendText("`r`n`r`nNo OU selected. $objectType not moved.")
    }
})

# Function to show a dialog for OU selection
function Show-OUMoveDialog {
    param (
        [array]$ouOptions
    )

    $ouForm = New-Object System.Windows.Forms.Form
    $ouForm.Text = "Select OU"
    $ouForm.Size = New-Object System.Drawing.Size(300, 200)

    $ouComboBox = New-Object System.Windows.Forms.ComboBox
    $ouComboBox.Location = New-Object System.Drawing.Point(50, 50)
    $ouComboBox.Size = New-Object System.Drawing.Size(200, 20)
    $ouComboBox.Items.AddRange($ouOptions.DisplayValue)
    $ouComboBox.AutoCompleteMode = 'SuggestAppend'
    $ouComboBox.AutoCompleteSource = 'CustomSource'
    $ouComboBox.AutoCompleteCustomSource.AddRange($ouOptions.DisplayValue)
    $ouForm.Controls.Add($ouComboBox)

    $ouComboBox.Add_KeyDown({
    param ($sender, $e)
    if ($e.Control -and $e.KeyCode -eq 'A') {
        # Ctrl+A is pressed, select all text
        $sender.SelectAll()
        #mute windows ping sound
        $e.Handled = $true
        $e.SuppressKeyPress = $true
        }
    })

    $ouOKButton = New-Object System.Windows.Forms.Button
    $ouOKButton.Location = New-Object System.Drawing.Point(100, 100)
    $ouOKButton.Size = New-Object System.Drawing.Size(75, 23)
    $ouOKButton.Text = "OK"
    $ouOKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $ouForm.Controls.Add($ouOKButton)

    $ouForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $ouForm.Location = $form.Location
    $ouResult = $ouForm.ShowDialog()

    if ($ouResult -eq [System.Windows.Forms.DialogResult]::OK) {
        return $ouComboBox.SelectedItem
    }

    return $null
}

# Function to retrieve user groups
function Get-UserGroups {
    param (
        [string]$userDistinguishedName,
        [string]$searchType
    )

    if ($searchType -eq "Computer Name") {
        return $null #We dont manage computer groups so no need to gather their groups
    }

    try {
    # Get the groups for the selected user
    $userGroups = Get-ADUser -Identity $userDistinguishedName | Get-ADUser -Properties MemberOf | Select-Object -ExpandProperty MemberOf

    return $userGroups
    } catch {
        return $null
    }
}

# Function to display a dialog with multiple user choices
function Show-UserSelectionDialog {
    param (
        [array]$userChoices
    )

    $userDialog = New-Object System.Windows.Forms.Form
    $userDialog.Text = "Select User"
    $userDialog.Size = New-Object System.Drawing.Size(400, 210)

    $userDialog.MinimizeBox = $false    # Disable minimize button
    $userDialog.MaximizeBox = $false    # Disable maximize button
    
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Multiple users found. Select the desired user:"
    $label.Size = New-Object System.Drawing.Size(350, 20)
    $label.Location = New-Object System.Drawing.Point(10, 10)

    $userListBox = New-Object System.Windows.Forms.ListBox
    $userListBox.Size = New-Object System.Drawing.Size(350, 100)
    $userListBox.Location = New-Object System.Drawing.Point(10, 30)

    foreach ($user in $userChoices) {
        $userListBox.Items.Add($user) | Out-Null
    }

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $okButton.Size = New-Object System.Drawing.Size(75, 23)
    $okButton.Location = New-Object System.Drawing.Point(10, 140)

    $userDialog.Controls.Add($label)
    $userDialog.Controls.Add($userListBox)
    $userDialog.Controls.Add($okButton)

    # Set position and location for centering on the main form
    $userDialog.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $userDialog.Location = $form.Location

    $result = $userDialog.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $userListBox.SelectedItem
    }

    return $null
}

# Function to toggle buttons based on the selected search type
function Toggle-Buttons {
    switch ($searchTypeComboBox.SelectedItem) {
        "Name" {
            $groupLabel.Visible = $true
            $editInfoButton.Visible = $true
            $inputLabelUser.Visible = $true
            $inputLabelLogonName.Visible =$false
            $addGroupButton.Visible = $true
            $newGroupTextBox.Visible = $true
            $removeGroupButton.Visible = $true
            $unlockDomainButton.Visible = $true
            $inputLabelComputer.Visible = $false
            $setNeverExpireButton.Visible = $true
            $gatherLapsPasswordButton.Visible = $false
            $gatherBitLockerPasswordButton.Visible = $false
        }
        "LogonName" {
            $groupLabel.Visible = $true
            $editInfoButton.Visible = $true
            $inputLabelUser.Visible = $false
            $inputLabelLogonName.Visible =$true
            $addGroupButton.Visible = $true
            $newGroupTextBox.Visible = $true
            $removeGroupButton.Visible = $true
            $unlockDomainButton.Visible = $true
            $inputLabelComputer.Visible = $false
            $setNeverExpireButton.Visible = $true
            $gatherLapsPasswordButton.Visible = $false
            $gatherBitLockerPasswordButton.Visible = $false
        }
        "Computer Name" {
            $groupLabel.Visible = $false
            $editInfoButton.Visible = $false
            $inputLabelUser.Visible = $false
            $inputLabelLogonName.Visible =$false
            $addGroupButton.Visible = $false
            $newGroupTextBox.Visible = $false
            $removeGroupButton.Visible = $false
            $inputLabelComputer.Visible = $true
            $unlockDomainButton.Visible = $false
            $setNeverExpireButton.Visible = $false
            $gatherLapsPasswordButton.Visible = $true
            $gatherBitLockerPasswordButton.Visible = $true
        }
    }
}

# Function to refresh the group list
function Refresh-GroupList {
    $userGroups = Get-UserGroups -userDistinguishedName $userDistinguishedName -searchType $searchTypeComboBox.SelectedItem

    # Sort the groups alphabetically
    $sortedGroups = $userGroups | ForEach-Object {
        $groups = ($_ -split ',')[0]
        $groupName = ($groups -split '=')[1]
        $groupName
    } | Sort-Object

    # Clear the existing items in the checklist
    $groupsChecklist.Items.Clear()

    # Add the sorted groups to the checklist
    foreach ($groupName in $sortedGroups) {
        $groupsChecklist.Items.Add($groupName) | Out-Null
    }
}

# Function to toggle between Dark and Light modes
function Toggle-DarkMode {
    if ($form.BackColor -eq $darkModeBackgroundColor) {
        Set-LightMode
    } else {
        Set-DarkMode
    }
}

# Function to set Dark Mode colors
function Set-DarkMode {
    $form.BackColor = $darkModeBackgroundColor
    $form.ForeColor = $darkModeForeColor
    $inputTextBox.BackColor = $darkModeBackgroundColor
    $inputTextBox.ForeColor = [System.Drawing.Color]::White
    $outputTextBox.BackColor = $darkModeBackgroundColor
    $outputTextBox.ForeColor = [System.Drawing.Color]::White
    $groupsChecklist.BackColor = $darkModeBackgroundColor
    $groupsChecklist.ForeColor = [System.Drawing.Color]::White
    $searchTypeComboBox.BackColor = $darkModeBackgroundColor
    $searchTypeComboBox.ForeColor = [System.Drawing.Color]::White
    $newGroupTextBox.BackColor = $darkModeBackgroundColor
    $newGroupTextBox.ForeColor = [System.Drawing.Color]::White
    $editInfoButton.BackColor = $darkModeBackgroundColor
    $editInfoButton.ForeColor = [System.Drawing.Color]::White
    $editInfoForm.BackColor = $darkModeBackgroundColor
    $editInfoForm.ForeColor = [System.Drawing.Color]::White
    $darkModeToggleButton.Text = "$sunSymbol"
}

# Function to set Light Mode colors
function Set-LightMode {
    $form.BackColor = $lightModeBackgroundColor
    $form.ForeColor = $lightModeForeColor
    $inputTextBox.BackColor = [System.Drawing.Color]::White
    $inputTextBox.ForeColor = [System.Drawing.Color]::Black
    $outputTextBox.BackColor = [System.Drawing.Color]::White
    $outputTextBox.ForeColor = [System.Drawing.Color]::Black
    $groupsChecklist.BackColor = $lightModeBackgroundColor
    $groupsChecklist.ForeColor = [System.Drawing.Color]::Black
    $searchTypeComboBox.BackColor = [System.Drawing.Color]::White
    $searchTypeComboBox.ForeColor = [System.Drawing.Color]::Black
    $newGroupTextBox.BackColor = [System.Drawing.Color]::White
    $newGroupTextBox.ForeColor = [System.Drawing.Color]::Black
    $editInfoButton.BackColor = $lightModeBackgroundColor
    $editInfoButton.ForeColor = [System.Drawing.Color]::Black
    $groupsChecklist.ForeColor = [System.Drawing.Color]::Black
    $groupsChecklist.BackColor = [System.Drawing.Color]::White
    $editInfoForm.BackColor = $lightModeBackgroundColor
    $editInfoForm.ForeColor = [System.Drawing.Color]::Black
    $darkModeToggleButton.Text = "$moonSymbol"
}

# Define variables for dark mode colors
$darkModeBackgroundColor = [System.Drawing.Color]::FromArgb(28, 28, 28)
$darkModeForeColor = [System.Drawing.Color]::White

# Define variables for light mode colors
$lightModeBackgroundColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$lightModeForeColor = [System.Drawing.Color]::Black


# Add dark mode toggle to the form
$form.Controls.Add($darkModeToggleButton)

# Inform user about first AD load
$outputTextBox.Text = "This script will connect to Active Directory on your first search. Please be patient as this may take a moment."

# Add hotkeys event for username/LogonName input box
$inputTextBox.Add_KeyDown({
    param ($sender, $e)
    if ($e.Control -and $e.KeyCode -eq 'A') {
        # Ctrl+A is pressed, select all text
        $sender.SelectAll()
        #mute windows ping sound
        $e.Handled = $true
        $e.SuppressKeyPress = $true
    }
    elseif ($e.KeyCode -eq 'Enter') {
        # Enter key is pressed, trigger the search
        $searchUserButton.PerformClick()
        #mute windows ping sound
        $e.Handled = $true
        $e.SuppressKeyPress = $true

    }
})

# Function to create a key press event handler for Ctrl+A
function CtrlA-Handler {
    return {
        param ($sender, $e)
        if ($e.Control -and $e.KeyCode -eq 'A') {
            # Ctrl+A is pressed, select all text in the textbox
            $sender.SelectAll()
            # Mute Windows ping sound
            $e.Handled = $true
            $e.SuppressKeyPress = $true
        }
    }
}

# Add hotkeys event for textboxes
$displayNameTextBox.Add_KeyDown((CtrlA-Handler))
$firstNameTextBox.Add_KeyDown((CtrlA-Handler))
$fullNameTextBox.Add_KeyDown((CtrlA-Handler))
$lastNameTextBox.Add_KeyDown((CtrlA-Handler))
$newEmailAddressTextBox.Add_KeyDown((CtrlA-Handler))
$newGroupTextBox.Add_KeyDown((CtrlA-Handler))
$newLogonNameTextBox.Add_KeyDown((CtrlA-Handler))
$preWindows2000TextBox.Add_KeyDown((CtrlA-Handler))

# Add controls to the edit info form
$editInfoForm.Controls.Add($newLogonNameLabel)
$editInfoForm.Controls.Add($newLogonNameTextBox)
$editInfoForm.Controls.Add($newEmailAddressLabel)
$editInfoForm.Controls.Add($newEmailAddressTextBox)

# Add controls for user name information
$editInfoForm.Controls.Add($firstNameLabel)
$editInfoForm.Controls.Add($firstNameTextBox)
$editInfoForm.Controls.Add($lastNameLabel)
$editInfoForm.Controls.Add($lastNameTextBox)
$editInfoForm.Controls.Add($fullNameLabel)
$editInfoForm.Controls.Add($fullNameTextBox)
$editInfoForm.Controls.Add($preWindows2000Label)
$editInfoForm.Controls.Add($preWindows2000TextBox)
$editInfoForm.Controls.Add($displayNameLabel)
$editInfoForm.Controls.Add($displayNameTextBox)

$editInfoForm.Controls.Add($saveChangesButton)

# Add controls to the form
$form.Controls.Add($inputLabelUser)
$form.Controls.Add($inputLabelLogonName)
$form.Controls.Add($groupLabel)
$form.Controls.Add($inputTextBox)
$form.Controls.Add($inputLabelComputer)
$form.Controls.Add($searchTypeComboBox)
$form.Controls.Add($searchUserButton)
$form.Controls.Add($enableAccountButton)
$form.Controls.Add($unlockDomainButton)
$form.Controls.Add($setNeverExpireButton)
$form.Controls.Add($addGroupButton)
$form.Controls.Add($removeGroupButton)
$form.Controls.Add($moveToOUButton)
$form.Controls.Add($newGroupTextBox)
$form.Controls.Add($outputTextBox)
$form.Controls.Add($groupsChecklist)
$form.Controls.Add($editInfoButton)
$form.Controls.Add($gatherLapsPasswordButton)
$form.Controls.Add($gatherBitLockerPasswordButton)

# Show the form
$form.ShowDialog()