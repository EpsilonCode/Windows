# Remove User from all groups but Domain Users
# Add user to group from csv column NewGroup
# Move to OU from column OU

# Import the Active Directory module
Import-Module ActiveDirectory

# Specify the path to the CSV file
$csvFilePath = "C:\path\to\user_data.csv"

# Import user data from the CSV file
$userData = Import-Csv -Path $csvFilePath

foreach ($entry in $userData) {
    # Retrieve the username, new group name, and target OU from each CSV row
    $userSamAccountName = $entry.Username
    $newGroupName = $entry.NewGroup
    $targetOU = $entry.OU

    # Find the user in Active Directory
    $user = Get-ADUser -Filter {SamAccountName -eq $userSamAccountName}

    if ($user) {
        # Get the user's current group memberships
        $currentGroups = Get-ADPrincipalGroupMembership -Identity $user

        # Remove the user from all groups except "Domain Users"
        foreach ($group in $currentGroups) {
            if ($group.Name -ne "Domain Users") {
                Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
            }
        }

        # Add the user to the new group specified in the CSV
        Add-ADGroupMember -Identity $newGroupName -Members $user

        # Move the user to the target OU
        try {
            Move-ADObject -Identity $user -TargetPath $targetOU -ErrorAction Stop
            Write-Host "User $($user.SamAccountName) has been removed from all groups except 'Domain Users', added to '$newGroupName', and moved to '$targetOU'."
        } catch {
            Write-Host "Error moving user $($user.SamAccountName) to '$targetOU': $_"
        }
    } else {
        Write-Host "User $userSamAccountName not found in Active Directory."
    }
}
