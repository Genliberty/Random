# Import the ActiveDirectory module - make sure this is run on a machine that has access to Active Directory and the module installed
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Get-FolderSecurityGroupsAndRights {
    param (
        [string]$Path,
        [int]$Depth = 0,
        [System.Collections.ArrayList]$Results
    )

    if ($Depth -gt 3) {
        return
    }

    $folders = Get-ChildItem -Path $Path -Directory -Force -ErrorAction SilentlyContinue

    $totalFolders = $folders.Count
    $processedFolders = 0

    foreach ($folder in $folders) {
        $acl = Get-Acl -Path $folder.FullName

        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.Value
            $rights = $ace.FileSystemRights
            $accessControlType = $ace.AccessControlType

            # Initialize an empty list to hold group members if applicable
            $groupMembers = @()

            # Extract the group name from the identity, removing the domain part if present
            $groupName = $identity -split '\\' | Select-Object -Last 1

            # Check if the extracted name is an AD group
            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction Stop

                # If it's a group, get its members
                $groupMembers = Get-ADGroupMember -Identity $groupName | Select-Object -ExpandProperty SamAccountName
            } catch {
                # If the identity is not a group or cannot be found in AD, this will catch the error
            }

            # Create a custom object with the folder, security information, and group members if applicable
            $obj = [PSCustomObject]@{
                Folder = $folder.FullName
                Identity = $identity
                Rights = $rights
                AccessType = $accessControlType
                GroupMembers = ($groupMembers -join ", ") # Convert the list of members to a comma-separated string
            }

            $null = $Results.Add($obj)
        }

        # Update processed folders count and display progress
        $processedFolders++
        Write-Progress -Activity "Processing folders for security groups and rights" -Status "Processing: $($folder.FullName) ($processedFolders of $totalFolders)" -PercentComplete (($processedFolders / $totalFolders) * 100)

        # Recurse into subfolders if needed
        Get-FolderSecurityGroupsAndRights -Path $folder.FullName -Depth ($Depth + 1) -Results $Results
    }
}

$results = New-Object System.Collections.ArrayList

$rootPath = "\\fill\in\your\shared\drive"

Get-FolderSecurityGroupsAndRights -Path $rootPath -Depth 0 -Results $results

$results | Export-Csv -Path "C:\TEMP\FolderSecurityReport.csv" -NoTypeInformation

Write-Host "Export completed: FolderSecurityReport.csv"
