<#
.SYNOPSIS
  Audits and enforces specific Active Directory accounts and group memberships.

.DESCRIPTION
  1. Ensures these administrator accounts exist and have correct passwords:
       jcena     -- CantCM3!
       crhodes   -- $toryFinished
       rripley   -- M@m!onTop
       blynch    -- TheM@N!35
       srollins  -- wardrobe
       fbalor    -- D3monM@keup
       rroode    -- Gl0ri0us!
       rreigns   -- tr1b4lChief
       abliss    -- 5ftOfFury
       jhendry   -- EyEB3liv3!
       wgunther  -- r!ngG3n3r4L

  2. Ensures these non-admin accounts exist:
       snakamura, tstratton, cgreen, laknight, ksane, lmorgan, pdunne, pniven,
       rrodriguez, juso, nlyons, kowens, dmcintyre, ajstyles, djohnson,
       jgargano, atheory, rorton

  3. Removes any other accounts, logging them to a text file.

  4. Checks for any group membership that grants administrative privileges
     (Administrators, Domain Admins, Enterprise Admins, etc.) to ensure only
     the above “administrator” accounts are found in those groups.

  Adjust the domain name, OU paths, group names, etc. as necessary for your environment.
#>

Import-Module ActiveDirectory

#--- 1) Define the domain and any OU paths if needed. Update to suit your domain.
$DomainName          = "yourdomain.local"      # Change this to your domain
$DefaultUserOU       = "OU=Users,DC=yourdomain,DC=local"  # Where you want new users placed

#--- 2) Define the lists of required accounts.

# Administrator accounts (SamAccountName => Password).
# Each should be in Domain Admins, Administrators, etc. 
$RequiredAdminUsers = @(
    @{Name='jcena';    Password='CantCM3!'},
    @{Name='crhodes';  Password='$toryFinished'},
    @{Name='rripley';  Password='M@m!onTop'},
    @{Name='blynch';   Password='TheM@N!35'},
    @{Name='srollins'; Password='wardrobe'},
    @{Name='fbalor';   Password='D3monM@keup'},
    @{Name='rroode';   Password='Gl0ri0us!'},
    @{Name='rreigns';  Password='tr1b4lChief'},
    @{Name='abliss';   Password='5ftOfFury'},
    @{Name='jhendry';  Password='EyEB3liv3!'},
    @{Name='wgunther'; Password='r!ngG3n3r4L'}
)

# Regular users that should exist (no password management is shown here,
# but you could extend this if you also need to set or reset their passwords).
$RequiredRegularUsers = @(
    'snakamura','tstratton','cgreen','laknight','ksane',
    'lmorgan','pdunne','pniven','rrodriguez','juso','nlyons',
    'kowens','dmcintyre','ajstyles','djohnson','jgargano',
    'atheory','rorton'
)

# Combine them for an overall “allowed” list
$AllAllowedSams = $RequiredAdminUsers.Name + $RequiredRegularUsers

#--- 3) Define the groups that grant administrative/elevated privileges.
# By default:
#   - The “Administrators” built-in group
#   - Domain Admins
#   - Enterprise Admins (if applicable)
$AdminGroupsToCheck = @('Administrators','Domain Admins','Enterprise Admins')

#--- 4) Function: Ensure a user exists with the specified password, create if needed.
function Ensure-ADUserExists {
    param(
        [string]$SamAccountName,
        [string]$Password,
        [string]$OU
    )

    $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
    if (-not $ExistingUser) {
        # Create the user
        Write-Host "Creating user: $SamAccountName"
        New-ADUser `
            -SamAccountName $SamAccountName `
            -Name $SamAccountName `
            -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
            -ChangePasswordAtLogon $false `
            -PasswordNeverExpires $false `
            -Enabled $true `
            -Path $OU

        # Optional: set the password again (Reset) or just rely on the New-ADUser
        Set-ADAccountPassword `
            -Identity $SamAccountName `
            -Reset `
            -NewPassword (ConvertTo-SecureString $Password -AsPlainText -Force)

        Enable-ADAccount -Identity $SamAccountName
    }
    else {
        # If the account exists, optionally reset the password if you want to enforce it:
        Write-Host "User exists: $SamAccountName. Resetting password to ensure compliance."
        Set-ADAccountPassword `
            -Identity $SamAccountName `
            -Reset `
            -NewPassword (ConvertTo-SecureString $Password -AsPlainText -Force)
        Enable-ADAccount -Identity $SamAccountName
    }
}

#--- 5) Ensure each required Admin user exists, with the proper password, and is in the relevant Admin groups.
foreach ($adminUser in $RequiredAdminUsers) {
    Ensure-ADUserExists -SamAccountName $adminUser.Name -Password $adminUser.Password -OU $DefaultUserOU

    foreach ($group in $AdminGroupsToCheck) {
        try {
            # Check if user is in that group
            $isInGroup = Get-ADGroupMember -Identity $group -Recursive | Where-Object {$_.SamAccountName -eq $adminUser.Name}
            if (-not $isInGroup) {
                Write-Host "Adding $($adminUser.Name) to group: $group"
                Add-ADGroupMember -Identity $group -Members $adminUser.Name -ErrorAction Stop
            }
        }
        catch {
            Write-Host "ERROR adding $($adminUser.Name) to $group: $_"
        }
    }
}

#--- 6) Ensure each required regular user exists. (No password enforcement shown – adapt if needed.)
foreach ($user in $RequiredRegularUsers) {
    $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
    if (-not $ExistingUser) {
        Write-Host "Creating user: $user"
        New-ADUser `
            -SamAccountName $user `
            -Name $user `
            -Enabled $true `
            -Path $DefaultUserOU
        # Possibly set a default password if you need:
        # Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString "SomePassword123" -AsPlainText -Force)
        Enable-ADAccount -Identity $user
    } else {
        Write-Host "User exists: $user"
    }
}

#--- 7) Audit membership of the admin groups to remove any undesired users.
foreach ($group in $AdminGroupsToCheck) {
    Write-Host "`nChecking admin group: $group"
    $GroupMembers = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.objectClass -eq 'user' }
    foreach ($member in $GroupMembers) {
        if ($AllAllowedSams -notcontains $member.SamAccountName) {
            # This user should not have admin privileges. Remove them from the group.
            Write-Host "Removing unauthorized user: $($member.SamAccountName) from $group"
            Remove-ADGroupMember -Identity $group -Members $member.SamAccountName -Confirm:$false
        }
    }
}

#--- 8) Finally, remove any user in the domain that is NOT in the allowed list. 
#       Log them first to a file "RemovedUsers.txt".
Write-Host "`nChecking for unauthorized users in AD..."
$LogFile = "C:\Temp\RemovedUsers.txt"
New-Item -ItemType File -Path $LogFile -Force | Out-Null

# Adjust filter to exclude built-in accounts like Administrator, krbtgt, Guest, etc.
$ExcludeBuiltIns = @('Administrator','krbtgt','Guest')  
$AllADUsers = Get-ADUser -Filter * -SearchBase "DC=yourdomain,DC=local" | Where-Object {
    $ExcludeBuiltIns -notcontains $_.SamAccountName
}

foreach ($user in $AllADUsers) {
    if ($AllAllowedSams -notcontains $user.SamAccountName) {
        # Log and remove
        "$($user.SamAccountName), $($user.DistinguishedName)" | Out-File $LogFile -Append
        Write-Host "Removing unauthorized AD user: $($user.SamAccountName)"
        Remove-ADUser -Identity $user.SamAccountName -Confirm:$false
    }
}

Write-Host "`nAudit/Reconciliation Complete."
Write-Host "Unauthorized (removed) users logged in $LogFile"
