<#
.SYNOPSIS
  Recursively searches all files on all drives for a specified search term (like "John").
  Results are written to a text file in C:\Temp.

.DESCRIPTION
  This script is similar to a Linux grep -r, but for Windows using PowerShell’s Select-String.
  It:
    1) Gathers all FileSystem drives.
    2) Recursively enumerates all files on those drives.
    3) Uses Select-String to search for the pattern in each file.
    4) Logs all matches (file path + matched line) to an output file.

.PARAMETER SearchTerm
  The text pattern you want to search for (e.g., "John").

.PARAMETER OutputFile
  The path where search results will be saved. Defaults to "C:\Temp\<SearchTerm>_SearchResults.txt".

.EXAMPLE
  .\Search-AllFiles.ps1 -SearchTerm "John"

  Searches for “John” in all files across all drives, logging matches to C:\Temp\John_SearchResults.txt.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SearchTerm,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "C:\Temp\$($SearchTerm)_SearchResults.txt"
)

# Create output directory if it doesn’t exist
$OutDir = Split-Path $OutputFile -Parent
if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

# Clear or create the output file
New-Item -Path $OutputFile -ItemType File -Force | Out-Null

Write-Host "Searching all files on all drives for pattern: '$SearchTerm'"
Write-Host "Results will be saved in $OutputFile"
Write-Host "This may take a long time, depending on system size..."

# Get all FileSystem drives
$Drives = (Get-PSDrive -PSProvider FileSystem).Name

# We’ll store all matches in $allMatches
$allMatches = @()

foreach ($drive in $Drives) {
    $rootPath = "$drive`:\"  # e.g., C:\, D:\, etc.

    Write-Host "Scanning drive: $rootPath ..."

    try {
        # Recursively get all files
        $files = Get-ChildItem -Path $rootPath -Recurse -Force -ErrorAction SilentlyContinue `
                 | Where-Object { -not $_.PSIsContainer }  # keep only files

        if ($files) {
            # Search the files for the pattern
            $matches = $files | Select-String -Pattern $SearchTerm -CaseSensitive:$false -SimpleMatch -ErrorAction SilentlyContinue
            if ($matches) {
                $allMatches += $matches
            }
        }
    }
    catch {
        # If something catastrophic happens (like drive read error), we handle it.
        Write-Host "Error scanning drive $rootPath : $_"
    }
}

if ($allMatches) {
    Write-Host "`nWriting matches to $OutputFile ..."
    # Format: path:lineNumber: matchedLine
    # If you want more detailed info, you can tweak how you output.
    foreach ($match in $allMatches) {
        $lineOutput = "{0}:{1}:{2}" -f $match.Path, $match.LineNumber, $match.Line
        $lineOutput | Out-File -Append $OutputFile
    }
    Write-Host "`nSearch complete! Found $($allMatches.Count) matches. See $OutputFile."
}
else {
    Write-Host "`nNo matches found for '$SearchTerm'."
}
