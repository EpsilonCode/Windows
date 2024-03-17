function Fetch-LatestChromeVersion {
    $url = "https://chromereleases.googleblog.com/search?max-results=10"
    Write-Host "Fetching webpage content from $url..."

    try {
        $webpageContent = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
    }
    catch {
        Write-Host "Failed to fetch webpage content."
        return "Error fetching webpage."
    }

    Write-Host "Webpage content fetched. Processing..."

    # Adjusted regex to match the structure and phrasing of the update announcement
    $regexPattern = "The Stable channel has been updated to (\d+\.\d+\.\d+\.\d+)/?.*? for Windows and Mac"
    if ($webpageContent -match $regexPattern) {
        $version = $matches[1] # Captures the main version number before any '/'
        Write-Host "Version captured: $version"
    } else {
        Write-Host "Failed to capture the version number with the updated regex pattern."
        $version = "Version number capture failed."
    }

    return $version
}

# Use the function to fetch and display the latest Google Chrome version for Desktop
$latestVersion = Fetch-LatestChromeVersion
Write-Output "The latest version of Google Chrome for Desktop is: $latestVersion"
