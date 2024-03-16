function Fetch-LatestChromeVersion {
    $url = "https://chromereleases.googleblog.com/search?max-results=10"
    $webpageContent = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content

    # Process the content to find the version number using regex
    if ($webpageContent -match "Stable Channel Update for Desktop.+?updated to ([\d\.]+)/?[\d\.]* ") {
        $version = $matches[1]
    }
    else {
        $version = "Could not find a specific Stable Channel Update for Desktop with a version number."
    }

    return $version
}

# Use the function to fetch and display the latest Google Chrome version for Desktop
$latestVersion = Fetch-LatestChromeVersion
Write-Output "The latest version of Google Chrome for Desktop is: $latestVersion"
