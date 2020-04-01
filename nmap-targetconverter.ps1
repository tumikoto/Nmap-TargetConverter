param (
	[Parameter(Mandatory=$true,Position=1)][string]$InputFile,
	[Parameter(Mandatory=$true,Position=2)][string]$OutputFile
)

# Checking pre-reqs
Write-Host -foregroundcolor Green [+] Checking pre-reqs
If (!(($InputFile) -and ($OutputFile))) {
	Write-Host [!] Missing parameter. Usage:
	Write-Host " "
	Write-Host pwsh nmap-targetconverter.ps1 -InputFile ./IP_ranges.txt -OutputFile ./IP_ranges_nmap.txt
	Write-Host " "
	Exit
} Elseif (!(Test-Path -Path $InputFile)) {
	Write-Host -foregroundcolor Red [!] InputFile arg is not a valid file path`, exiting.
	Exit
} Elseif (Test-Path -Path $OutputFile) {
	Write-Host -foregroundcolor Yellow [!] OutputFile already exists and will be overwritten. Press CTRL+C to exit`, otherwise
	Pause
}
If (Test-Path -Path ($OutputFile + "_failed.txt")) {
	Write-Host -foregroundcolor Yellow [!] Any lines which cannot be converted will be saved to($OutputFile + "_failed.txt") which already exists and will be overwritten. Press CTRL+C to exit`, otherwise
	Pause
}

# Load lines from txt file
Write-Host -Foregroundcolor Green [+] Loading contents of $InputFile
$FileContent = Get-Content $InputFile

# Set up arrays to store conversion results
$BadLines = @()
$ConvertedLines = @()

# Loop through lines in file and convert to nmap format
Write-Host -Foregroundcolor Green -Nonewline [+] Converting IP ranges to Nmap target format
Foreach ($Line in $FileContent) {
	Write-Host -Foregroundcolor Green -Nonewline " ."
	# Cleaning up
	$Line = $Line.Trim()
	$Line = $Line -replace " ",""
	
	# Sanity checks
	$OctetFormat = "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
	$IPformat = $OctetFormat + "." + $OctetFormat + "." + $OctetFormat + "." + $OctetFormat
	$LineFormat = "^" + $IPformat + "-" + $IPformat + "$"
	If ($Line -notmatch $LineFormat) {
		Write-Host " "
		Write-Host -Foregroundcolor Yellow [!] Line does not match expected `'d.d.d.d-d.d.d.d`' format: $Line
		$BadLines += $Line
		Continue
	}

	# Getting start and end IPs
	$Start = ($Line -split "-")[0]
	$End = ($Line -split "-")[1]

	# Getting octet values
	$StartOctet1 = ($Start -split "\.")[0]
	$StartOctet2 = ($Start -split "\.")[1]
	$StartOctet3 = ($Start -split "\.")[2]
	$StartOctet4 = ($Start -split "\.")[3]
	$EndOctet1 = ($End -split "\.")[0]
	$EndOctet2 = ($End -split "\.")[1]
	$EndOctet3 = ($End -split "\.")[2]
	$EndOctet4 = ($End -split "\.")[3]
	
	# Sanity checks
	If ($StartOctet1 -ne $EndOctet1) {
		Write-Host " "
		Write-Host -Foregroundcolor Yellow [!] Line appears to be a range of adjacent class A subnets, unsupported: $Line
		$BadLines += $Line
		Continue
	} ElseIf ($StartOctet2 -ne $EndOctet2) {
		Write-Host " "
		Write-Host -Foregroundcolor Yellow [!] Line appears to be a range of adjacent class B subnets, unsupported: $Line
		$BadLines += $Line
		Continue
	} ElseIf ($StartOctet3 -ne $EndOctet3) {
		If (!([Int]$StartOctet3 -lt [Int]$EndOctet3)) {
			Write-Host " "
			Write-Host -Foregroundcolor Yellow [!] Line end IP not greater than line start IP: $Line
			$BadLines += $Line
			Continue
		} ElseIf (([Int]$StartOctet4 -ne 0) -or ([Int]$EndOctet4 -ne 255)) {
			# Breaking up into multiple lines
			$Result1 = $Start + "-255"
			$Result2 = $StartOctet1 + "." + $StartOctet2 + "." + [String]([Int]$StartOctet3 + 1) + "-" + [String]([Int]$EndOctet3 - 1) + ".0-255"
			$Result3 = $EndOctet1 + "." + $EndOctet2 + "." + $EndOctet3 + ".0-" + $EndOctet4
			$ConvertedLines += $Result1
			$ConvertedLines += $Result2
			$ConvertedLines += $Result3
		} Else {
			$Result = $StartOctet1 + "." + $StartOctet2 + "." + $StartOctet3 + "-" + $EndOctet3 + "." + $StartOctet4 + "-" + $EndOctet4
			$ConvertedLines += $Result
		}
	} ElseIf ($StartOctet4 -ne $EndOctet4) {
		If (!([Int]$StartOctet4 -lt [Int]$EndOctet4)) {
			Write-Host " "
			Write-Host -Foregroundcolor Yellow [!] Line end IP not greater than line start IP: $Line
			$BadLines += $Line
			Continue
		} Else {
			$Result = $Start + "-" + $EndOctet4
			$ConvertedLines += $Result
		}
	}
}

# Saving results to file
Write-Host " "
If ($ConvertedLines) {
	Write-Host -Foregroundcolor Green [+] Successful conversions written to $OutputFile
	$ConvertedLines | Out-File $OutputFile
}
If ($BadLines) {
	Write-Host -Foregroundcolor Yellow [!] Failed conversions written to ($OutputFile + "_failed.txt")
	$BadLines | Out-File ($OutputFile + "_failed.txt")
}
Write-Host -Foregroundcolor Green [+] Done!
