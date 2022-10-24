# MemProcFS-Analyzer v0.6
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2021-2022 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:		  https://lethal-forensics.com/
# @date:	  2022-10-09
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
# 7-Zip 22.01 Standalone Console (2022-07-15)
# https://www.7-zip.org/download.html
#
# AmcacheParser v1.5.1.0 (.NET 6)
# https://ericzimmerman.github.io/
#
# AppCompatCacheParser v1.5.0.0 (.NET 6)
# https://ericzimmerman.github.io/
#
# ClamAV - Download --> Alternate Versions --> Windows Packages --> Win64 --> clamav-0.105.1.win.x64.msi (2022-07-26)
# https://www.clamav.net/downloads#otherversions
# https://docs.clamav.net/manual/Usage/Configuration.html#windows --> First Time Set-Up
# https://blog.clamav.net/
#
# Dokany Library Bundle v2.0.6.1000 (2022-10-02)
# https://github.com/dokan-dev/dokany/releases/latest --> DokanSetup.exe
#
# Elasticsearch 8.4.3 (2022-10-05)
# https://www.elastic.co/downloads/elasticsearch
#
# entropy v1.0 (2022-02-04)
# https://github.com/merces/entropy
#
# EvtxECmd v1.0.0.0 (.NET 6)
# https://ericzimmerman.github.io/
#
# ImportExcel 7.8.1 (2022-09-03)
# https://github.com/dfinke/ImportExcel
#
# Ipinfo CLI 2.10.0 (2022-09-28)
# https://github.com/ipinfo/cli
#
# Kibana 8.4.3 (2022-10-05)
# https://www.elastic.co/downloads/kibana
#
# lnk_parser v0.2.0 (2022-08-10)
# https://github.com/AbdulRhmanAlfaifi/lnk_parser
#
# MemProcFS v5.1.2 - The Memory Process File System (2022-09-26)
# https://github.com/ufrisk/MemProcFS
#
# RECmd v2.0.0.0 (.NET 6)
# https://ericzimmerman.github.io/
#
# SBECmd v2.0.0.0 (.NET 6)
# https://ericzimmerman.github.io/
#
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
#
# YARA v4.2.3 (2022-08-09)
# https://virustotal.github.io/yara/
#
#
# Changelog:
# Version 0.1
# Release Date: 2021-05-15
# Initial Release
#
# Version 0.2
# Release Date: 2021-05-26
# Added: IPinfo CLI
# Added: Collecting Registry Hives
# Added: AmcacheParser
# Added: AppCompatCacheParser (ShimCache)
# Added: PowerShell module 'ImportExcel'
# Added: Collection of PE_INJECT (PW: infected)
# Added: Hunting for suspicious Services
# Added: Hunting for suspicious Scheduled Tasks
# Fixed: Other minor fixes and improvements
#
# Version 0.3
# Release Date: 2021-06-17
# Added: OS Fingerprinting
# Added: Registry Explorer/RECmd
# Added: UserAssist
# Added: Syscache
# Added: ShellBags Explorer/SBECmd
# Added: Registry ASEPs (Auto-Start Extensibility Points)
# Fixed: Other minor fixes and improvements
#
# Version 0.4
# Release Date: 2022-07-27
# Added: Web Browser History
# Added: Forensic Timeline (CSV, XLSX)
# Added: JSON to CSV and XLSX output (including Handles)
# Added: Collecting output of pypykatz and regsecrets (MemProcFS Plugins)
# Added: RecentDocs
# Added: Office Trusted Documents
# Added: Adobe RecentDocs
# Added: Startup Folders
# Fixed: Other minor fixes and improvements
#
# Version 0.5
# Release Date: 2022-09-06
# Added: BitLocker Plugin
# Added: Kroll RECmd Batch File v1.20 (2022-06-01)
# Added: FS_Forensic_CSV + XLSX
# Added: FS_SysInfo_Users
# Added: Windows Shortcut Files (LNK)
# Added: Process Modules (Metadata)
# Added: Number of Sub-Processes (proc.csv, Processes.xlsx, and RunningandExited.xlsx)
# Added: Colorized Running and Exited Processes (RunningandExited.xlsx)
# Fixed: Other minor fixes and improvements
#
# Version 0.6
# Release Date: 2022-10-10
# Added: Process Tree (TreeView)
# Added: Unusual Number of Process Instances
# Added: Process Path Masquerading
# Added: Process Name Masquerading (Damerau Levenshtein Distance)
# Added: Suspicious Port Numbers
# Fixed: Other minor fixes and improvements
#
#
# Tested on Windows 10 Pro (x64) Version 21H2 (10.0.19044.2006) and PowerShell 5.1 (5.1.19041.1682)
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MemProcFS-Analyzer v0.6 - Automated Forensic Analysis of Windows Memory Dumps for DFIR

.DESCRIPTION
  MemProcFS-Analyzer.ps1 is a PowerShell script utilized to simplify the usage of MemProcFS and to assist with the memory analysis workflow.

.EXAMPLE
  PS> .\MemProcFS-Analyzer.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://github.com/evild3ad/MemProcFS-Analyzer
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $script:SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Analysis date (ISO 8601)
$script:Date = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss") # YYYY-MM-DDThh:mm:ss
$script:Timestamp = $Date -replace ":", "" # YYYY-MM-DDThhmmss

# Drive Letter (Mount Point)
$script:DriveLetter = "X:"

# Tools

# 7-Zip
$script:7za = "$SCRIPT_DIR\Tools\7-Zip\7za.exe"

# AmcacheParser
$script:AmcacheParser = "$SCRIPT_DIR\Tools\AmcacheParser\AmcacheParser.exe"

# AppCompatCacheParser
$script:AppCompatCacheParser = "$SCRIPT_DIR\Tools\AppCompatCacheParser\AppCompatCacheParser.exe"

# ClamAV
$script:freshclam = "C:\Program Files\ClamAV\freshclam.exe"
$script:clamscan = "C:\Program Files\ClamAV\clamscan.exe"
$script:clamd = "C:\Program Files\ClamAV\clamd.exe"
$script:clamdscan = "C:\Program Files\ClamAV\clamdscan.exe"

# Elasticsearch
$script:Elasticsearch = "$SCRIPT_DIR\Tools\Elasticsearch\bin\elasticsearch.bat"

# entropy
$script:entropy = "$SCRIPT_DIR\Tools\entropy\entropy.exe"

# EvtxECmd
$script:EvtxECmd = "$SCRIPT_DIR\Tools\EvtxECmd\EvtxECmd.exe"

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

# Kibana
$script:Kibana = "$SCRIPT_DIR\Tools\Kibana\bin\kibana.bat"

# lnk_parser
$script:lnk_parser = "$SCRIPT_DIR\Tools\lnk_parser\lnk_parser_x86_64.exe"

# MemProcFS
$script:MemProcFS = "$SCRIPT_DIR\Tools\MemProcFS\MemProcFS.exe"

# RECmd
$script:RECmd = "$SCRIPT_DIR\Tools\RECmd\RECmd.exe"

# SBECmd
$script:SBECmd = "$SCRIPT_DIR\Tools\SBECmd\SBECmd.exe"

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

# YARA
$script:yara64 = "$SCRIPT_DIR\Tools\YARA\yara64.exe"

# Archive Password
$script:PASSWORD = "MemProcFS"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$script:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

Function Header {

# Windows Title
$script:DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer v0.6 - Automated Forensic Analysis of Windows Memory Dumps for DFIR"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Requirements

# Dokany File System Library
$Dokany = "$env:SystemDrive\Windows\System32\dokan2.dll"
if (!(Test-Path "$Dokany"))
{
    Write-Host "[Error] Dokany File System Library NOT found." -ForegroundColor Red
    Write-Host "        Please download/install the latest release of Dokany File System Library manually:" -ForegroundColor Red
    Write-Host "        https://github.com/dokan-dev/dokany/releases/latest (DokanSetup.exe)" -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# EZTools
if (Get-Command -CommandType Application dotnet -ErrorAction SilentlyContinue)
{
    # TargetFramework (.NET 6)
    if (!(dotnet --list-runtimes | Select-String -Pattern "^Microsoft\.WindowsDesktop\.App" -Quiet))
    {
        Write-Host "[Error] Please download/install at least .NET 6.0 or newer manually:" -ForegroundColor Red
        Write-Host "        https://dotnet.microsoft.com/en-us/download/dotnet/6.0 (Recommended: .NET Desktop Runtime)" -ForegroundColor Red
    }
}

# Function Get-FileSize
Function script:Get-FileSize {
Param ([long]$Size)
If ($Size -gt 1TB) {[string]::Format("{0:0.00} TB", $Size / 1TB)}
ElseIf ($Size -gt 1GB) {[string]::Format("{0:0.00} GB", $Size / 1GB)}
ElseIf ($Size -gt 1MB) {[string]::Format("{0:0.00} MB", $Size / 1MB)}
ElseIf ($Size -gt 1KB) {[string]::Format("{0:0.00} KB", $Size / 1KB)}
ElseIf ($Size -gt 0) {[string]::Format("{0:0.00} Bytes", $Size)}
Else {""}
}

# Function Measure-DamerauLevenshteinDistance by Jared Atkinson (@jaredcatkinson)
Function script:Measure-DamerauLevenshteinDistance {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Original,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $Modified
    )

    if ($original -eq $modified)
    {
        return 0
    }

    $len_orig = $original.Length
    $len_diff = $modified.Length

    if ($len_orig -eq 0)
    {
        return $len_diff
    }

    if ($len_diff -eq 0)
    {
        return $len_orig
    }

    $matrix = New-Object -TypeName 'object[,]' ($len_orig + 1), ($len_diff + 1)

    for ($i = 1; $i -le $len_orig; $i++)
    {
        $matrix[$i,0] = $i

        for ($j = 1; $j -le $len_diff; $j++)
        {
            if ($modified[$j - 1] -eq $original[$i - 1])
            {
                $cost = 0
            }
            else
            {
                $cost = 1
            }

            if ($i -eq 1)
            {
                $matrix[0,$j] = $j
            }

            $v1 = $matrix[($i - 1), $j] + 1
            $v2 = $matrix[$i, ($j - 1)] + 1
            $v3 = $matrix[($i - 1), ($j - 1)] + $cost
            $vals = @($v1, $v2, $v3)

            $matrix[$i,$j] = ($vals | Measure-Object -Minimum).Minimum

            if (($i -gt 1) -and ($j -gt 1) -and ($original[$i - 1] -eq $modified[$j - 2]) -and ($original[$i - 2] -eq $modified[$j - 1]))
            {
                $val1 = $matrix[$i, $j]
                $val2 = $matrix[($i - 2), ($j - 2)] + $cost
                $matrix[$i, $j] = [Math]::Min($val1, $val2)
            }
        }
    }
    return $matrix[$len_orig, $len_diff]
}

# Add the required MessageBox class (Windows PowerShell)
Add-Type -AssemblyName System.Windows.Forms

# Select Raw Physical Memory Dump
Function Get-OpenFile($InitialDirectory)
{ 
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "MemProcFS-Analyzer v0.6 - Select Raw Physical Memory Dump"
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.Filter = "Memory Dump Files (*.bin;*.img;*.mem;*.raw;*.vmem)|*.bin;*.img;*.mem;*.raw;*.vmem|All Files (*.*)|*.*"
    $OpenFileDialog.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost=$true; TopLevel=$true}))
    $OpenFileDialog.Filename
    $OpenFileDialog.ShowHelp = $true
    $OpenFileDialog.Multiselect = $false
}

$Result = Get-OpenFile

if($Result -eq "OK")
{
    $script:MemoryDump = $Result[1]
}
else
{
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# FileName
$script:FileName = $MemoryDump.Split('\')[-1] | ForEach-Object{($_ -replace "\..*","")}

# Output Directory
$script:OUTPUT_FOLDER = "$SCRIPT_DIR\$Timestamp-$FileName"

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$SCRIPT_DIR\$Timestamp-$FileName.txt"

# Get Start Time
$script:startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Host ""
Write-Host "$Logo"

# Header
Write-Output ""
Write-Output "MemProcFS-Analyzer v0.6 - Automated Forensic Analysis of Windows Memory Dumps for DFIR"
Write-Output "(c) 2021-2022 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = $Date -replace "T", " " # YYYY-MM-DD hh:mm:ss
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Updater

Function Updater {

Function InternetConnectivityCheck {

# Internet Connectivity Check (Vista+)
$NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

# Offline
if (!($NetworkListManager -eq "True"))
{
    Write-Host "[Error] Your computer is NOT connected to the Internet." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Online
if ($NetworkListManager -eq "True")
{
    # Check if GitHub is reachable
    if (!(Test-Connection -ComputerName github.com -Count 1 -Quiet))
    {
        Write-Host "[Error] github.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }

    # Check if Backblaze B2 Platform is reachable
    if (!(Test-Connection -ComputerName f001.backblazeb2.com -Count 1 -Quiet))
    {
        Write-Host "[Error] f001.backblazeb2.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

}

#############################################################################################################################################################################################

Function Get-MemProcFS {

# Check Current Version of MemProcFS
if (Test-Path "$MemProcFS")
{
    if (Test-Path "$SCRIPT_DIR\Tools\MemProcFS\Version.txt")
    {
        $CurrentVersion = Get-Content "$SCRIPT_DIR\Tools\MemProcFS\Version.txt"
        Write-Output "[Info]  Current Version: MemProcFS v$CurrentVersion"
    }
}
else
{
    Write-Output "[Info]  MemProcFS NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "ufrisk/MemProcFS"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "win_x64" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]
$Version = $Download | ForEach-Object{($_ -split "_")[4]} | ForEach-Object{($_ -split "-")[0]}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  MemProcFS $Version ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: MemProcFS $Version ($ReleaseDate)"
}

# Check if MemProcFS needs to be downloaded/updated
$LatestRelease = $Version.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "MemProcFS.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\MemProcFS" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force

        # New Version
        $CurrentVersion = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($MemProcFS).FileVersion).SubString(0,5)
        & $MemProcFS | Out-File "$SCRIPT_DIR\Tools\MemProcFS\help.txt"
        (Get-Content "$SCRIPT_DIR\Tools\MemProcFS\help.txt" | Select-String -Pattern "COMMAND LINE REFERENCE" | ForEach-Object{($_ -split "\s+")[6]}).Substring(1) | Out-File "$SCRIPT_DIR\Tools\MemProcFS\Version.txt"
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of MemProcFS." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Dokany {

# Check Current Version of Dokany File System Library
$Dokany = "$env:SystemDrive\Windows\System32\dokan2.dll"
if (Test-Path "$Dokany")
{
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Dokany).FileVersion
    $LastWriteTime = ((Get-Item $Dokany).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: Dokany File System Library v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  Dokany File System Library NOT found."
    $CurrentVersion = ""
}

# Determining latest release of DokanSetup.exe on GitHub
# Note: Needs a restart of the computer.
$Repository = "dokan-dev/dokany"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "DokanSetup.exe" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Dokany File System Library $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Dokany File System Library $Tag ($ReleaseDate)"
}

# Check if Dokany File System Library needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    Write-Host "[Error] Please download/install the latest release of Dokany File System Library manually:" -ForegroundColor Red
    Write-Host "        https://github.com/dokan-dev/dokany/releases/latest (DokanSetup.exe)" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  You are running the most recent version of Dokany File System Library." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Elasticsearch {

# Elasticsearch
# https://github.com/elastic/elasticsearch

# Check Current Version of Elasticsearch
if (Test-Path "$Elasticsearch")
{
    $CurrentVersion = & $Elasticsearch --version | ForEach-Object{($_ -split "\s+")[1]} | ForEach-Object{($_ -replace ",","")}
    Write-Output "[Info]  Current Version: Elasticsearch v$CurrentVersion"
    Start-Sleep 1
}
else
{
    Write-Output "[Info]  Elasticsearch NOT found."
    $CurrentVersion = ""
}

# Determining latest release of Elasticsearch on GitHub
$Repository = "elastic/elasticsearch"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Elasticsearch $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Elasticsearch $Tag ($ReleaseDate)"
}

# Check if Elasticsearch needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    # Download latest release from elastic.co
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Download = "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$LatestRelease-windows-x86_64.zip"
    $Zip = "Elasticsearch.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\Elasticsearch")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\Elasticsearch" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\Elasticsearch" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Rename Unpacked Directory
        Start-Sleep 10
        Rename-Item "$SCRIPT_DIR\Tools\elasticsearch-$LatestRelease" "$SCRIPT_DIR\Tools\Elasticsearch" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of Elasticsearch." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Kibana {

# Kibana
# https://github.com/elastic/kibana

# Check Current Version of Kibana
if (Test-Path "$Kibana")
{
    $CurrentVersion = & $Kibana --version
    Write-Output "[Info]  Current Version: Kibana v$CurrentVersion"
    Start-Sleep 1
}
else
{
    Write-Output "[Info]  Kibana NOT found."
    $CurrentVersion = ""
}

# Determining latest release of Kibana on GitHub
$Repository = "elastic/kibana"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Kibana $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Kibana $Tag ($ReleaseDate)"
}

# Check if Kibana needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    # Download latest release from elastic.co
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Download = "https://artifacts.elastic.co/downloads/kibana/kibana-$LatestRelease-windows-x86_64.zip"
    $Zip = "Kibana.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\Kibana")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\Kibana" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\Kibana" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        if (Test-Path "$7za")
        {
            $DestinationPath = "$SCRIPT_DIR\Tools"
            & $7za x "$SCRIPT_DIR\Tools\$Zip" "-o$DestinationPath" > $null 2>&1
        }
        else
        {
            Write-Host "[Error] 7za.exe NOT found." -ForegroundColor Red
            Stop-Transcript
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }

        # Rename Unpacked Directory
        Start-Sleep 10
        Rename-Item "$SCRIPT_DIR\Tools\kibana-$LatestRelease" "$SCRIPT_DIR\Tools\Kibana" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of Kibana." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-AmcacheParser {

# AmcacheParser (.NET 6)
# https://ericzimmerman.github.io

# Check Current Version and SHA1 of AmcacheParser
if (Test-Path "$AmcacheParser")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AmcacheParser).FileVersion
    Write-Output "[Info]  Current Version: AmcacheParser v$CurrentVersion"

    # SHA1
    if (Test-Path "$SCRIPT_DIR\Tools\AmcacheParser\SHA1.txt")
    {
        $CurrentSHA1 = Get-Content "$SCRIPT_DIR\Tools\AmcacheParser\SHA1.txt"
    }
    else
    {
        $CurrentSHA1 = ""
    }

    # Determining latest release of AmcacheParser
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/AmcacheParser.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestSHA1 = $Headers["x-bz-content-sha1"]
}
else
{
    Write-Output "[Info]  AmcacheParser NOT found."
    $CurrentSHA1 = ""
}

if ($null -eq $CurrentSHA1 -or $CurrentSHA1 -ne $LatestSHA1)
{
    # Download latest release from Backblaze
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/AmcacheParser.zip"
    $Zip = "AmcacheParser.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\AmcacheParser")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\AmcacheParser" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\AmcacheParser" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\AmcacheParser" -Force

        # Calculate SHA1 of AmcacheParser.zip
        Start-Sleep 5
        (Get-FileHash -Path "$SCRIPT_DIR\Tools\$Zip" -Algorithm SHA1).Hash | Out-File "$SCRIPT_DIR\Tools\AmcacheParser\SHA1.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of AmcacheParser." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-AppCompatCacheParser {

# AppCompatCacheParser (.NET 6)
# https://ericzimmerman.github.io

# Check Current Version and SHA1 of AppCompatCacheParser
if (Test-Path "$AppCompatCacheParser")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppCompatCacheParser).FileVersion
    Write-Output "[Info]  Current Version: AppCompatCacheParser v$CurrentVersion"

    # SHA1
    if (Test-Path "$SCRIPT_DIR\Tools\AppCompatCacheParser\SHA1.txt")
    {
        $CurrentSHA1 = Get-Content "$SCRIPT_DIR\Tools\AppCompatCacheParser\SHA1.txt"
    }
    else
    {
        $CurrentSHA1 = ""
    }

    # Determining latest release of AppCompatCacheParser
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/AppCompatCacheParser.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestSHA1 = $Headers["x-bz-content-sha1"]
}
else
{
    Write-Output "[Info]  AppCompatCacheParser NOT found."
    $CurrentSHA1 = ""
}

if ($null -eq $CurrentSHA1 -or $CurrentSHA1 -ne $LatestSHA1)
{
    # Download latest release from Backblaze
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/AppCompatCacheParser.zip"
    $Zip = "AppCompatCacheParser.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\AppCompatCacheParser")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\AppCompatCacheParser" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\AppCompatCacheParser" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\AppCompatCacheParser" -Force

        # Calculate SHA1 of AppCompatCacheParser.zip
        Start-Sleep 5
        (Get-FileHash -Path "$SCRIPT_DIR\Tools\$Zip" -Algorithm SHA1).Hash | Out-File "$SCRIPT_DIR\Tools\AppCompatCacheParser\SHA1.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of AppCompatCacheParser." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Entropy {

# entropy
# https://github.com/merces/entropy

# Check Current Version of entropy.exe
if (Test-Path "$entropy")
{
    # Current Version
    if (Test-Path "$SCRIPT_DIR\Tools\entropy\Version.txt")
    {
        $CurrentVersion = Get-Content "$SCRIPT_DIR\Tools\entropy\Version.txt"
        $LastWriteTime = ((Get-Item $entropy).LastWriteTime).ToString("yyyy-MM-dd")
        Write-Output "[Info]  Current Version: entropy v$CurrentVersion ($LastWriteTime)"
    }
    else
    {
        $CurrentVersion = ""
    }
}
else
{
    Write-Output "[Info]  entropy.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "merces/entropy"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "-win64" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]
$LatestRelease = $Tag.Substring(1)

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  entropy $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: entropy $Tag ($ReleaseDate)"
}

# Check if entropy.exe needs to be downloaded/updated
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "entropy.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\entropy")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\entropy" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\entropy" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Rename Unpacked Directory
        Start-Sleep 5
        Rename-Item "$SCRIPT_DIR\Tools\entropy-$LatestRelease-win64" "$SCRIPT_DIR\Tools\entropy" -Force

        # Version
        Write-Output "$LatestRelease" | Out-File "$SCRIPT_DIR\Tools\entropy\Version.txt"

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of entropy." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-EvtxECmd {

# EvtxECmd (.NET 6)
# https://ericzimmerman.github.io

# Check Current Version and SHA1 of EvtxECmd
if (Test-Path "$EvtxECmd")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($EvtxECmd).FileVersion
    Write-Output "[Info]  Current Version: EvtxECmd v$CurrentVersion"

    # SHA1
    if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd\SHA1.txt")
    {
        $CurrentSHA1 = Get-Content "$SCRIPT_DIR\Tools\EvtxECmd\SHA1.txt"
    }
    else
    {
        $CurrentSHA1 = ""
    }

    # Determining latest release of EvtxECmd
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/EvtxECmd.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestSHA1 = $Headers["x-bz-content-sha1"]
}
else
{
    Write-Output "[Info]  EvtxECmd NOT found."
    $CurrentSHA1 = ""
}

if ($null -eq $CurrentSHA1 -or $CurrentSHA1 -ne $LatestSHA1)
{
    # Download latest release from Backblaze
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/EvtxECmd.zip"
    $Zip = "EvtxECmd.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\EvtxECmd" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\EvtxECmd" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Calculate SHA1 of EvtxECmd.zip
        Start-Sleep 5
        (Get-FileHash -Path "$SCRIPT_DIR\Tools\$Zip" -Algorithm SHA1).Hash | Out-File "$SCRIPT_DIR\Tools\EvtxECmd\SHA1.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of EvtxECmd." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-ImportExcel {

# ImportExcel
# https://github.com/dfinke/ImportExcel

# Check if PowerShell module 'ImportExcel' exists
if (Get-Module -ListAvailable -Name ImportExcel) 
{
    # Check if multiple versions of PowerShell module 'ImportExcel' exist
    $Modules = (Get-Module -ListAvailable -Name ImportExcel | Measure-Object).Count

    if ($Modules -eq "1")
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel).Version.ToString()
        Write-Output "[Info]  Current Version: ImportExcel v$CurrentVersion"
    }
    else
    {
        Write-Host "[Info]  Multiple installed versions of PowerShell module 'ImportExcel' found. Uninstalling ..."
        Uninstall-Module -Name ImportExcel -AllVersions -ErrorAction SilentlyContinue
        $CurrentVersion = $null
    }
}
else
{
    Write-Output "[Info]  PowerShell module 'ImportExcel' NOT found."
    $CurrentVersion = $null
}

# Determining latest release on GitHub
$Repository = "dfinke/ImportExcel"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$ReleaseDate = $Published.split('T')[0]
$LatestRelease = $Tag.Substring(1)

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  ImportExcel $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: ImportExcel $Tag ($ReleaseDate)"
}

# Check if ImportExcel needs to be installed
if ($null -eq $CurrentVersion)
{
    Write-Output "[Info]  Installing ImportExcel v$LatestRelease ..."
    Install-Module -Name ImportExcel -Scope CurrentUser -Repository PSGallery -Force
}

# Check if ImportExcel needs to be updated
if ($CurrentVersion -ne $LatestRelease)
{
    # Remove and uninstall PowerShell module 'ImportExcel'
    try
    {
        Update-Module -Name ImportExcel -Force -ErrorAction SilentlyContinue
    }
    catch
    {
        Write-Output "PowerShell module 'ImportExcel' is in use. Please close PowerShell session, and run MemProcFS-Analyzer.ps1 again."
    }   
}
else
{
    Write-Host "[Info]  You are running the most recent version of ImportExcel." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-IPinfo {

# IPinfo CLI
# https://github.com/ipinfo/cli

# Check Current Version of IPinfo CLI
if (Test-Path "$IPinfo")
{
    $CurrentVersion = & $IPinfo version
    $LastWriteTime = ((Get-Item $IPinfo).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: IPinfo CLI v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  IPinfo CLI NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "ipinfo/cli"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)

$Asset=0
while($true) {
  $Asset++
  $Check = $Response[$Asset].assets | Select-Object @{Name="browser_download_orl"; Expression={$_.browser_download_url}} | Select-String -Pattern "ipinfo_" -Quiet
  if ($Check -eq "True" )
  {
    Break
  }
}

$TagName = $Response[$Asset].tag_name
$Tag = $TagName.Split("-")[1] 
$Published = $Response[$Asset].published_at
$Download = ($Response[$Asset].assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "windows_amd64" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  IPinfo CLI v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: IPinfo CLI v$Tag ($ReleaseDate)"
}

# Check if IPinfo CLI needs to be downloaded/updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "IPinfo.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\IPinfo")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\IPinfo" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\IPinfo" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\IPinfo" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force

        # Rename Executable
        if (Test-Path "$SCRIPT_DIR\Tools\IPinfo\ipinfo_*")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\IPinfo\ipinfo_*.exe" | Rename-Item -NewName {"ipinfo.exe"}
        }
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of IPinfo CLI." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-lnk_parser {

# lnk_parser
# https://github.com/AbdulRhmanAlfaifi/lnk_parser

# Check Current Version of lnk_parser
if (Test-Path "$lnk_parser")
{
    $CurrentVersion = & $lnk_parser --version | ForEach-Object{($_ -split "\s+")[1]}
    $LastWriteTime = ((Get-Item $lnk_parser).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: lnk_parser v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  lnk_parser_x86_64.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "AbdulRhmanAlfaifi/lnk_parser"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "lnk_parser_x86_64.exe" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  lnk_parser $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: lnk_parser $Tag ($ReleaseDate)"
}

# Check if lnk_parser needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    if (Test-Path "$SCRIPT_DIR\Tools\lnk_parser\lnk_parser_x86_64.exe")
    {
        Get-ChildItem -Path "$SCRIPT_DIR\Tools\lnk_parser" -Recurse | Remove-Item -Force -Recurse
    }
    else
    {
        New-Item "$SCRIPT_DIR\Tools\lnk_parser" -ItemType Directory -Force | Out-Null
    }
    
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $EXE = "lnk_parser_x86_64.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\Tools\lnk_parser\$EXE"
}
else
{
    Write-Host "[Info]  You are running the most recent version of lnk_parser." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-RECmd {

# RECmd (.NET 6)
# https://ericzimmerman.github.io

# Check Current Version and SHA1 of RECmd
if (Test-Path "$RECmd")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($RECmd).FileVersion
    Write-Output "[Info]  Current Version: RECmd v$CurrentVersion"

    # SHA1
    if (Test-Path "$SCRIPT_DIR\Tools\RECmd\SHA1.txt")
    {
        $CurrentSHA1 = Get-Content "$SCRIPT_DIR\Tools\RECmd\SHA1.txt"
    }
    else
    {
        $CurrentSHA1 = ""
    }

    # Determining latest release of RECmd
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/RECmd.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestSHA1 = $Headers["x-bz-content-sha1"]
}
else
{
    Write-Output "[Info]  RECmd NOT found."
    $CurrentSHA1 = ""
}

if ($null -eq $CurrentSHA1 -or $CurrentSHA1 -ne $LatestSHA1)
{
    # Download latest release from Backblaze
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/RECmd.zip"
    $Zip = "RECmd.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\RECmd" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\RECmd" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools" -Force

        # Calculate SHA1 of RECmd.zip
        Start-Sleep 5
        (Get-FileHash -Path "$SCRIPT_DIR\Tools\$Zip" -Algorithm SHA1).Hash | Out-File "$SCRIPT_DIR\Tools\RECmd\SHA1.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of RECmd." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-SBECmd {

# SBECmd (.NET 6)
# https://ericzimmerman.github.io

# Check Current Version and SHA1 of SBECmd
if (Test-Path "$SBECmd")
{
    # Current Version
    $CurrentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($SBECmd).FileVersion
    Write-Output "[Info]  Current Version: SBECmd v$CurrentVersion"

    # SHA1
    if (Test-Path "$SCRIPT_DIR\Tools\SBECmd\SHA1.txt")
    {
        $CurrentSHA1 = Get-Content "$SCRIPT_DIR\Tools\SBECmd\SHA1.txt"
    }
    else
    {
        $CurrentSHA1 = ""
    }

    # Determining latest release of SBECmd
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/SBECmd.zip"
    $Headers = (Invoke-WebRequest -Uri $URL -UseBasicParsing -Method Head).Headers
    $LatestSHA1 = $Headers["x-bz-content-sha1"]
}
else
{
    Write-Output "[Info]  SBECmd NOT found."
    $CurrentSHA1 = ""
}

if ($null -eq $CurrentSHA1 -or $CurrentSHA1 -ne $LatestSHA1)
{
    # Download latest release from Backblaze
    Write-Output "[Info]  Dowloading Latest Release ..."
    $ProgressPreference = 'SilentlyContinue'
    $URL = "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/SBECmd.zip"
    $Zip = "SBECmd.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $URL -OutFile "$SCRIPT_DIR\Tools\$Zip"

    if (Test-Path "$SCRIPT_DIR\Tools\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\SBECmd")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\SBECmd" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\SBECmd" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\Tools\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\SBECmd" -Force

        # Calculate SHA1 of SBECmd.zip
        Start-Sleep 5
        (Get-FileHash -Path "$SCRIPT_DIR\Tools\$Zip" -Algorithm SHA1).Hash | Out-File "$SCRIPT_DIR\Tools\SBECmd\SHA1.txt"

        # Remove Downloaded Archive
        Remove-Item "$SCRIPT_DIR\Tools\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of SBECmd." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-XSV {

# xsv
# https://github.com/BurntSushi/xsv

# Check Current Version of xsv
if (Test-Path "$xsv")
{
    $CurrentVersion = & $xsv --version
    $LastWriteTime = ((Get-Item $xsv).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: xsv v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  xsv.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "BurntSushi/xsv"
$Releases = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "-x86_64-pc-windows-msvc" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  xsv v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: xsv v$Tag ($ReleaseDate)"
}

# Check if xsv needs to be downloaded/updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "xsv.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\xsv")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\xsv" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\xsv" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\xsv" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of xsv." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Yara {

# YARA
# https://github.com/VirusTotal/yara

# Check Current Version of YARA
if (Test-Path "$yara64")
{
    $CurrentVersion = & $yara64 --version
    $LastWriteTime = ((Get-Item $yara64).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: YARA v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  yara64.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "VirusTotal/yara"
$Latest = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Latest -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "-win64" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  YARA $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: YARA $Tag ($ReleaseDate)"
}

# Check if YARA needs to be downloaded/updated
$LatestRelease = $Tag.Substring(1)
if ($CurrentVersion -ne $LatestRelease -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "yara64.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$SCRIPT_DIR\$Zip"

    if (Test-Path "$SCRIPT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$SCRIPT_DIR\Tools\YARA")
        {
            Get-ChildItem -Path "$SCRIPT_DIR\Tools\YARA" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$SCRIPT_DIR\Tools\YARA" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$SCRIPT_DIR\$Zip" -DestinationPath "$SCRIPT_DIR\Tools\YARA" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$SCRIPT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of YARA." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

# Installer/Updater
InternetConnectivityCheck
Get-MemProcFS
Get-Dokany
Get-Elasticsearch
Get-Kibana
Get-AmcacheParser
Get-AppCompatCacheParser
Get-Entropy
Get-EvtxECmd
Get-ImportExcel
Get-IPinfo
Get-lnk_parser
Get-RECmd
Get-SBECmd
Get-XSV
Get-Yara

}

#endregion Updater

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Elasticsearch

Function Elasticsearch {

# Launch Elasticsearch (PowerShell.exe)
Write-Output "[Info]  Starting Elasticsearch ... "
$Elasticsearch_Process = Start-Process powershell.exe "& $Elasticsearch" -WindowStyle Minimized -PassThru
$Elasticsearch_Id = $Elasticsearch_Process.Id
$script:Elasticsearch_Termination = Get-Process | Where-Object {$_.Id -eq $Elasticsearch_Id}
$ProgressPreference = 'SilentlyContinue'
do {
  Start-Sleep 1
  $ProgressPreference = 'SilentlyContinue'
} until( Test-NetConnection localhost -Port 9200 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $_.TcpTestSucceeded })

# Launch Kibana (PowerShell.exe)
Write-Output "[Info]  Starting Kibana ... "
$Kibana_Process = Start-Process powershell.exe "& $Kibana" -WindowStyle Minimized -PassThru
$Kibana_Id = $Kibana_Process.Id
$script:Kibana_Termination = Get-Process | Where-Object {$_.Id -eq $Kibana_Id}
$ProgressPreference = 'SilentlyContinue'
do {
  Start-Sleep 1
  $ProgressPreference = 'SilentlyContinue'
} until(Test-NetConnection localhost -Port 5601 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $_.TcpTestSucceeded })

Start-Sleep 2

}

#endregion Elasticsearch

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region MemProcFS

Function MemProcFS {

# MemProcFS
# https://github.com/ufrisk/MemProcFS

# Mount the physical memory dump file and enable forensic mode
if (Test-Path "$MemProcFS")
{
    if (Test-Path "$MemoryDump")
    {
        Write-Output "[Info]  Mounting the Physical Memory Dump file as $DriveLetter ..."

        $MemorySize = Get-FileSize((Get-Item "$MemoryDump").Length)
        Write-Output "[Info]  Physical Memory Dump File Size: $MemorySize"

        Write-Output "[Info]  MemProcFS Forensic Analysis initiated ..."
        Write-Output "[Info]  Processing $MemoryDump [approx. 1-3 min] ..."
        New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
        $Mount = $DriveLetter -replace ":", ""
        $StartTime_MemProcFS = (Get-Date)
        Start-Process -FilePath "$MemProcFS" -ArgumentList "-mount $Mount -device `"$MemoryDump`" -forensic 4"

        # Check if successfully mounted
        while (!(Test-Path "$DriveLetter"))
        {
            Start-Sleep -Seconds 2
        }

        # Check forensic mode processing
        while (!(Select-String -Pattern "100" -Path "$DriveLetter\forensic\progress_percent.txt" -Quiet))
        {
            Start-Sleep -Seconds 2
        }

        $EndTime_MemProcFS = (Get-Date)
        $Time_MemProcFS = ($EndTime_MemProcFS-$StartTime_MemProcFS)
        ('MemProcFS Processing duration: {0} h {1} min {2} sec' -f $Time_MemProcFS.Hours, $Time_MemProcFS.Minutes, $Time_MemProcFS.Seconds) > "$OUTPUT_FOLDER\Stats.txt"
    }
    else
    {
        Write-Host "[Error] Physical Memory Dump file does NOT exist." -ForegroundColor Red
        Stop-Transcript
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }

    # Check if Mount Point exists
    if (Test-Path "$DriveLetter\forensic\*")
    {
        # CurrentControlSet
        $RegistryValue = "$DriveLetter\registry\HKLM\SYSTEM\Select\Current.txt"

        if (Test-Path "$RegistryValue")
        {
            $CurrentControlSet = Get-Content "$RegistryValue" | Select-Object -Skip 2 | ForEach-Object {$_ -replace "^0+", ""}
        }

        # ComputerName
        $RegistryValue = "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\ComputerName\ComputerName\ComputerName.txt"

        if (Test-Path "$RegistryValue")
        {
            $ComputerName = Get-Content "$RegistryValue" | Select-Object -Skip 2
            Write-Output "[Info]  Host Name: $ComputerName"
        }

        # ProductName
        $ProductName = "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName.txt"

        # OSName
        if (Test-Path "$ProductName")
        {
            $OSName = Get-Content "$ProductName" | Select-Object -Skip 2
        }

        # OSArchitecture
        if (Test-Path "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_ARCHITECTURE.txt")
        {
            $PROCESSOR_ARCHITECTURE = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_ARCHITECTURE.txt" | Select-Object -Skip 2

            if ($PROCESSOR_ARCHITECTURE -match "AMD64")
            {
                $OSArchitecture = "x64"
            }
            else
            {
                $OSArchitecture = "x86"
            }
        }
        else
        {
            Write-Host "[Info]  Processor Architecture: UNKNOWN"
        }

        # CSDVersion
        $CSDVersion = "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CSDVersion.txt"

        if (Test-Path "$CSDVersion")
        {
            # OSVersion
            $OSVersion = (Get-Content "$CSDVersion" | Select-Object -Skip 2) -creplace '(?s)^.*Service Pack ', ''
        }

        # Windows 10
        if ($OSName -like "*Windows 10*")
        {
            # Major
            $CurrentMajorVersionNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentMajorVersionNumber.txt" | Select-Object -Skip 2
            $Major = [Convert]::ToInt64("$CurrentMajorVersionNumber",16)

            # Minor
            $CurrentMinorVersionNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentMinorVersionNumber.txt" | Select-Object -Skip 2
            $Minor = [Convert]::ToInt64("$CurrentMinorVersionNumber",16)
        }
        else 
        {
            # CurrentVersion
            $CurrentVersion = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion.txt" | Select-Object -Skip 2

            # Major
            $Major = $CurrentVersion.split('.')[0]

            # Minor
            $Minor = $CurrentVersion.split('.')[1]
        }

        # Windows 10, Windows Server 2016, Windows Server 2019, and Windows Server 2022
        if (($OSName -like "*Windows 10*") -Or ($OSName -like "*Windows Server 2016*") -Or ($OSName -like "*Windows Server 2019*") -Or ($OSName -like "*Windows Server 2022*"))
        {
            # DisplayVersion
            $DisplayVersion = ( (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name DisplayVersion).DisplayVersion ) 2> $null

            # ReleaseID
            $ReleaseID = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ReleaseId.txt" | Select-Object -Skip 2
    
            # CurrentBuildNumber
            $CurrentBuildNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber.txt" | Select-Object -Skip 2

            # Revision
            $BuildLabEx = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLabEx.txt" | Select-Object -Skip 2
            $Revision = $BuildLabEx.split('.')[1]

            Write-Output "[Info]  OS: $OSName ($OSArchitecture), Version: $ReleaseID / $DisplayVersion ($Major.$Minor.$CurrentBuildNumber.$Revision)"
        }
        else
        {
            # CurrentBuildNumber
            $CurrentBuildNumber = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber.txt" | Select-Object -Skip 2

            # Revision
            $BuildLabEx = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLabEx.txt" | Select-Object -Skip 2
            $Revision = $BuildLabEx.split('.')[1]

            Write-Output "[Info]  OS: $OSName ($OSArchitecture), Service Pack $OSVersion ($Major.$Minor.$CurrentBuildNumber.$Revision)"
        }

        # InstallDate (ISO 8601)
        $RegistryValue = "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate.txt"

        if (Test-Path "$RegistryValue")
        {
            $HexadecimalBigEndian = Get-Content "$RegistryValue" | Select-Object -Skip 2
            $UnixSeconds = [Convert]::ToInt64("$HexadecimalBigEndian",16)
            $InstallDate = ((Get-Date 01.01.1970).AddSeconds($UnixSeconds)).ToString("yyyy-MM-dd HH:mm:ss")
            Write-Output "[Info]  InstallDate: $InstallDate UTC"
        }

        # RegisteredOrganization
        $RegisteredOrganization = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization.txt" -ErrorAction SilentlyContinue | Select-Object -Skip 2
        if ($null -ne $RegisteredOrganization)
        {
            Write-Output "[Info]  RegisteredOrganization: $RegisteredOrganization"
        } 
        else 
        {
            Write-Output "[Info]  RegisteredOrganization: --"
        }

        # RegisteredOwner
        $RegisteredOwner = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner.txt" | Select-Object -Skip 2
        if ($null -ne $RegisteredOwner)
        {
            Write-Output "[Info]  RegisteredOwner: $RegisteredOwner"
        }
        else
        {
            Write-Output "[Info]  RegisteredOwner: --"
        }

        # Check if it is an Microsoft Exchange Server
        if (Get-ChildItem -Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | Select-Object FullName | Select-String -Pattern "Microsoft Exchange*" -Quiet)
        {
            $SubDirectory = (Get-ChildItem -Path "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | Select-Object FullName).FullName | Select-String -Pattern "Microsoft Exchange*" | ForEach-Object{($_ -split "\\")[-1]}
            $DisplayName = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$SubDirectory\DisplayName.txt" | Select-Object -Skip 2
            $DisplayVersion = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$SubDirectory\DisplayVersion.txt" | Select-Object -Skip 2
            $InstallLocation = Get-Content "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$SubDirectory\InstallLocation.txt" | Select-Object -Skip 2
            Write-Output "[Info]  $DisplayName ($DisplayVersion)"
            Write-Output "[Info]  Install Location: $InstallLocation"
        }

        # Timezone Information
        $TimeZoneKeyName = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\TimeZoneKeyName.txt" | Select-Object -Skip 2 | ForEach-Object{($_ -replace "\.\..*$","")}
        $LastWriteTime = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\(_Key_).txt" | Select-Object -Skip 3
        $ActiveTimeBias = Get-Content "$DriveLetter\registry\HKLM\SYSTEM\ControlSet00$CurrentControlSet\Control\TimeZoneInformation\ActiveTimeBias.txt" | Select-Object -Skip 2
        $UTC = '{0:d2}' -f -([int]"0x$ActiveTimeBias" / 60)

        if ($UTC -like "*-*" )
        {
            Write-Output "[Info]  Timezone Information: $TimeZoneKeyName (UTC$UTC`:00)"
            Write-Output "[Info]  Last Written Time: $LastWriteTime"
        }
        else
        {
            Write-Output "[Info]  Timezone Information: $TimeZoneKeyName (UTC+$UTC`:00)"
            Write-Output "[Info]  Last Written Time: $LastWriteTime"
        }

        # LastLoggedOnUser
        $RegistryValue = "$DriveLetter\registry\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\LastLoggedOnUser.txt"

        if (Test-Path "$RegistryValue")
        {
            $LastLoggedOnUser = (Get-Content "$RegistryValue" | Select-Object -Skip 2) -creplace '(?s)^.*\\', ''
            Write-Output "[Info]  Last Logged On User: $LastLoggedOnUser"
        }

        # Last Boot Up Time (ISO 8601)
        if (Test-Path "$DriveLetter\sys\time-boot.txt")
        {
            $LastBoot = Get-Content -Path "$DriveLetter\sys\time-boot.txt"
            Write-Output "[Info]  Last Boot: $LastBoot"
        }

        # Memory Acquisition Time (ISO 8601)
        if (Test-Path "$DriveLetter\sys\time-current.txt")
        {
            $Current = Get-Content -Path "$DriveLetter\sys\time-current.txt"
            Write-Output "[Info]  Memory Acquisition Time: $Current"
        }

        # Collecting Evidence Files
        Write-Output "[Info]  Collecting Evidence Files ..."

        # FS_FindEvil
        # https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil
        #
        # Indicators of Evil
        # PE_INJECT     PE_INJECT locates malware by scanning for valid .DLLs and .EXEs with executable pages in their page tables located in a private (non-image) virtual address descriptor.
        # PEB_MASQ      PEB_MASQ will flag PEB Masquerading attempts. If PEB_MASQ is detected please investigate further in /sys/proc/proc-v.txt
        # PEB_BAD_LDR   BAD_PEB_LDR will flag if no in-process modules are enumerated from the PEB/LDR_DATA structures.
        # PE_NOLINK     PE_NOLINK locates malware in image virtual address descriptors which is not linked from the in-process PEB/Ldr lists.
        # PE_PATCHED    PE_PATCHED locates malware in image virtual address descriptors which executable pages (in the page tables) differs from kernel prototype memory.
        # PRIVATE_RWX   PRIVATE_RWX locates malware with read/write/execute (RWX) pages in the page table which belongs to a private memory virtual address descriptor.
        # NOIMAGE_RWX   NOIMAGE_RWX locates malware with read/write/execute (RWX) pages in the page table which does not belong to image (module) virtual address descriptors.
        # PRIVATE_RX    PRIVATE_RX locates malware with read/execute (RX) pages in the page table which belongs to a private memory virtual address descriptor.
        # NOIMAGE_RX    NOIMAGE_RX locates malware with read/execute (RX) pages in the page table which does not belong to image (module) virtual address descriptors.

        # FS_FindEvil
        if (Test-Path "$DriveLetter\forensic\findevil\findevil.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\findevil" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\forensic\findevil\findevil.txt" -Destination "$OUTPUT_FOLDER\forensic\findevil\findevil.txt"

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "evil" }

                $Data | Foreach-Object {

                $proc = $_ | Select-Object -ExpandProperty proc
                $procid = $_ | Select-Object -ExpandProperty pid

                $addr = $_ | Select-Object -ExpandProperty addr -ErrorAction SilentlyContinue
                if ($addr)
                {
                    $Address = $addr.PadLeft(16,"0")
                }
                else
                {
                    $Address = "0000000000000000"
                }

                $desc = $_ | Select-Object -ExpandProperty desc
                $desc2 = $_ | Select-Object -ExpandProperty desc2

                New-Object -TypeName PSObject -Property @{
                    "Process Name" = $proc
	                "PID" = $procid
	                "Address" = $Address
	                "Type" = $desc
                    "Description" = $desc2
                    }
                } | Select-Object "Process Name","PID","Type","Address","Description" | Export-Csv -Path "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\forensic\findevil\findevil.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\forensic\findevil\findevil.csv").Length -gt 0kb)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\findevil\findevil.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FindEvil" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-D
                        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        # Find Evil
        if (Test-Path "$OUTPUT_FOLDER\forensic\findevil\findevil.csv")
        {
            # PE_INJECT (Injected Modules)
            $Data = Import-Csv "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t" | Where-Object { $_.Type -like "*PE_INJECT*" }
            $Count = ($Data | Measure-Object).Count
            if ($Count -gt 0)
            {
                New-Item "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT" -ItemType Directory -Force | Out-Null
                ($Data | Select-Object PID,"Process Name",Type,Address,Description | Format-Table -HideTableHeaders | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt"
                Write-Host "[Alert] PE_INJECT found ($Count)" -ForegroundColor Red
                (Get-Content "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt") -replace "^", "        "  | Write-Host -ForegroundColor Red
            }

            # Collecting PE_INJECT (Injected Modules)
            if (Test-Path "$7za")
            {
                if (Test-Path "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt")
                {
                    $PE_INJECTS = Get-Content "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\PE_INJECT.txt"
                    ForEach( $PE_INJECT in $PE_INJECTS )
                    {
                        $ProcessID = $PE_INJECT | ForEach-Object{($_ -split "\s+")[0]}
                        $InjectedModuleList = (Get-ChildItem -Recurse -Force "$DriveLetter\pid\$ProcessID\files\modules\*" | Where-Object {($_.FullName -match "_INJECTED*")} | Foreach-Object FullName)

                        ForEach( $InjectedModule in $InjectedModuleList )
                        {
                            $INFECTED = "infected"
                            $ArchiveName = $InjectedModule | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "_INJECTED-")[-1]}
                            & $7za a -mx5 -mhe "-p$INFECTED" -t7z "$OUTPUT_FOLDER\forensic\findevil\PE_INJECT\$ProcessID-$ArchiveName.7z" "$InjectedModule" > $null 2>&1
                        }
                    }
                }
            }

            # PEB_MASQ (PEB Masquerading)
            $Data = Import-Csv "$OUTPUT_FOLDER\forensic\findevil\findevil.csv" -Delimiter "`t" | Where-Object { $_.Type -like "*PEB_MASQ*" }
            $Count = ($Data | Measure-Object).Count
            if ($Count -gt 0)
            {
                New-Item "$OUTPUT_FOLDER\forensic\findevil\PEB_MASQ" -ItemType Directory -Force | Out-Null
                ($Data | Select-Object PID,"Process Name",Type,Address,Description | Format-Table -HideTableHeaders | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\forensic\findevil\PEB_MASQ\PEB_MASQ.txt"
                Write-Host "[Alert] PEB_MASQ found ($Count)" -ForegroundColor Red
                (Get-Content "$OUTPUT_FOLDER\forensic\findevil\PEB_MASQ\PEB_MASQ.txt") -replace "^", "        "  | Write-Host -ForegroundColor Red
            }
        }
        else
        {
            Write-Output "[Info]  Your Operating System is NOT supported by FindEvil."
            Write-Output "        Note: FindEvil is only available for Windows 10 (x64) and Windows 8.1 (x64)"
        }

        # FS_Forensic_CSV
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_CSV
        if (Test-Path "$DriveLetter\forensic\csv\*.csv")
        {
            New-Item "$OUTPUT_FOLDER\forensic\csv" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\forensic\csv\*.csv" -Destination "$OUTPUT_FOLDER\forensic\csv"
        }

        # FS_Forensic_XLSX
        if (Test-Path "$OUTPUT_FOLDER\forensic\csv\*.csv")
        {
            New-Item "$OUTPUT_FOLDER\forensic\xlsx" -ItemType Directory -Force | Out-Null

            # drivers.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\drivers.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\drivers.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\drivers.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\drivers.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Drivers" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-E
                    $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # handles.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\handles.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\handles.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\handles.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\handles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Handles" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-H
                    $WorkSheet.Cells["A:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # modules.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\modules.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\modules.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\modules.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\modules.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Modules" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:N1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-I and M-N
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:I"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["M:N"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # process.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\process.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\process.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\process.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\process.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Processes" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-C and F-O
                    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:O"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # services.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\services.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\services.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\services.csv" -Delimiter "," | Sort-Object PID
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\services.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Services" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-B and E-J
                    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["E:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # tasks.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\tasks.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\tasks.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\tasks.csv" -Delimiter "," | Sort-Object { $_.TimeCreate -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\tasks.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Tasks" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, D-E and H-K
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["H:K"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # threads.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\threads.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\threads.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\threads.csv" -Delimiter "," | Sort-Object PID # or CreateTime???
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\threads.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Threads" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:T1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-T
                    $WorkSheet.Cells["A:T"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_all.csv --> \forensic\timeline\timeline-reverse.csv

            # timeline_kernelobject.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_kernelobject.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_kernelobject.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_kernelobject.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_kernelobject.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_kernelobject" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_net.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_net.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_net.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_net.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_net.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_net" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_ntfs.csv --> \forensic\timeline\timeline-reverse.csv

            # timeline_process.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_process.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_process.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_process.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_process.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_process" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_registry.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_registry.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_registry.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_registry.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_registry.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_registry" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_task.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_task.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_task.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_task.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_task.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_task" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_thread.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_thread.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_thread.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_thread.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_thread.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_thread" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # timeline_web
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\timeline_web.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\timeline_web.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\timeline_web.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\timeline_web.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "timeline_web" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-F
                    $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # unloaded_modules.csv
            if (Test-Path "$OUTPUT_FOLDER\forensic\csv\unloaded_modules.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\forensic\csv\unloaded_modules.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\csv\unloaded_modules.csv" -Delimiter "," | Sort-Object { $_.Time -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\xlsx\unloaded_modules.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "unloaded_modules" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and 
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # FS_Forensic_JSON
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_JSON
        if (Test-Path "$DriveLetter\forensic\json\*.json")
        {
            New-Item "$OUTPUT_FOLDER\forensic\json" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\forensic\json\*.json" -Destination "$OUTPUT_FOLDER\forensic\json"
        }

        # FS_Forensic_Ntfs
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Ntfs
        if (Test-Path "$DriveLetter\forensic\ntfs\ntfs_files.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\ntfs" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\forensic\ntfs\ntfs_files.txt" -Destination "$OUTPUT_FOLDER\forensic\ntfs\ntfs_files.txt"
        }

        # FS_Forensic_Timeline
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Timeline
        if (Test-Path "$DriveLetter\forensic\timeline\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\forensic\timeline" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\forensic\timeline\*.txt" -Destination "$OUTPUT_FOLDER\forensic\timeline"
        }

        # FS_SysInfo
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo
        if (Test-Path "$DriveLetter\sys\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\sys\*.txt" -Destination "$OUTPUT_FOLDER\sys"
        }

        # FS_SysInfo_Users
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Users
        if (Test-Path "$DriveLetter\sys\users\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\users" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\sys\users\*.txt" -Destination "$OUTPUT_FOLDER\sys\users"
        }

        # FS_SysInfo_Certificates
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Certificates
        if (Test-Path "$DriveLetter\sys\certificates\certificates.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\certificates" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\sys\certificates\certificates.txt" -Destination "$OUTPUT_FOLDER\sys\certificates\certificates.txt"

            # SHA1
            Get-Content "$OUTPUT_FOLDER\sys\certificates\certificates.txt" | Select-String -Pattern "[A-Za-z0-9]{32}" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\sys\certificates\SHA1.txt"

            # Count
            $Total = (Get-Content "$OUTPUT_FOLDER\sys\certificates\certificates.txt" | Measure-Object).Count
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\certificates\SHA1.txt" | Measure-Object).Count
            Write-Output "[Info]  $Count Certificates found ($Total)"

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "certificate" }

                $Data | Foreach-Object {

                $desc = $_ | Select-Object -ExpandProperty desc
                $store = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="store"; Expression={ForEach-Object{($_ -split "store:")[1]} | ForEach-Object{($_ -split "thumbprint:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $thumbprint = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="thumbprint"; Expression={ForEach-Object{($_ -split "thumbprint:")[1]} | ForEach-Object{($_ -split "issuer:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $issuer  = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="issuer"; Expression={ForEach-Object{($_ -split "issuer:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                New-Object -TypeName PSObject -Property @{
	                "Description" = $desc
	                "Store" = $store.store
	                "Thumbprint (SHA1)" = $thumbprint.thumbprint
	                "Issuer" = $issuer.issuer
                    }
                } | Select-Object "Description","Store","Thumbprint (SHA1)","Issuer" | Export-Csv -Path "$OUTPUT_FOLDER\sys\certificates\certificates.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\certificates\certificates.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\certificates\certificates.csv").Length -gt 0kb)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\certificates\certificates.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\certificates\certificates.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Certificates" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-C
                        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }

        # FS_Sys_Drivers
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Sys_Drivers
        if (Test-Path "$DriveLetter\sys\drivers\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\drivers" -ItemType Directory -Force | Out-Null
            Copy-Item "$DriveLetter\sys\drivers\*.txt" -Destination "$OUTPUT_FOLDER\sys\drivers"
        }

        # CSV
        if (Test-Path "$DriveLetter\forensic\json\general.json")
        {
            $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "driver" }

            $Data | Foreach-Object {

            $obj = $_ | Select-Object -ExpandProperty obj
            $desc = $_ | Select-Object -ExpandProperty desc
            $size = $_ | Select-Object -ExpandProperty size -ErrorAction SilentlyContinue
            $addr = $_ | Select-Object -ExpandProperty addr -ErrorAction SilentlyContinue
            $addr2 = $_ | Select-Object -ExpandProperty addr2 -ErrorAction SilentlyContinue
            $svc = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="svc"; Expression={ForEach-Object{($_ -split "svc:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
            $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

            New-Object -TypeName PSObject -Property @{
                "Object Address" = $obj
                "Driver" = $desc
                "Size" = $size
                "Start" = $addr
                "End" = $addr2
                "Service Key" = $svc.svc
                "Driver Name" = $path.path
                }
            } | Select-Object "Object Address","Driver","Size","Start","End","Service Key","Driver Name" | Export-Csv -Path "$OUTPUT_FOLDER\sys\drivers\drivers.csv" -Delimiter "`t" -NoTypeInformation
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\sys\drivers\drivers.csv")
            {
                if ((Get-Item "$OUTPUT_FOLDER\sys\drivers\drivers.csv").Length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\drivers\drivers.csv" -Delimiter "`t"
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\drivers\drivers.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Drivers" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, D-E
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    # HorizontalAlignment "Center" of column C
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Right"
                    # HorizontalAlignment "Center" of header of column C
                    $WorkSheet.Cells["C1:C1"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # FS_SysInfo_Network
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Network
        if (Test-Path "$DriveLetter\sys\net\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\net" -ItemType Directory -Force | Out-Null

            # netstat.txt
            if (Test-Path "$DriveLetter\sys\net\netstat.txt")
            { 
                Copy-Item "$DriveLetter\sys\net\netstat.txt" -Destination "$OUTPUT_FOLDER\sys\net\netstat.txt"

                # IPv4
                # https://ipinfo.io/bogon
                New-Item "$OUTPUT_FOLDER\sys\net\IPv4" -ItemType Directory -Force | Out-Null
                $IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                $Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
                $Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPv4-All.txt"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt"

                # Count
                $Total = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4-All.txt" | Measure-Object).Count
                $Count = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt" | Measure-Object).Count
                Write-Output "[Info]  $Count IPv4 addresses found ($Total)"

                # CSV
                if (Test-Path "$DriveLetter\forensic\json\general.json")
                {
                    New-Item "$OUTPUT_FOLDER\sys\net\CSV" -ItemType Directory -Force | Out-Null
                    
                    $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "net" }

                    $Data | Foreach-Object {

                    $proc = $_ | Select-Object -ExpandProperty proc -ErrorAction SilentlyContinue
                    $procid = $_ | Select-Object -ExpandProperty pid -ErrorAction SilentlyContinue
                    $obj = $_ | Select-Object -ExpandProperty obj
                    $desc = $_ | Select-Object -ExpandProperty desc
                    $proc2 = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="proc"; Expression={ForEach-Object{($_ -split "proc:")[1]} | ForEach-Object{($_ -split "time:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    $time = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="time"; Expression={ForEach-Object{($_ -split "time:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    
                    New-Object -TypeName PSObject -Property @{
                        "Process" = $proc
                        "PID" = $procid
                        "Protocol" = $desc | ForEach-Object{($_ -split "\s+")[0]}
                        "State" = $desc | ForEach-Object{($_ -split "\s+")[1]}
                        "Source" = $desc | ForEach-Object{($_ -split "\s+")[2]}
                        "Destination" = $desc | ForEach-Object{($_ -split "\s+")[3]}
                        "Time" = $time.time
                        "Object Address" = $obj
                        "Process Path" = $path.path
                        }
                    } | Select-Object "Process","PID","Protocol","State","Source","Destination","Time","Object Address","Process Path" | Export-Csv -Path "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" -NoTypeInformation
                }

                # Custom CSV
                if (Test-Path "$DriveLetter\forensic\json\general.json")
                {
                    New-Item "$OUTPUT_FOLDER\sys\net\CSV" -ItemType Directory -Force | Out-Null
                    
                    $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "net" }

                    $Data | Foreach-Object {

                    $proc = $_ | Select-Object -ExpandProperty proc -ErrorAction SilentlyContinue
                    $procid = $_ | Select-Object -ExpandProperty pid -ErrorAction SilentlyContinue
                    $obj = $_ | Select-Object -ExpandProperty obj
                    $desc = $_ | Select-Object -ExpandProperty desc
                    $proc2 = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="proc"; Expression={ForEach-Object{($_ -split "proc:")[1]} | ForEach-Object{($_ -split "time:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    $time = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="time"; Expression={ForEach-Object{($_ -split "time:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                    
                    New-Object -TypeName PSObject -Property @{
                        "Process" = $proc
                        "PID" = $procid
                        "Protocol" = $desc | ForEach-Object{($_ -split "\s+")[0]}
                        "State" = $desc | ForEach-Object{($_ -split "\s+")[1]}
                        "Source" = ($desc | ForEach-Object{($_ -split "\s+")[2]} | Select-Object @{Name="Source"; Expression={ ForEach-Object{($_ -replace ":\d+$","")}}}).Source
                        "SrcPort" = ($desc | ForEach-Object{($_ -split "\s+")[2]} | Select-Object @{Name="SrcPort"; Expression={ ForEach-Object{($_ -split ":")[-1]} | ForEach-Object{($_ -replace "\*\*\*","")}}}).SrcPort
                        "Destination" = ($desc | ForEach-Object{($_ -split "\s+")[3]} | Select-Object @{Name="Destination"; Expression={ ForEach-Object{($_ -replace ":\d+$","")}}}).Destination
                        "DstPort" = ($desc | ForEach-Object{($_ -split "\s+")[3]} | Select-Object @{Name="DstPort"; Expression={ ForEach-Object{($_ -split ":")[-1]} | ForEach-Object{($_ -replace "\*\*\*","")}}}).DstPort
                        "Time" = $time.time
                        "Object Address" = $obj
                        "Process Path" = $path.path
                        }
                    } | Select-Object "Process","PID","Protocol","State","Source","SrcPort","Destination","DstPort","Time","Object Address","Process Path" | Export-Csv -Path "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv" -Delimiter "`t" -NoTypeInformation
                }

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\sys\net\CSV\net.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\sys\net\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t"
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\XLSX\net.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Network" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-H
                            $WorkSheet.Cells["B:H"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }

                # Custom XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\sys\net\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net-custom.csv" -Delimiter "`t"
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\XLSX\net-custom.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Network" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-J
                            $WorkSheet.Cells["B:J"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }

                # IPinfo CLI (50000 requests per month)
                if (Test-Path "$IPinfo")
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt").Length -gt 0kb)
                        {
                            # Internet Connectivity Check (Vista+)
                            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

                            if (!($NetworkListManager -eq "True"))
                            {
                                Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                            }
                            else
                            {
                                # Check if IPinfo.io is reachable
                                if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
                                {
                                    Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                                }
                                else
                                {
                                    New-Item "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\TXT" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\JSON" -ItemType Directory -Force | Out-Null

                                    $List = Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt"

                                    ForEach ($IPv4 in $List)
                                    {
                                        # TXT
                                        & $IPinfo "$IPv4" | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\TXT\$IPv4.txt"

                                        # JSON
                                        & $IPinfo "$IPv4" --json | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\JSON\$IPv4.json"
                                    }

                                    # Map IPs
                                    # https://ipinfo.io/map
                                    Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt" | & $IPinfo map | Out-Null

                                    # Access Token
                                    # https://ipinfo.io/signup?ref=cli
                                    $Token = "access_token" # Please insert your Access Token here

                                    if (!("$Token" -eq "access_token"))
                                    {
                                        # Summarize IPs
                                        # https://ipinfo.io/summarize-ips
                                        Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt" | & $IPinfo summarize -t $Token | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\Summary.txt"

                                        # JSON
                                        Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt" | & $IPinfo --json -t $Token | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\IPinfo.json"

                                        # CSV
                                        Get-Content "$OUTPUT_FOLDER\sys\net\IPv4\IPv4.txt" | & $IPinfo --csv -t $Token | Out-File "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\IPinfo.csv"

                                        # XLSX
                                        if (Get-Module -ListAvailable -Name ImportExcel)
                                        {
                                            if (Test-Path "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\IPinfo.csv")
                                            {
                                                if ((Get-Item "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\IPinfo.csv").Length -gt 0kb)
                                                {
                                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\IPinfo.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\IPv4\IPinfo\IPinfo.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPinfo" -CellStyleSB {
                                                    param($WorkSheet)
                                                    # BackgroundColor and FontColor for specific cells of TopRow
                                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                    Set-Format -Address $WorkSheet.Cells["A1:AI1"] -BackgroundColor $BackgroundColor -FontColor White
                                                    # HorizontalAlignment "Center" of columns A-I and K-AI
                                                    $WorkSheet.Cells["A:I"].Style.HorizontalAlignment="Center"
                                                    $WorkSheet.Cells["K:AI"].Style.HorizontalAlignment="Center"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Write-Output "[Info]  ipinfo.exe NOT found."
                }

                # IPv6
                # IPv6 Bogon Ranges --> https://ipinfo.io/bogon
                New-Item "$OUTPUT_FOLDER\sys\net\IPv6" -ItemType Directory -Force | Out-Null
                $IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
                $Bogon = "^(::1|::ffff:0:0|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPv6-All.txt"
                Get-Content "$OUTPUT_FOLDER\sys\net\netstat.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt"

                # Count
                $Total = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6-All.txt" | Measure-Object).Count
                $Count = (Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt" | Measure-Object).Count
                Write-Output "[Info]  $Count IPv6 addresses found ($Total)"

                # IPinfo CLI (50000 requests per month)
                if (Test-Path "$IPinfo")
                {
                    if (Test-Path "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt").Length -gt 0kb)
                        {
                            # Internet Connectivity Check (Vista+)
                            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

                            if (!($NetworkListManager -eq "True"))
                            {
                                Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                            }
                            else
                            {
                                # Check if IPinfo.io is reachable
                                if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
                                {
                                    Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                                }
                                else
                                {
                                    New-Item "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\TXT" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\JSON" -ItemType Directory -Force | Out-Null

                                    $List = Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt"

                                    $Index = 0

                                    ForEach ($IPv6 in $List)
                                    {
                                        # TXT
                                        & $IPinfo "$IPv6" | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\TXT\$Index.txt"

                                        # JSON
                                        & $IPinfo "$IPv6" --json | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\JSON\$Index.json"

                                        $Index++
                                    }

                                    # Map IPs
                                    # https://ipinfo.io/map
                                    Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt" | & $IPinfo map | Out-Null

                                    if (!("$Token" -eq "access_token"))
                                    {
                                        # Summarize IPs
                                        # https://ipinfo.io/summarize-ips
                                        Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt" | & $IPinfo summarize -t $Token | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\Summary.txt"

                                        # JSON
                                        Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt" | & $IPinfo --json -t $Token | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\IPinfo.json"

                                        # CSV
                                        Get-Content "$OUTPUT_FOLDER\sys\net\IPv6\IPv6.txt" | & $IPinfo --csv -t $Token | Out-File "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\IPinfo.csv"

                                        # XLSX
                                        if (Get-Module -ListAvailable -Name ImportExcel)
                                        {
                                            if (Test-Path "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\IPinfo.csv")
                                            {
                                                if ((Get-Item "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\IPinfo.csv").Length -gt 0kb)
                                                {
                                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\IPinfo.csv" -Delimiter "," | Sort-Object ip
                                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\net\IPv6\IPinfo\IPinfo.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPinfo" -CellStyleSB {
                                                    param($WorkSheet)
                                                    # BackgroundColor and FontColor for specific cells of TopRow
                                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                    Set-Format -Address $WorkSheet.Cells["A1:AI1"] -BackgroundColor $BackgroundColor -FontColor White
                                                    # HorizontalAlignment "Center" of columns A-I and K-AI
                                                    $WorkSheet.Cells["A:I"].Style.HorizontalAlignment="Center"
                                                    $WorkSheet.Cells["K:AI"].Style.HorizontalAlignment="Center"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Write-Output "[Info]  ipinfo.exe NOT found."
                }
            }

            # netstat-v.txt
            if (Test-Path "$DriveLetter\sys\net\netstat-v.txt")
            {
                Copy-Item "$DriveLetter\sys\net\netstat-v.txt" -Destination "$OUTPUT_FOLDER\sys\net\netstat-v.txt"
            }

            # State
            if ((Test-Path "$OUTPUT_FOLDER\sys\net\CSV\net.csv") -And ((Get-Item "$OUTPUT_FOLDER\sys\net\CSV\net.csv").length -gt 0kb))
            {
                $CLOSED      = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "CLOSED" }).Count
                $CLOSING     = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "CLOSING" }).Count
                $CLOSE_WAIT  = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "CLOSE_WAIT" }).Count
                $ESTABLISHED = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "ESTABLISHED" }).Count
                $FIN_WAIT_1  = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "FIN_WAIT_1" }).Count
                $FIN_WAIT_2  = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "FIN_WAIT_2" }).Count
                $LAST_ACK    = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "LAST_ACK" }).Count
                $LISTENING   = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "LISTENING" }).Count
                $SYN_RCVD    = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "SYN_RCVD" }).Count
                $SYN_SENT    = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "SYN_SENT" }).Count
                $TIME_WAIT   = (Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.State -eq "TIME_WAIT" }).Count

                Write-Output "CLOSED      : $CLOSED" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "CLOSING     : $CLOSING" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "CLOSE_WAIT  : $CLOSE_WAIT" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "ESTABLISHED : $ESTABLISHED" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "FIN_WAIT_1  : $FIN_WAIT_1" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "FIN_WAIT_2  : $FIN_WAIT_2" | Out-File "$OUTPUT_FOLDER\sys\net\Stats.txt" -Append
                Write-Output "LAST_ACK    : $LAST_ACK" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "LISTENING   : $LISTENING" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "SYN_RCVD    : $SYN_RCVD" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "SYN_SENT    : $SYN_SENT" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
                Write-Output "TIME_WAIT   : $TIME_WAIT" | Out-File "$OUTPUT_FOLDER\sys\net\State.txt" -Append
            }

            # Stats
            if ((Test-Path "$OUTPUT_FOLDER\sys\net\State.txt") -And ((Get-Item "$OUTPUT_FOLDER\sys\net\State.txt").length -gt 0kb))
            {
                $Stats = Get-Content "$OUTPUT_FOLDER\sys\net\State.txt" | ForEach-Object{($_ -replace ":","")} | ConvertFrom-String -PropertyNames State, Count | Sort-Object Count -Descending
                ($Stats | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\net\Stats.txt"
            }

            # CLOSED        Closed. The socket is not being used.
            # CLOSING       Closed, then remote shutdown; awaiting acknowledgment.
            # CLOSE_WAIT    Remote shutdown; waiting for the socket to close.
            # ESTABLISHED   Connection has been established.
            # FIN_WAIT_1    Socket closed; shutting down connection.
            # FIN_WAIT_2    Socket closed; waiting for shutdown from remote.
            # LAST_ACK      Remote shutdown, then closed; awaiting acknowledgment.
            # LISTENING     Listening for incoming connections.
            # SYN_RCVD      Active/initiate synchronization received and the connection under way.
            # SYN_SENT      Actively trying to establish connection.
            # TIME_WAIT     Wait after close for remote shutdown retransmission.
                
            # Suspicious Port Numbers

            # Source

            # TCP on Source Port 3262 --> This rule detects events that may indicate use of encrypted traffic on TCP port 3262 (F-Response)
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Source -like "*:3262" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Output "[Info]  TCP on Source Port 3262 detected - May indicates use of encrypted traffic by F-Response ($Count)"
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Source-Port-3262.txt"
            }

            # TCP on Source Port 3389 --> This rule detects events that may indicate incoming Remote Desktop Protocol (RDP) activity on TCP port 3389 - Incoming
            # Note: proc.xlsx --> CommandLine: C:\Windows\System32\svchost.exe -k termsvc
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Source -match ":3389$" } | Where-Object { $_.Process -eq "svchost.exe" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Source Port 3389 detected - May indicates incoming Remote Desktop Protocol (RDP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Source-Port-3389.txt"
            }

            # TCP on Source Port 4444 --> This rule detects events that may indicate a Meterpreter session (Reverse Shell)
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.State -eq "LISTENING" } | Where-Object { $_.Source -match ":4444$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Source Port 4444 detected - May indicates use of Meterpreter Reverse Shell ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Source-Port-4444.txt"
            }

            # Destination

            # TCP on Destination Port 20 --> This rule detects events that may indicate outgoing File Transfer Protocol (FTP) activity over port 20
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":20$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 20 detected - May indicates  File Transfer Protocol (FTP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-20.txt"
            }

            # TCP on Destination Port 21 --> This rule detects events that may indicate outgoing File Transfer Protocol (FTP) activity over port 21
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":21$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 21 detected - May indicates outgoing File Transfer Protocol (FTP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-21.txt"
            }

            # TCP on Destination Port 3389 --> This rule detects events that may indicate outgoing Remote Desktop Protocol (RDP) activity on TCP port 3389 - Outgoing
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":3389$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 3389 detected - May indicates outgoing Remote Desktop Protocol (RDP) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-3389.txt"
            }

            # TCP on Destination Port 8080 --> This rule detects events that may indicate Command-and-Control (C2) activity over port 8080
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":8080$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 8080 detected - May indicates Command-and-Control (C2) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-8080.txt"
            }

            # TCP on Destination Port 8081 --> This rule detects events that may indicate Command-and-Control (C2) activity over port 8081
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":8081$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 8081 detected - May indicates Command-and-Control (C2) activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-8081.txt"
            }

            # TCP on Destination Port 9001 --> This rule detects events that may indicate use of Tor client on TCP port 9001
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":9001$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 9001 detected - May indicates Tor activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-9001.txt"
            }

            # TCP on Destination Port 9030 --> This rule detects events that may indicate Tor activity on TCP port 9030
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -match ":9030$" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 9030 detected - May indicates Tor activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-9030.txt"
            }

            # TCP on Destination Port 9150 --> This rule detects events that may indicate use of Tor client on TCP port 9150
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\net\CSV\net.csv" -Delimiter "`t" | Where-Object { $_.Protocol -like "TCP*" } | Where-Object { $_.Destination -eq "127.0.0.1:9150" } | Sort-Object { $_.Time -as [datetime] }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

            if ($Count -gt 0)
            {
                Write-Host "[Alert] TCP on Destination Port 9150 detected - May indicates Tor activity ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\net\Detections" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\net\Detections\TCP-on-Destination-Port-9150.txt"
            }
        }

        # FS_SysInfo_Process
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Process
        if (Test-Path "$DriveLetter\sys\proc\*.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\proc" -ItemType Directory -Force | Out-Null
            Add-Content -Path "$OUTPUT_FOLDER\sys\proc\proc.txt" -Encoding utf8 -Value (Get-Content -Path "$DriveLetter\sys\proc\proc.txt")
            Add-Content -Path "$OUTPUT_FOLDER\sys\proc\proc-v.txt" -Encoding utf8 -Value (Get-Content -Path "$DriveLetter\sys\proc\proc-v.txt")

            # Count Processes
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Measure-Object).Count -2
            Write-Output "[Info]  Processing $Count Processes ..."

            # Flags
            # 32 - Process is 32-bit on 64-bit Windows.
            # E  - Process is NOT found in EPROCESS list (memory corruption, drift or unlink)
            # T  - Process is terminated
            # U  - Process is user-account (non-system user)
            # *  - Process is outside standard paths.

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                New-Item "$OUTPUT_FOLDER\sys\proc\CSV" -ItemType Directory -Force | Out-Null

                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "process" }

                $Data | Foreach-Object {

                $proc = $_ | Select-Object -ExpandProperty proc

                # Replace empty "Process Name" fields
                if ($proc -eq "")
                {
                    $proc = "<unknown>"        
                }

                $procid = $_ | Select-Object -ExpandProperty pid
                $obj = $_ | Select-Object -ExpandProperty obj
                $parentid = $_ | Select-Object -ExpandProperty num -ErrorAction SilentlyContinue
                $hex = $_ | Select-Object -ExpandProperty hex
                $hex2 = $_ | Select-Object -ExpandProperty hex2 -ErrorAction SilentlyContinue
                $desc = $_ | Select-Object -ExpandProperty desc
                $flags = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="flags"; Expression={ForEach-Object{($_ -split "flags:")[1]} | ForEach-Object{($_ -split "user:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $user = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="user"; Expression={ForEach-Object{($_ -split "user:")[1]} | ForEach-Object{($_ -split "upath:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $upath = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="upath"; Expression={ForEach-Object{($_ -split "upath:")[1]} | ForEach-Object{($_ -split "cmd:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $cmd = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="cmd"; Expression={ForEach-Object{($_ -split "cmd:")[1]} | ForEach-Object{($_ -split "createtime:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $createtime = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="createtime"; Expression={ForEach-Object{($_ -split "createtime:")[1]} | ForEach-Object{($_ -split "integrity:")[0]} | ForEach-Object{($_ -split "exittime:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $exittime = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="exittime"; Expression={ForEach-Object{($_ -split "exittime:")[1]} | ForEach-Object{($_ -split "integrity:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $integrity = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="integrity"; Expression={ForEach-Object{($_ -split "integrity:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $Parents = $Data | Select-Object num -ErrorAction SilentlyContinue | Sort-Object
                $SubProcesses = ($Data | Where-Object { $_.num -eq $procid } | Measure-Object).Count

                New-Object -TypeName PSObject -Property @{
                    "Create Time" = $createtime.createtime
	                "Process Name" = $proc
	                "PID" = $procid
	                "obj " = $obj
	                "PPID" = $parentid
                    "hex" = $hex
                    "hex2" = $hex2
                    "Device Path" = $desc
                    "Flags" = $flags.flags
                    "User" = $user.user
                    "File Path" = $upath.upath
                    "CommandLine" = $cmd.cmd
                    "Integrity" = $integrity.integrity
                    "Exit Time" = $exittime.exittime
                    "Sub-Processes" = $SubProcesses
                    }
                } | Select-Object "Create Time","Process Name","PID","PPID","Sub-Processes","Device Path","Flags","User","File Path","CommandLine","Integrity","Exit Time" | Export-Csv -Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX

            # Default
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv").Length -gt 0kb)
                    {
                        New-Item "$OUTPUT_FOLDER\sys\proc\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\XLSX\Processes.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Processes" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-E, G-H and K-L
                        $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["G:H"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["K:L"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }

            # Process Tree (TreeView)
            if (Test-Path "$SCRIPT_DIR\Scripts\Get-ProcessTree\Get-ProcessTree.ps1")
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv").Length -gt 0kb)
                    {
                        Write-Output "[Info]  Launching Process Tree (TreeView) ... "
                        Start-Process -FilePath "powershell" -NoNewWindow -ArgumentList "-File $SCRIPT_DIR\Scripts\Get-ProcessTree\Get-ProcessTree.ps1 -CSVPath $OUTPUT_FOLDER\sys\proc\CSV\proc.csv"
                    }
                }
            }

            # Running and Exited Processes
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv").Length -gt 0kb)
                    {
                        New-Item "$OUTPUT_FOLDER\sys\proc\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Sort-Object { $_."Create Time" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\proc\XLSX\RunningAndExited.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Processes" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-E, G-H and K-L
                        $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["G:H"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["K:L"].Style.HorizontalAlignment="Center"

                        # Exited Processes
                        $ExitedColor = [System.Drawing.Color]::FromArgb(255,0,0) # Red
                        $LastRow = $WorkSheet.Dimension.End.Row
                        Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=NOT(OR($L1="", $L1="Exit Time"))' -BackgroundColor $ExitedColor

                        # Running Processes
                        $RunningColor = [System.Drawing.Color]::FromArgb(0,255,0) # Green
                        $LastRow = $WorkSheet.Dimension.End.Row
                        Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=($L1="")' -BackgroundColor $RunningColor
                        }
                    }
                }
            }

            # Unusual Parent-Child Relationships

            # 01. Unusual Parent-Child Relationship (csrss.exe)
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Pid_svchost = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "svchost.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "csrss.exe" | Where-Object{($_ -notmatch "$Pid_smss|$Pid_svchost")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: csrss.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "csrss.exe" | Where-Object{($_ -notmatch "$Pid_smss|$Pid_svchost")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\csrss.exe.txt"
            }

            # 02. Unusual Parent-Child Relationship (LogonUI.exe)
            $Pid_wininit = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "wininit.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_winlogon = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "winlogon.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "LogonUI.exe" | Where-Object{($_ -notmatch "$Pid_wininit|$Pid_winlogon")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: LogonUI.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "LogonUI.exe" | Where-Object{($_ -notmatch "$Pid_wininit|$Pid_winlogon")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\LogonUI.exe.txt"
            }

            # 03. Unusual Parent-Child Relationship (lsass.exe)
            $Pid_wininit = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "wininit.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "lsass.exe" | Where-Object{($_ -notmatch $Pid_wininit)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: lsass.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "lsass.exe" | Where-Object{($_ -notmatch "$Pid_wininit")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\lsass.exe.txt"
            }

            # 04. Unusual Parent-Child Relationship (services.exe)
            $Pid_wininit = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "wininit.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "services.exe" | Where-Object{($_ -notmatch $Pid_wininit)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: services.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "services.exe" | Where-Object{($_ -notmatch "$Pid_wininit")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\services.exe.txt"
            }

            # 05. Unusual Parent-Child Relationship (smss.exe)
            $Pid_System = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "System " -CaseSensitive | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "smss.exe" | Where-Object{($_ -notmatch "$Pid_System|$Pid_smss")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: smss.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "smss.exe" | Where-Object{($_ -notmatch "$Pid_System|$Pid_smss")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\smss.exe.txt"
            }

            # 06. Unusual Parent-Child Relationship (spoolsv.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "spoolsv.exe" | Where-Object{($_ -notmatch $Pid_services)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: spoolsv.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "spoolsv.exe" | Where-Object{($_ -notmatch "$Pid_services")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\spoolsv.exe.txt"
            }

            # 07. Unusual Parent-Child Relationship (svchost.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_MsMpEng = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "MsMpEng.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "svchost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_MsMpEng")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: svchost.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "svchost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_MsMpEng")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\svchost.exe.txt"
            }

            # 08. Unusual Parent-Child Relationship (taskhost.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_svchost = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "svchost.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "taskhost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: taskhost.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "taskhost.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\taskhost.exe.txt"
            }

            # 09. Unusual Parent-Child Relationship (taskhostw.exe)
            $Pid_services = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "services.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_svchost = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "svchost.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "taskhostw.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: taskhostw.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "taskhostw.exe" | Where-Object{($_ -notmatch "$Pid_services|$Pid_svchost")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\taskhostw.exe.txt"
            }

            # 10. Unusual Parent-Child Relationship (userinit.exe)
            $Pid_dwm = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "dwm.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Pid_winlogon = Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "winlogon.exe" | ForEach-Object{($_ -split "\s+")[2]}
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "userinit.exe" | Where-Object{($_ -notmatch "$Pid_dwm|$Pid_winlogon")} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: userinit.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "userinit.exe" | Where-Object{($_ -notmatch "$Pid_dwm|$Pid_winlogon")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\userinit.exe.txt"
            }

            # 11. Unusual Parent-Child Relationship (wininit.exe)
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "wininit.exe" | Where-Object{($_ -notmatch $Pid_smss)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: wininit.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "wininit.exe" | Where-Object{($_ -notmatch "$Pid_smss")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\wininit.exe.txt"
            }

            # 12. Unusual Parent-Child Relationship (winlogon.exe)
            $Pid_smss = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "smss.exe" | ForEach-Object{($_ -split "\s+")[2]}) -join "|"
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "winlogon.exe" | Where-Object{($_ -notmatch $Pid_smss)} | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Unusual Parent-Child Relationship found: winlogon.exe ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships" -ItemType Directory -Force | Out-Null
                Get-Content "$OUTPUT_FOLDER\sys\proc\proc.txt" | Select-String -Pattern "winlogon.exe" | Where-Object{($_ -notmatch "$Pid_smss")} | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Parent-Child_Relationships\winlogon.exe.txt"
            }

            # Unusual Number of Process Instances
            if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
            {
                if ((Get-Item "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv").Length -gt 0kb)
                {
                    $RunningProcs = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Exit Time" -eq "" }

                    # Unusual Number of Process Instances (lsaiso.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "lsaiso.exe" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: lsaiso.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "lsaiso.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\lsaiso.exe.txt"
                    }

                    # Unusual Number of Process Instances (lsass.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "lsass.exe" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: lsass.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "lsass.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\lsass.exe.txt"
                    }

                    # Unusual Number Process of Instances (lsm.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "lsm.exe" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: lsm.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "lsm.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\lsm.exe.txt"
                    }

                    # Unusual Number Process of Instances (Memory Compression)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "MemCompression" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: MemCompression ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "MemCompression" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\MemCompression.txt"
                    }

                    # Unusual Number Process of Instances (Registry)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "Registry" } | Measure-Object).Count
                    if ($Count -ne 0 -and $Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: Registry ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "Registry" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\Registry.txt"
                    }

                    # Unusual Number of Process Instances (services.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "services.exe" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: services.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "services.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\services.exe.txt"
                    }

                    # Unusual Number of Process Instances (System)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "System" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: System ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "System" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\System.txt"
                    }

                    # Unusual Number of Process Instances (wininit.exe)
                    $Count = ($RunningProcs | Where-Object { $_."Process Name" -eq "wininit.exe" } | Measure-Object).Count
                    if ($Count -ne 1)
                    {
                        Write-Host "[Alert] Unusual Number of Process Instances found: wininit.exe ($Count)" -ForegroundColor Red
                        New-Item "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances" -ItemType Directory -Force | Out-Null
                        $RunningProcs | Where-Object { $_."Process Name" -eq "wininit.exe" } | Out-File "$OUTPUT_FOLDER\sys\proc\Unusual_Number-of-Process-Instances\wininit.exe.txt"
                    }
                }
            }
        }

        # Process Masquerading
        # https://attack.mitre.org/techniques/T1036/
        # https://car.mitre.org/analytics/CAR-2021-04-001/
        if (Test-Path "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv")
        {
            if ((Get-Item "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv").Length -gt 0kb)
            {
                # Process Path Masquerading - Looks for mismatches between process names and their image paths
                # https://attack.mitre.org/techniques/T1036/005/
                Write-Output "[Info]  Checking for Process Path Masquerading ..."

                # Masquerading Client/Server Runtime Subsystem (csrss.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "csrss.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\csrss\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Client/Server Runtime Subsystem (csrss.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\csrss.exe.txt"
                }

                # Masquerading Windows Explorer (explorer.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "explorer.exe" -and $_."Device Path" -notmatch "\\Windows\\explorer\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Explorer (explorer.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\explorer.exe.txt"
                }

                # Masquerading Local Security Authority Server Service (lsass.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "lsass.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\lsass\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Local Security Authority Server Service (lsass.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\lsass.exe.txt"
                }

                # Masquerading Local Session Manager Service (lsm.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "lsm.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\lsm\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Local Session Manager Service (lsm.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\lsm.exe.txt"
                }

                # Masquerading Windows Services Control Manager (services.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "services.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\services\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Services Control Manager (services.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\services.exe.txt"
                }

                # Masquerading Windows Session Manager Subsystem (smss.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "smss.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\smss\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Session Manager Subsystem (smss.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\smss.exe.txt"
                }

                # Masquerading Windows Service Host (svchost.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "svchost.exe" -and ($_."Device Path" -notmatch "\\Windows\\System32\\svchost\.exe" -and $_."Device Path" -notmatch "\\Windows\\SysWOW64\\svchost\.exe") }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Service Host (svchost.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\svchost.exe.txt"
                }

                # Masquerading Host Process for Windows Tasks (taskhost.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "taskhost.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\taskhost\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Host Process for Windows Tasks (taskhost.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\taskhost.exe.txt"
                }

                # Masquerading Host Process for Windows Tasks (taskhostw.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "taskhostw.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\taskhostw\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Host Process for Windows Tasks (taskhostw.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\taskhostw.exe.txt"
                }

                # Masquerading Windows Start-Up Application (wininit.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "wininit.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\wininit\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Start-Up Application (wininit.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\wininit.exe.txt"
                }

                # Masquerading Windows Logon (winlogon.exe)
                $Import = Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -eq "winlogon.exe" -and $_."Device Path" -notmatch "\\Windows\\System32\\winlogon\.exe" }
                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                if ($Count -gt 0)
                {
                    Write-Host "[Alert] Process Masquerading as Windows Logon (winlogon.exe) detected (Count: $Count)" -ForegroundColor Red
                    New-Item "$OUTPUT_FOLDER\sys\proc\Process-Masquerading" -ItemType Directory -Force | Out-Null
                    $Import | Out-File "$OUTPUT_FOLDER\sys\proc\Process-Masquerading\winlogon.exe.txt"
                }

                # Process Name Masquerading - Measures the edit distance between used Process Name and Original Windows Process Name (Damerau–Levenshtein Distance)
                # https://en.wikipedia.org/wiki/Damerau-Levenshtein_distance
                Write-Output "[Info]  Checking Damerau–Levenshtein Distance of common System Processes ..."
                $ProcessList = (Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."Process Name" -ne "" } | Select-Object PID | Sort-Object @{Expression={$_.PID -as [int]}}).PID

                ForEach( $ProcessID in $ProcessList )
                {
                    $ProcessName = (Import-Csv "$OUTPUT_FOLDER\sys\proc\CSV\proc.csv" -Delimiter "`t" | Where-Object { $_."PID" -eq "$ProcessID" } | Select-Object "Process Name")."Process Name"

                    # Masquerading Client/Server Runtime Subsystem (csrss.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "csrss.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: csrss.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading COM Surrogate (dllhost.exe) --> Microsoft Component Object Model (COM)
                    $Distance = Measure-DamerauLevenshteinDistance "dllhost.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: dllhost.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading Windows Explorer (explorer.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "explorer.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: explorer.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading Internet Explorer (iexplore.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "iexplore.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: iexplore.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading Local Security Authority Server Service (lsass.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "lsass.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: lsass.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading Shell Infrastructure Host (sihost.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "sihost.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: sihost.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading Windows Session Manager Subsystem (smss.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "smss.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: smss.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading Windows Service Host (svchost.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "svchost.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: svchost.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }

                    # Masquerading Windows Logon (winlogon.exe)
                    $Distance = Measure-DamerauLevenshteinDistance "winlogon.exe" "$ProcessName"

                    if ($Distance -eq "1")
                    {
                        Write-Host "[Alert] Process Name Masquerading detected: winlogon.exe (Process Name: $ProcessName PID: $ProcessId)" -ForegroundColor Red
                    }
                }
            }
        }

        # FS_SysInfo_Services
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_Services
        if (Test-Path "$DriveLetter\sys\services\services.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\services" -ItemType Directory -Force | Out-Null

            # All Services
            Add-Content -Path "$OUTPUT_FOLDER\sys\services\services.txt" -Encoding utf8 -Value (Get-Content -Path "$DriveLetter\sys\services\services.txt")

            # Running Services
            Write-Output "   #    PID Start Type   State      Type Type    Obj Address  Name / Display Name                                              User                         Image Path                                          Object Name / Command Line   " | Out-File "$OUTPUT_FOLDER\sys\services\services-running.txt"
            Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" | Out-File "$OUTPUT_FOLDER\sys\services\services-running.txt" -Append
            Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "RUNNING" -CaseSensitive | Add-Content "$OUTPUT_FOLDER\sys\services\services-running.txt" -Encoding utf8

            # Stopped Services
            Write-Output "   #    PID Start Type   State      Type Type    Obj Address  Name / Display Name                                              User                         Image Path                                          Object Name / Command Line   " | Out-File "$OUTPUT_FOLDER\sys\services\services-stopped.txt"
            Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" | Out-File "$OUTPUT_FOLDER\sys\services\services-stopped.txt" -Append
            Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "STOPPED" -CaseSensitive | Add-Content "$OUTPUT_FOLDER\sys\services\services-stopped.txt" -Encoding utf8

            # Count Services
            $Total = (Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Measure-Object).Count -2
            $Running = (Get-Content "$OUTPUT_FOLDER\sys\services\services-running.txt" | Measure-Object).Count
            Write-Output "[Info]  Processing $Total Services (Running Services: $Running) ..."

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "service" }

                $Data | Foreach-Object {

                $procid = $_ | Select-Object -ExpandProperty pid -ErrorAction SilentlyContinue
                $obj = $_ | Select-Object -ExpandProperty obj
                $desc = $_ | Select-Object -ExpandProperty desc
                $start = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="start"; Expression={ForEach-Object{($_ -split "start:")[1]} | ForEach-Object{($_ -split "state:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $state = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="state"; Expression={ForEach-Object{($_ -split "state:")[1]} | ForEach-Object{($_ -split "type:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $type = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="type"; Expression={ForEach-Object{($_ -split "type:")[1]} | ForEach-Object{($_ -split "user:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $user = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="user"; Expression={ForEach-Object{($_ -split "user:")[1]} | ForEach-Object{($_ -split "image:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $image = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="image"; Expression={ForEach-Object{($_ -split "image:")[1]} | ForEach-Object{($_ -split "path:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $path = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="path"; Expression={ForEach-Object{($_ -split "path:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                New-Object -TypeName PSObject -Property @{
                    "PID" = $procid
                    "Start Type" = $start.start
                    "State" = $state.state
                    "Type" = $type.type
	                "Object Address" = $obj
	                "Name / Display Name" = $desc
                    "User" = $user.user
                    "Image Path" = $image.image
                    "Object Name / Command Line" = $path.path
                    }
                } | Select-Object "PID","Start Type","State","Type","Object Address","Name / Display Name","User","Image Path","Object Name / Command Line" | Export-Csv -Path "$OUTPUT_FOLDER\sys\services\services.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\services\services.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\services\services.csv").Length -gt 0kb)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\services\services.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\services\services.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Services" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-E and G
                        $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
            
            # Service running from a suspicious folder location: C:\Users\*\AppData\Local\Temp\*
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "[A-Z]{1}:\\Users\\.*\\AppData\\Local\\Temp\\" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Service running from a suspicious folder location: C:\Users\*\AppData\Local\Temp\* ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\services\Suspicious-Services" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\services\services.txt" | Select-String -Pattern "[A-Z]{1}:\\Users\\.*\\AppData\\Local\\Temp\\" | Out-String).Trim() | Set-Content "$OUTPUT_FOLDER\sys\services\Suspicious-Services\AppData-Local-Temp.txt" -Encoding utf8
            }
        }

        # FS_SysInfo_ScheduledTasks
        # https://github.com/ufrisk/MemProcFS/wiki/FS_SysInfo_ScheduledTasks
        # Note: A scheduled task can be used by an adversary to establish persistence, move laterally, and/or escalate privileges.
        if (Test-Path "$DriveLetter\sys\tasks\tasks.txt")
        {
            New-Item "$OUTPUT_FOLDER\sys\tasks" -ItemType Directory -Force | Out-Null
            Add-Content -Path "$OUTPUT_FOLDER\sys\tasks\tasks.txt" -Encoding utf8 -Value (Get-Content -Path "$DriveLetter\sys\tasks\tasks.txt")

            # Count Scheduled Tasks
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Measure-Object).Count -2
            Write-Output "[Info]  Processing $Count ScheduledTasks ..."

            # CSV
            if (Test-Path "$DriveLetter\forensic\json\general.json")
            {
                $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "shtask" }

                $Data | Foreach-Object {

                $desc = $_ | Select-Object -ExpandProperty desc
                $user = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="user"; Expression={ForEach-Object{($_ -split "user:")[1]} | ForEach-Object{($_ -split "cmd:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $cmd = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="cmd"; Expression={ForEach-Object{($_ -split "cmd:")[1]} | ForEach-Object{($_ -split "param:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                $param = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="param"; Expression={ForEach-Object{($_ -split "param:")[1]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                New-Object -TypeName PSObject -Property @{
	                "Task Name" = $desc
	                "User" = $user.user
	                "Command Line" = $cmd.cmd
	                "Parameters" = $param.param
                    }
                } | Select-Object "Task Name","User","Command Line","Parameters" | Export-Csv -Path "$OUTPUT_FOLDER\sys\tasks\tasks.csv" -Delimiter "`t" -NoTypeInformation
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\sys\tasks\tasks.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\sys\tasks\tasks.csv").Length -gt 0kb)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\tasks\tasks.csv" -Delimiter "`t"
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\tasks\tasks.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Tasks" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of column B
                        $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }

            # Threat Hunting: Scheduled Tasks
            # https://attack.mitre.org/techniques/T1053/

            # a) Task Scheduler running from a suspicious folder location (False Positives: MEDIUM)

            # Task Scheduler running from a suspicious folder location: C:\Users\*
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "[A-Z]{1}:\\Users\\" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\Users\* ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "[A-Z]{1}:\\Users\\" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\Users.txt"
            }

            # Task Scheduler running from a suspicious folder location: C:\ProgramData\*
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "[A-Z]{1}:\\ProgramData\\" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\ProgramData\* ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "[A-Z]{1}:\\ProgramData\\" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\ProgramData.txt"
            }

            # Task Scheduler running from a suspicious folder location: C:\Windows\Temp\*
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "[A-Z]{1}:\\Windows\\Temp\\" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\Windows\Temp\* ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "[A-Z]{1}:\\Windows\\Temp\\" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\Temp.txt"
            }

            # Task Scheduler running from a suspicious folder location: C:\TMP\*
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\tasks.csv" -Delimiter "`t" | Where-Object {($_."Command Line" -match "[A-Z]{1}:\\TMP\\")}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running from a suspicious folder location: C:\TMP\* ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\TMP.txt"
            }

            # b) Task Scheduler running using suspicious Scripting Utilities (False Positives: MEDIUM)

            # Task Scheduler running using suspicious Scripting Utility: cmd.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "cmd" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: cmd.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "cmd" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\cmd.txt"
            }

            # Task Scheduler running using suspicious Scripting Utility: csript.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "csript" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: csript.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "csript" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\csript.txt"
            }

            # Task Scheduler running using suspicious Scripting Utility: mshta.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "mshta" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: mshta.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "mshta" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\mshta.txt"
            }

            # Task Scheduler running using suspicious Scripting Utility: powershell.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "powershell" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: powershell.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "powershell" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\powershell.txt"
            }

            # Task Scheduler running using suspicious Scripting Utility: regsvr32.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "regsvr32" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: regsvr32.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "regsvr32" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\regsvr32.txt"
            }

            # Task Scheduler running using suspicious Scripting Utility: rundll32.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "rundll32" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: rundll32.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "rundll32" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\rundll32.txt"
            }

            # Task Scheduler running using suspicious Scripting Utility: wmic.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "wmic" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: wmic.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "wmic" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\wmic.txt"
            }

            # Task Scheduler running using suspicious Scripting Utility: wscript.exe
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "wscript" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running using suspicious Scripting Utility: wscript.exe ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "wscript" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities\wscript.txt"
            }

            # Parameters
            
            # Task Scheduler running malicious command line argument: sekurlsa::LogonPasswords --> OS Credential Dumping: LSASS Memory [T1003.001] --> mimikatz
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\tasks.csv" -Delimiter "`t" | Where-Object {($_.Parameters -match "sekurlsa::LogonPasswords")}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running malicious command line argument: sekurlsa::LogonPasswords ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\sekurlsa_LogonPasswords.txt"
            }

            # Task Scheduler running suspicious command line argument: -WindowStyle Hidden
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\tasks.csv" -Delimiter "`t" | Where-Object {($_.Parameters -match "-WindowStyle Hidden")}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running malicious command line argument: -WindowStyle Hidden ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\WindowStyle_Hidden.txt"
            }

            # Task Scheduler running suspicious command line argument: -nop
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\tasks\tasks.csv" -Delimiter "`t" | Where-Object {($_.Parameters -match "-nop")}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running malicious command line argument: -nop ($Count)" -ForegroundColor Yellow
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters" -ItemType Directory -Force | Out-Null
                $Import | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Parameters\nop.txt"
            }

            # Custom

            # Task Scheduler running from a suspicious folder location executes an EXE: 'C:\Users\*\AppData\Roaming\*' + EXE
            $Count = (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "AppData\\Roaming" | Select-String -Pattern "\.exe" | Measure-Object).Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Task Scheduler running from a suspicious folder location executes an EXE: 'C:\Users\*\AppData\Roaming\*' + EXE ($Count)" -ForegroundColor Red
                New-Item "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Scripting-Utilities" -ItemType Directory -Force | Out-Null
                (Get-Content "$OUTPUT_FOLDER\sys\tasks\tasks.txt" | Select-String -Pattern "AppData\\Roaming" | Select-String -Pattern "\.exe" | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\sys\tasks\Suspicious-Tasks\Location\APPDATA-EXE.txt"
            }
        }

        # FS_Process_Handles
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Process_Handles
        New-Item "$OUTPUT_FOLDER\sys\handles" -ItemType Directory -Force | Out-Null
        
        # CSV
        if (Test-Path "$DriveLetter\forensic\json\general.json")
        {
            $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "handle" }

            $Data | Foreach-Object {

                $proc = $_ | Select-Object -ExpandProperty proc
                $procid = $_ | Select-Object -ExpandProperty pid
                $handle = $_ | Select-Object -ExpandProperty hex
                $obj = $_ | Select-Object -ExpandProperty obj
                $access = $_ | Select-Object -ExpandProperty hex2 -ErrorAction SilentlyContinue
                $type = $_ | Select-Object -ExpandProperty desc
                $desc = $_ | Select-Object -ExpandProperty desc2
            
                New-Object -TypeName PSObject -Property @{
                "Process" = $proc
                "PID" = $procid
                "Handle" = $handle
                "Object Address" = $obj
                "Access" = $access
                "Type" = $type
                "Details" = $desc
                }

            } | Select-Object "Process","PID","Handle","Object Address","Access","Type","Details" | Export-Csv -Path "$OUTPUT_FOLDER\sys\handles\handles.csv" -Delimiter "`t" -NoTypeInformation
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\sys\handles\handles.csv")
            {
                if ((Get-Item "$OUTPUT_FOLDER\sys\handles\handles.csv").Length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\handles\handles.csv" -Delimiter "`t"
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\handles\handles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Handles" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-F
                    $WorkSheet.Cells["B:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # FS_Web (Web Browser History: Google Chrome, Microsoft Edge and Firefox)
        # https://github.com/ufrisk/MemProcFS/wiki/FS_Web
        if (Test-Path "$DriveLetter\misc\web\web.txt")
        {
            New-Item "$OUTPUT_FOLDER\misc\web" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\misc\web\web.txt" -Destination "$OUTPUT_FOLDER\misc\web\web-draft.txt"
            Add-Content -Path "$OUTPUT_FOLDER\misc\web\web.txt" -Encoding utf8 -Value (Get-Content -Path "$OUTPUT_FOLDER\misc\web\web-draft.txt")
            Remove-Item -Path "$OUTPUT_FOLDER\misc\web\web-draft.txt" -Force

            # Count URL (w/ thousands separators)
            $Count = (Get-Content "$OUTPUT_FOLDER\misc\web\web.txt" | Measure-Object).Count -2
            $URL = '{0:N0}' -f $Count
            Write-Output "[Info]  Processing Web History Information (Records: $URL) ..."

            if ($Count -gt 0)
            {
                # CSV
                if (Test-Path "$DriveLetter\forensic\json\general.json")
                {
                    $Data = Get-Content "$DriveLetter\forensic\json\general.json" | ConvertFrom-Json | Where-Object { $_.type -eq "web" }

                    $Data | Foreach-Object {

                        $index     = $_ | Select-Object -ExpandProperty i
                        $proc      = $_ | Select-Object -ExpandProperty proc
                        $procid    = $_ | Select-Object -ExpandProperty pid
                        $url       = $_ | Select-Object -ExpandProperty desc
                        $type      = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="type"; Expression={ForEach-Object{($_ -split "type:")[1]} | ForEach-Object{($_ -split "time:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                        $time      = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="time"; Expression={ForEach-Object{($_ -split "time:")[1]} | ForEach-Object{($_ -split "info:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}
                        $info      = $_ | Select-Object -ExpandProperty desc2 | Select-Object @{Name="info"; Expression={ForEach-Object{($_ -split "info:")[1]} | ForEach-Object{($_ -split "info:")[0]} | ForEach-Object{($_ -replace "[\[\]]","")}}}

                        New-Object -TypeName PSObject -Property @{
                        "Index"        = $index
                        "Process Name" = $proc
                        "PID"          = $procid
                        "URL"          = $url
                        "Type"         = $type.type
                        "Timestamp"    = $time.time
                        "Info"         = $info.info
                        }

                    } | Select-Object "Index","Timestamp","Process Name","PID","Type","URL","Info" | Export-Csv -Path "$OUTPUT_FOLDER\misc\web\web.csv" -Delimiter "," -NoTypeInformation -Encoding UTF8
                }

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\misc\web\web.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\misc\web\web.csv").Length -gt 0kb)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\misc\web\web.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\misc\web\web.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Web History" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-E
                            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
        }

        # FS_BitLocker
        # https://github.com/ufrisk/MemProcFS/wiki/FS_BitLocker
        if (Test-Path "$DriveLetter\misc\bitlocker\*.fvek")
        {
            # Collection
            New-Item "$OUTPUT_FOLDER\misc\bitlocker" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DriveLetter\misc\bitlocker\*" -Destination "$OUTPUT_FOLDER\misc\bitlocker"

            # Count BitLocker Full Volume Encryption Key(s)
            $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\misc\bitlocker" -Filter "*.fvek" | Measure-Object).Count
            Write-Output "[Info]  $Count BitLocker Full Volume Encryption Key(s) found"
        }

        # Forensic Timeline
        if (Test-Path "$OUTPUT_FOLDER\forensic\json\timeline.json")
        {
            Write-Output "[Info]  Creating Forensic Timeline ... "

            # CSV --> Timeline Explorer (TLE)
            New-Item "$OUTPUT_FOLDER\forensic\timeline\CSV" -ItemType Directory -Force | Out-Null
            Get-Content "$DriveLetter\forensic\json\timeline.json" | ConvertFrom-Json | Export-Csv -Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," -NoTypeInformation

            # File Size (CSV)
            if (Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv")
            {
                $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv").Length)
                Write-Output "[Info]  File Size (CSV): $Size"
            }

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel) 
            {
                if (Test-Path "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv")
                {
                    if ((Get-Item "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv").Length -gt 0kb)
                    {
                        New-Item "$OUTPUT_FOLDER\forensic\timeline\XLSX" -ItemType Directory -Force | Out-Null

                        # Count rows of CSV (w/ thousands separators)
                        [int]$Count = & $xsv count "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv"
                        $Rows = '{0:N0}' -f $Count
                        Write-Output "[Info]  Total Lines (CSV): $Rows"

                        if ($Count -gt "1048576")
                        {
                            Write-Output "[Info]  ImportExcel: timeline.csv will be splitted ..."
                            & $xsv sort -R -s "date" "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" --delimiter "," -o "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline-reverse.csv"
                            & $xsv split -s 1000000 "$OUTPUT_FOLDER\forensic\timeline\CSV" --filename "timeline-{}.csv" --delimiter "," "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline-reverse.csv"

                            [array]$Files = (Get-ChildItem -Path "$OUTPUT_FOLDER\forensic\timeline\CSV" | Where-Object {$_.Name -match "timeline-[0-9].*\.csv"}).FullName

                            ForEach( $File in $Files )
                            {
                                $FileName = $File | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                                $IMPORT = Import-Csv "$File" -Delimiter "," | Sort-Object { $_.date -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\timeline\XLSX\$FileName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Timeline" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Right" of columns A-I
                                $WorkSheet.Cells["A:I"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                        else
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\forensic\timeline\CSV\timeline.csv" -Delimiter "," | Sort-Object { $_.date -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\forensic\timeline\XLSX\timeline.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Timeline" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Right" of columns A-I
                            $WorkSheet.Cells["A:I"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
        }

        # Windows XML Event Log (EVTX)
        if (Test-Path "$DriveLetter\name\svchost.exe-*\files\handles\*.evtx") 
        {
            Write-Output "[Info]  Collecting Windows Event Logs (EVTX) ... "
            New-Item "$OUTPUT_FOLDER\EventLogs\EventLogs" -ItemType Directory -Force | Out-Null
            Get-ChildItem -Recurse -Force "$DriveLetter\name\svchost.exe-*\files\handles\*.evtx" | Foreach-Object FullName | Out-File "$OUTPUT_FOLDER\EventLogs\EventLogs.txt"
            Copy-Item -Recurse -Force "$DriveLetter\name\svchost.exe-*\files\handles\*.evtx" "$OUTPUT_FOLDER\EventLogs\EventLogs" 2>&1 | Out-Null

            # Count EVTX Files
            $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\EventLogs\EventLogs" -Filter "*.evtx" | Measure-Object).Count
            $InputSize = Get-FileSize((Get-ChildItem -Path "$OUTPUT_FOLDER\EventLogs\EventLogs" -Filter "*.evtx" | Measure-Object Length -Sum).Sum)
            Write-Output "[Info]  Processing $Count EVTX Files ($InputSize) ..."

            # EvtxECmd

            # Internet Connectivity Check (Vista+)
            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

            if (!($NetworkListManager -eq "True"))
            {
                Write-Host "[Error] Your computer is NOT connected to the Internet. Event Log Maps cannot be updated." -ForegroundColor Red
            }
            else
            {
                # Check if GitHub is reachable
                if (!(Test-Connection -ComputerName github.com -Count 1 -Quiet))
                {
                    Write-Host "[Error] github.com is NOT reachable. Event Log Maps cannot be updated." -ForegroundColor Red
                }
                else
                {
                    Write-Output "[Info]  Updating Event Log Maps ... "

                    # Flush
                    if (Test-Path "$SCRIPT_DIR\Tools\EvtxECmd\Maps")
                    {
                        Get-ChildItem -Path "$SCRIPT_DIR\Tools\EvtxECmd\Maps" -Recurse | Remove-Item -Force -Recurse
                    }

                    # Sync for EvtxECmd Maps with GitHub
                    if (Test-Path "$EvtxECmd")
                    {
                        & $EvtxECmd --sync > "$SCRIPT_DIR\Tools\EvtxECmd\Maps.log" 2> $null
                        $Count = (Get-ChildItem "$SCRIPT_DIR\Tools\EvtxECmd\Maps\*" -Include *.map | Measure-Object).Count
                    }
                    else
                    {
                        Write-Host "[Error] EvtxECmd.exe NOT found." -ForegroundColor Red
                    }
                }
            }

            # EvtxECmd --> Timeline Explorer
            if (Test-Path "$EvtxECmd")
            {
                Write-Output "[Info]  $Count Event Log Maps will be initiated by EvtxECmd ..."

                if (Test-Path "$OUTPUT_FOLDER\EventLogs\EventLogs\*.evtx") 
                {
                    New-Item "$OUTPUT_FOLDER\EventLogs\EvtxECmd" -ItemType Directory -Force | Out-Null
                    & $EvtxECmd -d "$OUTPUT_FOLDER\EventLogs\EventLogs" --csv "$OUTPUT_FOLDER\EventLogs\EvtxECmd" --csvf "EventLogs.csv" > "$OUTPUT_FOLDER\EventLogs\EvtxECmd\EvtxECmd.log" 2> $null

                    # File Size (CSV)
                    if (Test-Path "$OUTPUT_FOLDER\EventLogs\EvtxECmd\EventLogs.csv")
                    {
                        $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\EventLogs\EvtxECmd\EventLogs.csv").Length)
                        Write-Output "[Info]  File Size (CSV): $Size"
                    }

                    # Windows Title (Default)
                    $Host.UI.RawUI.WindowTitle = "MemProcFS-Analyzer v0.6 - Automated Forensic Analysis of Windows Memory Dumps for DFIR"
                }
            }
            else
            {
                Write-Host "[Error] EvtxECmd.exe NOT found." -ForegroundColor Red
            }
        }

        # Registry Hives
        if (Test-Path "$DriveLetter\registry\hive_files\*.reghive") 
        {
            Write-Output "[Info]  Collecting Registry Hives ... "
            New-Item "$OUTPUT_FOLDER\Registry\Registry" -ItemType Directory -Force 2>&1 | Out-Null
            Get-ChildItem "$DriveLetter\registry\hive_files\*.reghive" -Exclude "*ActivationStoredat*","*settingsdat*" | Foreach-Object FullName | Out-File "$OUTPUT_FOLDER\Registry\Hives.txt"
            Copy-Item "$DriveLetter\registry\hive_files\*.reghive" -Exclude "*ActivationStoredat*","*settingsdat*" "$OUTPUT_FOLDER\Registry\Registry" 2>&1 | Out-Null
        }

        # Count Registry Hives
        $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\Registry" | Measure-Object).Count
        $InputSize = Get-FileSize((Get-ChildItem -Path "$OUTPUT_FOLDER\Registry\Registry" | Measure-Object Length -Sum).Sum)
        Write-Output "[Info]  $Count Registry Hives ($InputSize) found"

        # AmcacheParser
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*Amcache*.reghive") 
        {
            if (Test-Path "$AmcacheParser")
            {
                Write-Output "[Info]  Analyzing Amcache Hive ... "

                # Collecting Amcache.hve
                New-Item "$OUTPUT_FOLDER\Amcache\Amcache" -ItemType Directory -Force 2>&1 | Out-Null
                Copy-Item "$DriveLetter\registry\hive_files\0x*Amcachehve-*.reghive" "$OUTPUT_FOLDER\Amcache\Amcache\Amcache.hve"
                
                # CSV
                New-Item "$OUTPUT_FOLDER\Amcache\CSV" -ItemType Directory -Force | Out-Null
                $AmcacheHive = "$OUTPUT_FOLDER\Amcache\Amcache\Amcache.hve"
                & $AmcacheParser -f "$AmcacheHive" -i --csv "$OUTPUT_FOLDER\Amcache\CSV" --csvf AmcacheParser.csv > "$OUTPUT_FOLDER\Amcache\AmcacheParser.log" 2> $null

                # Stats
                if (Test-Path "$OUTPUT_FOLDER\Amcache\AmcacheParser.log")
                {
                    $Total = Get-Content "$OUTPUT_FOLDER\Amcache\AmcacheParser.log" | Select-String -Pattern "unassociated file entries"
                    if ($Total) 
                    { 
                        Write-Output "[Info]  $Total"
                    }
                    else
                    {
                        Write-Output "[Info]  Amcache Hive seems to be partially corrupt."
                    }
                }

                # XLSX
                # Note: The output of Windows 10 and Win 7 looks different --> optimized for Windows 10 only
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    # AssociatedFileEntries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv" -Delimiter "," | Sort-Object { $_.FileKeyLastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_AssociatedFileEntries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AssociatedFileEntries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:U1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-E and G-U
                            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:U"].Style.HorizontalAlignment="Center"
                            # HorizontalAlignment "Center" of header of column F
                            $WorkSheet.Cells["F1:F1"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DeviceContainers
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DeviceContainers.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DeviceContainers.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DeviceContainers.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DeviceContainers.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DeviceContainers" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:Q1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-Q
                            $WorkSheet.Cells["B:Q"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DevicePnps
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DevicePnps.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DevicePnps.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DevicePnps.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DevicePnps.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DevicePnps" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-E and G-Y
                            $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:Y"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DriveBinaries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriveBinaries.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriveBinaries.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriveBinaries.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DriveBinaries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DriveBinaries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:T1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-T
                            $WorkSheet.Cells["B:T"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # DriverPackages
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriverPackages.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriverPackages.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_DriverPackages.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_DriverPackages.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DriverPackages" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-D and -L
                            $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:L"].Style.HorizontalAlignment="Center"
                            # HorizontalAlignment "Center" of header of column E
                            $WorkSheet.Cells["E1:E1"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # ProgramEntries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ProgramEntries.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ProgramEntries.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ProgramEntries.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_ProgramEntries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ProgramEntries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:Z1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-J, L-N, P-S, V-X and Z
                            $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["L:N"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["P:S"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["V:X"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["Z:Z"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # ShortCuts
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ShortCuts.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ShortCuts.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_ShortCuts.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_ShortCuts.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ShortCuts" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A and C
                            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # UnassociatedFileEntries
                    if (Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Amcache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.FileKeyLastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\XLSX\AmcacheParser_UnassociatedFileEntries.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UnassociatedFileEntries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:U1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-E and G-T
                            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:T"].Style.HorizontalAlignment="Center"
                            # HorizontalAlignment "Center" of header of column F
                            $WorkSheet.Cells["F1:F1"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
                else
                {
                    Write-Output "[Info]  PowerShell module 'ImportExcel' NOT found."
                }

                # Amcache Scan --> Check SHA1 File Hashes on VirusTotal
                if ((Test-Path "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv") -And ((Get-Item "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv").length -gt 0kb))
                {
                    New-Item "$OUTPUT_FOLDER\Amcache\SHA1" -ItemType Directory -Force | Out-Null
                    Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_UnassociatedFileEntries.csv" -Delimiter "," | Select-Object -Property Name, ProductName, ApplicationName, FullPath, SHA1 | Sort-Object -Property SHA1 -Unique | Export-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," -NoTypeInformation
                    Import-Csv "$OUTPUT_FOLDER\Amcache\CSV\AmcacheParser_AssociatedFileEntries.csv" -Delimiter "," | Select-Object -Property Name, ProductName, ApplicationName, FullPath, SHA1 | Sort-Object -Property SHA1 -Unique | Export-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," -NoTypeInformation -Append
                    Import-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," | Where-Object {$_.SHA1 -ne ""} | Sort-Object -Property SHA1 -Unique | Export-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv" -Delimiter "," -NoTypeInformation
                    (Import-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv" -Delimiter "," | Where-Object {$_.SHA1 -ne ""} | Sort-Object -Property SHA1 -Unique).SHA1 | Out-File "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.txt" -Encoding ascii
                    Remove-Item "$OUTPUT_FOLDER\Amcache\SHA1\SHA1-draft.csv"

                    # XLSX
                    if (Get-Module -ListAvailable -Name ImportExcel)
                    {
                        if (Test-Path "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv")
                        {
                            if ((Get-Item "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv").Length -gt 0kb)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SHA1" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of column E
                                $WorkSheet.Cells["E:E"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }
                    }
                
                    # Count SHA1 File Hashes
                    $Count = [string]::Format('{0:N0}',(Get-Content "$OUTPUT_FOLDER\Amcache\SHA1\SHA1.txt" | Measure-Object).Count)
                    Write-Output "[Info]  $Count SHA1 hash value(s) of executables found"
                }
            }
        }

        # AppCompatCacheParser (ShimCache)
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*SYSTEM*.reghive") 
        {
            if (Test-Path "$AppCompatCacheParser")
            {
                Write-Output "[Info]  Analyzing Application Compatibility Cache aka ShimCache ... "

                # CSV
                New-Item "$OUTPUT_FOLDER\Registry\ShimCache\CSV" -ItemType Directory -Force | Out-Null
                $SYSTEM = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Foreach-Object FullName | Select-String -Pattern "SYSTEM" -CaseSensitive | Out-String).Trim()
                & $AppCompatCacheParser -f "$SYSTEM" --csv "$OUTPUT_FOLDER\Registry\ShimCache\CSV" --csvf AppCompatCacheParser.csv -t > "$OUTPUT_FOLDER\Registry\ShimCache\AppCompatCacheParser.log" 2> $null

                # Stats
                if (Test-Path "$OUTPUT_FOLDER\Registry\ShimCache\AppCompatCacheParser.log")
                {
                    $Total = Get-Content "$OUTPUT_FOLDER\Registry\ShimCache\AppCompatCacheParser.log" | Select-String -Pattern "cache entries"
                    if ($Total)
                    {
                        Write-Output "[Info]  $Total"
                    }
                    else
                    {
                        Write-Output "[Info]  SYSTEM Hive seems to be partially corrupt."
                    }
                }

                # XLSX
                if (Get-Module -ListAvailable -Name ImportExcel)
                {
                    if (Test-Path "$OUTPUT_FOLDER\Registry\ShimCache\CSV\AppCompatCacheParser.csv")
                    {
                        if ((Get-Item "$OUTPUT_FOLDER\Registry\ShimCache\CSV\AppCompatCacheParser.csv").Length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Registry\ShimCache\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\ShimCache\CSV\AppCompatCacheParser.csv" -Delimiter "," | Sort-Object { $_.LastModifiedTimeUTC -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\ShimCache\XLSX\AppCompatCacheParser.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ShimCache" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-B and D-F
                            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["D:F"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] AppCompatCacheParser.exe NOT found." -ForegroundColor Red
            }
        }

        # Syscache
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*Syscachehve*.reghive") 
        {
            if (Test-Path "$RECmd")
            {
                Write-Output "[Info]  Analyzing Syscache Hive ... "

                # CSV
                New-Item "$OUTPUT_FOLDER\Syscache\CSV" -ItemType Directory -Force | Out-Null
                $Syscachehve = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "Syscachehve")} | Foreach-Object FullName)
                & $RECmd -f "$Syscachehve" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\SysCache.reb" --csv "$OUTPUT_FOLDER\Syscache\CSV" --csvf "Syscache.csv" > "$OUTPUT_FOLDER\Syscache\Syscache.log" 2> $null

                # Stats
                if (Test-Path "$OUTPUT_FOLDER\Syscache\Syscache.log")
                {
                    $Total = Get-Content "$OUTPUT_FOLDER\Syscache\Syscache.log" | Select-String -Pattern "key/value pairs"
                    Write-Output "[Info]  $Total"
                }

                # SHA1 --> Check SHA1 hashes on VirusTotal
                if ((Test-Path "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv") -And ((Get-Item "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv").length -gt 0kb))
                {
                    (Import-Csv "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv" | Select-Object -Property "ValueData2" | Sort-Object -Property "ValueData2" -Unique).ValueData2 | ForEach-Object{($_ -split "SHA-1: ")[1]} | Select-Object -Skip 1 | Out-File "$OUTPUT_FOLDER\Syscache\SHA1.txt" -Encoding ascii

                    # Count SHA1 hashes
                    $Count = [string]::Format('{0:N0}',(Get-Content "$OUTPUT_FOLDER\Syscache\SHA1.txt" | Measure-Object).Count)
                    Write-Output "[Info]  $Count SHA1 hash value(s) of executables found"
                }

                # XLSX

                # Syscache.csv
                if (Test-Path "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv")
                {
                    if((Get-Item "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv").length -gt 0kb)
                    {
                        New-Item "$OUTPUT_FOLDER\Syscache\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Syscache\CSV\Syscache.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Syscache\XLSX\Syscache.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SysCache" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-N
                        $WorkSheet.Cells["B:N"].Style.HorizontalAlignment="Center"
                        }
                    }
                }

                # Syscache_SyscacheObjectTable.csv
                if (Test-Path "$OUTPUT_FOLDER\Syscache\CSV\*\Syscache_SyscacheObjectTable.csv")
                {
                    if((Get-Item "$OUTPUT_FOLDER\Syscache\CSV\*\Syscache_SyscacheObjectTable.csv").length -gt 0kb)
                    {
                        New-Item "$OUTPUT_FOLDER\Syscache\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Syscache\CSV\*\Syscache_SyscacheObjectTable.csv" -Delimiter "," | Sort-Object { $_.LastWriteTime -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Syscache\XLSX\Syscache_SyscacheObjectTable.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SysCache (Plugin)" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-L
                        $WorkSheet.Cells["B:L"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["D:L"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Info]  Syscache.hve not found."
        }

        # UserAssist

        # Check if RECmd.exe exists
        if (Test-Path "$RECmd")
        {
            # Check if batch processing file exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\UserAssist.reb")
            {
                # Check if Registry Plugin exists
                if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Plugins\RegistryPlugin.UserAssist.dll")
                {
                    # Analyzing UserAssist Artifacts
                    Write-Output "[Info]  Analyzing UserAssist Artifacts ..."
                    New-Item "$OUTPUT_FOLDER\UserAssist\CSV" -ItemType Directory -Force | Out-Null
                    New-Item "$OUTPUT_FOLDER\UserAssist\XLSX" -ItemType Directory -Force | Out-Null

                    $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                    ForEach( $FilePath in $FilePathList )
                    {
                        $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
                        $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                        # Check if UserAssist key exists
                        if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
                        {
                            # CSV
                            & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\UserAssist.reb" --csv "$OUTPUT_FOLDER\UserAssist\CSV" --csvf "$SID-UserAssist.csv" > "$OUTPUT_FOLDER\UserAssist\$SID-UserAssist.log" 2> $null

                            # Stats
                            if (Test-Path "$OUTPUT_FOLDER\UserAssist\$SID-UserAssist.log")
                            {
                                # Check for parsing error
                                if (!(Get-Content -Path "$OUTPUT_FOLDER\UserAssist\$SID-UserAssist.log" | Select-String -Pattern "parse error" -Quiet))
                                {
                                    # Check if key/value pairs were found
                                    if (!(Get-Content -Path "$OUTPUT_FOLDER\UserAssist\$SID-UserAssist.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                                    {
                                        # Count
                                        $Total = Get-Content "$OUTPUT_FOLDER\UserAssist\$SID-UserAssist.log" | Select-String -Pattern "key/value pairs"
                                        Write-Host "[Info]  $Total ($SID)"

                                        # Header
                                        Write-Output "UserAssist Entries Description,Count" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv"

                                        # Total Entries
                                        $TotalEntries = (Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Measure-Object).Count
                                        Write-Output "Total Entries,$TotalEntries" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Append

                                        # Toral Entries w/ Run Count
                                        $TotalRunCount = (Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData3 -match "Run count:" } | Measure-Object).Count
                                        Write-Output "Total Entries with Run Count,$TotalRunCount" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Append

                                        # Entries with "Run count: 0"
                                        $RunCount0 = (Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData3 -match "Run count: 0" } | Measure-Object).Count
                                        Write-Output "Entries with Run Count 0,$RunCount0" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Append

                                        # Entries with "Last executed" field populated
                                        $LastExecutedPopulated = (Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData2 -match "Last executed: 2" } | Measure-Object).Count
                                        Write-Output "Entries with 'Last executed' field populated,$LastExecutedPopulated" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Append

                                        # Entries with "Last executed" field not populated
                                        $LastExecutedEmpty = (Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.ValueData2 -match "Last executed: $" } | Measure-Object).Count
                                        Write-Output "Entries with 'Last executed' field not populated,$LastExecutedEmpty" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Append

                                        # Executable File Execution (GUID)
                                        $ExecutableFileExecution = (Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.KeyPath -match "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count" } | Measure-Object).Count
                                        Write-Output "Executable File Execution,$ExecutableFileExecution" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Append

                                        # Shortcut File Execution (GUID)
                                        $ShortcutFileExecution = (Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Where-Object { $_.KeyPath -match "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count" } | Measure-Object).Count
                                        Write-Output "Shortcut File Execution,$ShortcutFileExecution" | Out-File "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Append
                                    }
                                    else
                                    {
                                        Write-Host "[Info]  Found 0 key/value pairs across 1 file ($SID)"
                                    }
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv")
                            {
                                if((Get-Item "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv").length -gt 0kb)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UserAssist\XLSX\$SID-UserAssist.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAssist" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns B-D, G and J-N
                                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["J:N"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }

                            # XLSX (PluginDetailFile)
                            if (Test-Path "$OUTPUT_FOLDER\UserAssist\CSV\*\$SID-UserAssist_UserAssist.csv")
                            {
                                if((Get-Item "$OUTPUT_FOLDER\UserAssist\CSV\*\$SID-UserAssist_UserAssist.csv").length -gt 0kb)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\*\$SID-UserAssist_UserAssist.csv" -Delimiter "," | Sort-Object { $_.LastExecuted -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UserAssist\XLSX\$SID-UserAssist_UserAssist.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAssist (Plugin)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns D-G
                                    $WorkSheet.Cells["D:G"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }

                            # XLSX (Stats)
                            if (Test-Path "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv")
                            {
                                if((Get-Item "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv").length -gt 0kb)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UserAssist\CSV\$SID-UserAssist-Stats.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UserAssist\XLSX\$SID-UserAssist-Stats.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAssist (Stats)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of column B
                                    $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Write-Host "[Error] RegistryPlugin.UserAssist.dll NOT found." -ForegroundColor Red
                }
            }
            else
            {
                Write-Host "[Error] UserAssist.reb NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
        }

        # SBECCmd

        # Check ShellBags Location
        if ((Test-Path "$OUTPUT_FOLDER\Registry\Registry\*ntuserdat*") -or (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*UsrClassdat*"))
        {
            if (Test-Path "$SBECmd")
            {
                Write-Output "[Info]  Analyzing ShellBags Artifacts ... "
                New-Item "$OUTPUT_FOLDER\ShellBags\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\ShellBags\XLSX" -ItemType Directory -Force | Out-Null

                # ShellBags are stored in both NTUSER.DAT and USRCLASS.DAT
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat|UsrClassdat")} | Foreach-Object FullName)

                # Rename Registry Hives temporarily...SBECCmd requires .dat file extension
                Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat|UsrClassdat")} | Rename-Item -NewName {$_.Name -replace "\.reghive$",".dat"}

                # CSV
                & $SBECmd -d "$OUTPUT_FOLDER\Registry\Registry" --csv "$OUTPUT_FOLDER\ShellBags\CSV" --csvf "SBECmd.csv" > "$OUTPUT_FOLDER\ShellBags\SBECmd.log" 2> $null
                
                # Rename Registry Hives
                Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat|UsrClassdat")} | Rename-Item -NewName {$_.Name -replace "\.dat$",".reghive"}

                # Stats
                if (Get-Content "$OUTPUT_FOLDER\ShellBags\SBECmd.log" | Select-String -Pattern "^Total ShellBags found:" -Quiet)
                {
                    # Error
                    if (Get-Content "$OUTPUT_FOLDER\ShellBags\SBECmd.log" | Select-String -Pattern "Error processing hbin" -Quiet)
                    {
                        Write-Output "[Info]  ShellBags Artifacts seem to be partially corrupt."
                    }

                    # Total
                    $Total = (Get-Content "$OUTPUT_FOLDER\ShellBags\SBECmd.log" | Select-String -Pattern "Total ShellBags found:" | Select-Object -Last 1 | Out-String).Trim()
                    Write-Output "[Info]  $Total"
                }

                # XLSX
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\ShellBags\CSV" | Where-Object {($_.Extension -eq ".csv")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "-USER_")[1]} | ForEach-Object{($_ -split "\.csv")[0]}

                    if (Test-Path "$FilePath")
                    {
                        if((Get-Item "$FilePath").length -gt 1kb)
                        {
                            New-Item "$OUTPUT_FOLDER\ShellBags\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$FilePath" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\ShellBags\XLSX\$FileName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ShellBags" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:S1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-D, F and H-S
                            $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["H:S"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] SBECCmd.exe NOT found." -ForegroundColor Red
            }
        }

        # Registry ASEPs (Auto-Start Extensibility Points)
        if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
        {
            if (Test-Path "$RECmd")
            {
                # Check if batch processing file exists
                if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RegistryASEPs.reb")
                {
                    Write-Output "[Info]  Extracting Auto-Start Extensibility Points (ASEPs) ... "

                    # CSV
                    New-Item "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV" -ItemType Directory -Force | Out-Null
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","ntuser.dat"}
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","UsrClass.dat"}
                    & $RECmd -d "$OUTPUT_FOLDER\Registry\Registry" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RegistryASEPs.reb" --csv "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV" --csvf "RegistryASEPs.csv" > "$OUTPUT_FOLDER\Registry\RegistryASEPs\RegistryASEPs.log" 2> $null
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "ntuser\.dat$",".reghive"}
                    Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "UsrClass\.dat$",".reghive"}

                    # Stats
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RegistryASEPs\RegistryASEPs.log")
                    {
                        $Total = Get-Content "$OUTPUT_FOLDER\Registry\RegistryASEPs\RegistryASEPs.log" | Select-String -Pattern "key/value pairs"
                        Write-Output "[Info]  $Total"
                    }

                    # XSLX
                    New-Item "$OUTPUT_FOLDER\Registry\RegistryASEPs\XLSX" -ItemType Directory -Force | Out-Null
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV\RegistryASEPs.csv")
                    {
                        if((Get-Item "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV\RegistryASEPs.csv").length -gt 0kb)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\RegistryASEPs\CSV\RegistryASEPs.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\RegistryASEPs\XLSX\RegistryASEPs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RegistryASEPs" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B-D, G and L-O
                            $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["L:O"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
                else
                {
                    Write-Host "[Error] RegistryASEPs.reb NOT found." -ForegroundColor Red
                }
            }
            else
            {
                Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
            }
        }

        # Startup Folders
        if (Test-Path "$DriveLetter\forensic\timeline\timeline_ntfs.txt")
        {
            New-Item "$OUTPUT_FOLDER\Persistence" -ItemType Directory -Force | Out-Null
            $StartupFolders = (Get-Content "$DriveLetter\forensic\timeline\timeline_ntfs.txt" | Select-String -Pattern "\\Start Menu\\Programs\\Startup\\" | Where-Object {$_ -notmatch "desktop.ini"} | Out-String).Trim()
            $StartupFolders | Out-File "$OUTPUT_FOLDER\Persistence\Startup-Folders.txt"
        }

        # SQLite Database
        if (Test-Path "$DriveLetter\forensic\database.txt")
        {
            # Collecting SQLite Database
            $DatabasePath = (Get-Content "$DriveLetter\forensic\database.txt" | Select-String -Pattern "vmm.sqlite3" | Out-String).Trim()
            Write-Output "[Info]  SQLite Database: $DatabasePath"
            Write-Output "[Info]  Collecting SQLite Database ..."
            New-Item "$OUTPUT_FOLDER\database" -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$DatabasePath" -Destination "$OUTPUT_FOLDER\database\vmm.sqlite3"

            # File Size (SQLite3)
            if (Test-Path "$OUTPUT_FOLDER\database\vmm.sqlite3")
            {
                $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\database\vmm.sqlite3").Length)
                Write-Output "[Info]  File Size (SQLite3): $Size"
            }
        }

        # MemProcFS Plugins
        # https://github.com/ufrisk/MemProcFS-plugins

        # pypykatz
        # https://github.com/skelsec/pypykatz
        if (Test-Path "$DriveLetter\py\secrets\*")
        {
            Write-Output "[Info]  Collecting pypykatz ... "
            New-Item "$OUTPUT_FOLDER\MemProcFS-Plugins\pypykatz" -ItemType Directory -Force | Out-Null
            Copy-Item -Recurse -Force "$DriveLetter\py\secrets\*" "$OUTPUT_FOLDER\MemProcFS-Plugins\pypykatz" 2>&1 | Out-Null
        }

        # regsecrets
        # https://github.com/skelsec/pypykatz
        if (Test-Path "$DriveLetter\py\regsecrets\*")
        {
            Write-Output "[Info]  Collecting regsecrets ... "
            New-Item "$OUTPUT_FOLDER\MemProcFS-Plugins\regsecrets" -ItemType Directory -Force | Out-Null
            Copy-Item -Recurse -Force "$DriveLetter\py\regsecrets\*" "$OUTPUT_FOLDER\MemProcFS-Plugins\regsecrets" 2>&1 | Out-Null
        }
    }
    else
    {
        Write-Host "[Error] Forensic Directory doesn't exist." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] MemProcFS.exe NOT found." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

}

#endregion MemProcFS

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region ELKImport

Function ELKImport {

# Elastic-Import
if (Test-Path "$DriveLetter\forensic\json\elastic_import.ps1")
{
    # Copy elastic_import.ps1 to a trusted location (to avoid security warning)
    Copy-Item -Path "$DriveLetter\forensic\json\elastic_import.ps1" -Destination "$SCRIPT_DIR\elastic_import.ps1"

    # ELK Import
    Write-Output "[Info]  Importing JSON data to Elasticsearch [approx. 1-5 min] ... "
    $Elastic_Import = "$SCRIPT_DIR\elastic_import.ps1"
    $Argument = $DriveLetter.TrimEnd(":")
    Start-Process -FilePath "powershell" -Verb RunAs -Wait -ArgumentList "-File $Elastic_Import", "$Argument"

    # Cleaning up
    if (Test-Path "$Elastic_Import")
    {
        Remove-Item "$Elastic_Import" -Force
    }

    try 
    {
        # Open Kibana w/ Google Chrome
        $Chrome = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\ChromeHTML\shell\open\command" -ErrorAction SilentlyContinue)."(Default)"
        #Start-Process -FilePath $Chrome -ArgumentList "--new-window http://localhost:5601"
    }
    catch 
    {
        # Open Kibana in your Default Browser
        Start-Process "http://localhost:5601"
    }
}

}

#endregion ELKImport

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region MicrosoftDefender

Function MicrosoftDefender {

# Turning Microsoft Defender AntiVirus off (Real-Time Protection)

# Real-Time Protection Activation Status
# Note: Tamper Protection must be disabled.
$DisableRealtimeMonitoring = ((Get-MpPreference | Select-Object DisableRealtimeMonitoring).DisableRealtimeMonitoring | Out-String).Trim()

# Disable Real-Time Protection
if ($DisableRealtimeMonitoring -eq "False")
{
    Write-Output "[Info]  Microsoft Defender (Real-Time Protection) will be disabled temporarily ..."
    Set-MpPreference -DisableRealtimeMonitoring $true
    Start-Sleep 10
}

}

#endregion MicrosoftDefender

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region ClamAVUpdate

Function ClamAVUpdate {

# ClamAVUpdate
New-Item "$OUTPUT_FOLDER\ClamAV" -ItemType Directory -Force | Out-Null

# freshclam.conf
if (!(Test-Path "C:\Program Files\ClamAV\freshclam.conf"))
{
    Write-Host "[Error] freshclam.conf is missing." -ForegroundColor Red
    Write-Host "        https://www.clamav.net/documents/installing-clamav-on-windows --> First Time Set-Up" -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# clamd.conf
if (!(Test-Path "C:\Program Files\ClamAV\clamd.conf"))
{
    Write-Host "[Error] clamd.conf is missing." -ForegroundColor Red
    Write-Host "        https://www.clamav.net/documents/installing-clamav-on-windows --> First Time Set-Up" -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Update
if (Test-Path "$freshclam")
{
    # Internet Connectivity Check (Vista+)
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

    if (!($NetworkListManager -eq "True"))
    {
        Write-Host "[Error] Your computer is NOT connected to the Internet. ClamAV cannot check for any updates." -ForegroundColor Red
    }
    else
    {
        # Check if clamav.net is reachable
        if (!(Test-Connection -ComputerName clamav.net -Count 1 -Quiet))
        {
            Write-Host "[Error] clamav.net is NOT reachable. ClamAV cannot check for any updates." -ForegroundColor Red
        }
        else
        {
            Write-Output "[Info]  Checking for ClamAV Updates ..."
            & $freshclam > "$OUTPUT_FOLDER\ClamAV\Update.txt" 2> "$OUTPUT_FOLDER\ClamAV\Warning.txt"

            # Update ClamAV Engine
            if (Select-String -Pattern "WARNING: Your ClamAV installation is OUTDATED!" -Path "$OUTPUT_FOLDER\ClamAV\Warning.txt" -Quiet)
            {
                Write-Host "[Info]  WARNING: Your ClamAV installation is OUTDATED!" -ForegroundColor Red

                if (Select-String -Pattern "Recommended version:" -Path "$OUTPUT_FOLDER\ClamAV\Warning.txt" -Quiet)
                {
                    $WARNING = Get-Content "$OUTPUT_FOLDER\ClamAV\Warning.txt" | Select-String -Pattern "Recommended version:"
                    Write-Host "[Info]  $WARNING" -ForegroundColor Red
                }
            }

            # Update Signature Databases
            $Count = (Get-Content "$OUTPUT_FOLDER\ClamAV\Update.txt" | Select-String -Pattern "is up to date" | Measure-Object).Count
            if ($Count -match "3")
            {
                Write-Output "[Info]  All ClamAV Virus Databases (CVD) are up-to-date."
            }
            else
            {
                Write-Output "[Info]  Updating ClamAV Virus Databases (CVD) ... "
            }
        }
    }
}
else
{
    Write-Host "[Error] freshclam.exe NOT found." -ForegroundColor Red
}

# Engine Version
if (Test-Path "$clamscan")
{
    $Version = & $clamscan -V
    $EngineVersion = $Version.Split('/')[0]
    $Patch = $Version.Split('/')[1]
    Write-Output "[Info]  Engine Version: $EngineVersion (#$Patch)"
    $Version | Out-File "$OUTPUT_FOLDER\ClamAV\Version.txt"
}
else
{
    Write-Host "[Error] clamscan.exe NOT found." -ForegroundColor Red
}

}

#endregion ClamAVUpdate

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region ClamAV

Function ClamAV {

# ClamAV

# Custom Scan
# Note: By default ClamAV will not scan files larger than 20MB.
$ScanPath = "$DriveLetter\name"

# Drive Letter Scan Mode
if ((Get-Item $ScanPath) -is [System.IO.DirectoryInfo])
{
    if ($ScanPath -match ":$")
    {
        Write-Output "[Info]  Custom scan w/ ClamAV is running ($ScanPath) ..."
        Write-Output "[Info]  Drive Letter Scan Mode enabled [time-consuming task] ..."
    }
}

# Directory Scan Mode
if ((Get-Item $ScanPath) -is [System.IO.DirectoryInfo])
{
    if (!($ScanPath -match ":$"))
    {
        Write-Output "[Info]  Custom scan w/ ClamAV is running ($ScanPath) ..."
        Write-Output "[Info]  Directory Scan Mode enabled [time-consuming task] ..."
    }
}

# File Scan Mode
if ((Get-Item $ScanPath) -is [System.IO.FileInfo])
{
    Write-Output "[Info]  Custom scan w/ ClamAV is running ($ScanPath) ..."
    Write-Output "[Info]  File Scan Mode enabled"
}

# Start ClamAV Daemon
if (Test-Path "$clamd")
{
    if (Test-Path "$clamdscan")
    {
        Write-Output "[Info]  Starting ClamAV Daemon ..."
        Start-Process powershell.exe -FilePath "$clamd" -WindowStyle Minimized
        $ProgressPreference = 'SilentlyContinue'
        do {
          Start-Sleep -Seconds 5
        } until (Test-NetConnection 127.0.0.1 -Port 3310 -InformationLevel Quiet -WarningAction SilentlyContinue )
        Write-Output "[Info]  ClamAV Daemon is running ..."

        # ClamAV Daemon Scan (Multi-Threaded)
        $LogFile = "$OUTPUT_FOLDER\ClamAV\LogFile.txt"
        $ConfigFile = "$SCRIPT_DIR\Tools\ClamAV\clamd.conf"
        Start-Process -FilePath "$clamdscan" -ArgumentList "$ScanPath --quiet --multiscan -c $ConfigFile --log=$LogFile" -WindowStyle Minimized -Wait
        Stop-Process -Name "clamdscan" -ErrorAction SilentlyContinue
        Stop-Process -Name "clamd" -ErrorAction SilentlyContinue

        # ClamAV Detection(s)

        # FOUND (Infected Files)
        New-Item "$OUTPUT_FOLDER\ClamAV\Infected" -ItemType Directory -Force | Out-Null
        $InfectedFilesCount = (Get-Content $LogFile | Select-String -Pattern "FOUND" -CaseSensitive | Select-String -Pattern "Heuristics.Encrypted.* FOUND" -NotMatch | Measure-Object).Count
        $InfectedFilesMatches = Get-Content $LogFile | Select-String -Pattern "FOUND" -CaseSensitive | Select-String -Pattern "Heuristics.Encrypted.* FOUND" -NotMatch
        if ($InfectedFilesCount -eq "0")
        {
            Write-Host "[Info]  0 infected file(s) found" -ForegroundColor Green
        }
        else
        {
            ($InfectedFilesMatches | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles.txt"
            Get-Content "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles.txt" | Where-Object {$_ -notmatch "MsMpEng.exe"} | Out-File "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt"
    
            $FilteredCount = (Get-Content "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt" | Measure-Object).Count
            Write-Host "[Alert] $FilteredCount infected file(s) found ($InfectedFilesCount)" -ForegroundColor Red
        }

        # Collect Infected Files
        if (Test-Path "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt")
        {
            $InfectedFiles = Get-Content "$OUTPUT_FOLDER\ClamAV\Infected\InfectedFiles-filtered.txt" | ForEach-Object{($_ -split ": ")[0]}
            New-Item "$OUTPUT_FOLDER\ClamAV\Infected\Infected" -ItemType Directory -Force | Out-Null

            ForEach( $InfectedFile in $InfectedFiles )
            {
                $ProcessID = $InfectedFile | ForEach-Object{($_ -split "\\")[2]} | ForEach-Object{($_ -split "-")[-1]}
                $INFECTED = "infected"
                $ArchiveName = $InfectedFile | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "_INJECTED-")[-1]}
                & $7za a -mx5 -mhe "-p$INFECTED" -t7z "$OUTPUT_FOLDER\ClamAV\Infected\Infected\$ProcessID-$ArchiveName.7z" "$InfectedFile" > $null 2>&1
            }
        }

        # Stop ClamAV Daemon
        Stop-Process -Name "clamd" -ErrorAction SilentlyContinue
    }
    else
    {
        Write-Host "[Error] clamdscan.exe NOT found." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] clamd.exe NOT found." -ForegroundColor Red
}

}

#endregion ClamAV

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Documents

Function Documents {

# RecentDocs
if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
{
    if (Test-Path "$RECmd")
    {
        # Check if batch processing file exists
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RecentDocs.reb")
        {
            # Check if Registry Plugin exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Plugins\RegistryPlugin.RecentDocs.dll")
            {
                # Analyzing RecentDocs Artifacts
                Write-Output "[Info]  Analyzing RecentDocs Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\RecentDocs\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX" -ItemType Directory -Force | Out-Null

                # CSV
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.reghive$")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if RecentDocs key exists
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
                    {
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\RecentDocs.reb" --csv "$OUTPUT_FOLDER\Registry\RecentDocs\CSV" --csvf "$SID-RecentDocs.csv" > "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" 2> $null
                    }

                    # Stats
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log")
                    {
                        # Check for parsing error
                        if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" | Select-String -Pattern "parse error" -Quiet))
                        {
                            # Check if key/value pairs were found
                            if (!(Get-Content -Path "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" | Select-String -Pattern "Found 0 key/value pairs across 1 file" -Quiet))
                            {
                                $Total = Get-Content "$OUTPUT_FOLDER\Registry\RecentDocs\$SID-RecentDocs.log" | Select-String -Pattern "key/value pairs"
                                Write-Host "[Info]  $Total ($SID)"
                            }
                            else
                            {
                                if ($SID)
                                {
                                    Write-Output "[Info]  Found 0 key/value pairs across 1 file ($SID)"
                                }
                                else
                                {
                                    Write-Output "[Info]  Found 0 key/value pairs across 1 file"
                                }
                            }
                        }
                    }
                    
                    # XLSX
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\$SID-RecentDocs.csv")
                    {
                        if((Get-Item "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\$SID-RecentDocs.csv").length -gt 0kb)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\$SID-RecentDocs.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX\$SID-RecentDocs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecentDocs" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B, D, F-G and J-N
                            $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:G"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["J:N"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # RecentDocs_RecentDocs.csv
                    if (Test-Path "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\*\$SID-RecentDocs_RecentDocs.csv")
                    {
                        if((Get-Item "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\*\$SID-RecentDocs_RecentDocs.csv").length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\RecentDocs\CSV\*\$SID-RecentDocs_RecentDocs.csv" -Delimiter ","
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\RecentDocs\XLSX\$SID-RecentDocs_RecentDocs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecentDocs (Plugin)" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A, C-D and G-I
                            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["G:I"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] RegistryPlugin.RecentDocs.dll NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] RecentDocs.reb NOT found." -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
    }
}

# Office Trusted Documents
if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
{
    if (Test-Path "$RECmd")
    {
        # Check if batch processing file exists
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\TrustedDocuments.reb")
        {
            # Check if Registry Plugin exists
            if (Test-Path "$SCRIPT_DIR\Tools\RECmd\Plugins\RegistryPlugin.TrustedDocuments.dll")
            {
                # Analyzing Trusted Documents Artifacts
                Write-Output "[Info]  Analyzing Trusted Documents Artifacts ... "
                New-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV" -ItemType Directory -Force | Out-Null
                New-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX" -ItemType Directory -Force | Out-Null

                # CSV
                $FilePathList = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuserdat")} | Foreach-Object FullName)

                ForEach( $FilePath in $FilePathList )
                {
                    $FileName = $FilePath | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.reghive$")[0]}
                    $SID = $FileName | ForEach-Object{($_ -split "_")[1]}

                    # Check if TrustedDocuments key exists
                    if (Test-Path "$DriveLetter\registry\by-hive\$FileName\ROOT\SOFTWARE\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords")
                    {
                        & $RECmd -f "$FilePath" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\TrustedDocuments.reb" --csv "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV" --csvf "$SID-TrustedDocuments.csv" > "$OUTPUT_FOLDER\Registry\TrustedDocuments\$SID-TrustedDocuments.log" 2> $null
                    }

                    # Stats
                    if (Test-Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\$SID-TrustedDocuments.log")
                    {
                        $Total = Get-Content "$OUTPUT_FOLDER\Registry\TrustedDocuments\$SID-TrustedDocuments.log" | Select-String -Pattern "key/value pair"
                        Write-Host "[Info]  $Total ($SID)"
                    }
                    else
                    {
                        if ($SID)
                        {
                            Write-Output "[Info]  Found 0 key/value pairs across 1 file ($SID)"
                        }
                        else
                        {
                            Write-Output "[Info]  Found 0 key/value pairs across 1 file"
                        }
                    }

                    # XLSX
                    if (Test-Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\$SID-TrustedDocuments.csv")
                    {
                        if((Get-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\$SID-TrustedDocuments.csv").length -gt 0kb)
                        {
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\$SID-TrustedDocuments.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX\$SID-TrustedDocuments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TrustedDocuments" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns B, D, F-G and J-N
                            $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:G"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["J:N"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }

                    # TrustedDocuments_TrustedDocuments.csv
                    if (Test-Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\*\$SID-TrustedDocuments_TrustedDocuments.csv")
                    {
                        if((Get-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\*\$SID-TrustedDocuments_TrustedDocuments.csv").length -gt 0kb)
                        {
                            New-Item "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX" -ItemType Directory -Force | Out-Null
                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\TrustedDocuments\CSV\*\$SID-TrustedDocuments_TrustedDocuments.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\TrustedDocuments\XLSX\$SID-TrustedDocuments_TrustedDocuments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TrustedDocuments (Plugin)" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A, C, and F
                            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                            $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                            }
                        }
                    }
                }
            }
            else
            {
                Write-Host "[Error] RegistryPlugin.TrustedDocuments.dll NOT found." -ForegroundColor Red
            }
        }
        else
        {
            Write-Host "[Error] TrustedDocuments.reb NOT found." -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
    }
}

}

#endregion Documents

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Kroll_Batch

Function KrollBatch {

# Kroll RECmd Batch File v1.20 (2022-06-01)
# https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.md
# https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/Kroll_Batch.reb
if (Test-Path "$OUTPUT_FOLDER\Registry\Registry\*.reghive") 
{
    if (Test-Path "$RECmd")
    {
        # Check if batch processing file exists
        if (Test-Path "$SCRIPT_DIR\Tools\RECmd_BatchFiles\Kroll_Batch.reb")
        {
            # Analyzing Registry Hives w/ RECmd (Kroll Batch)
            Write-Output "[Info]  Analyzing Registry Hives w/ RECmd (Kroll Batch) ... "
            New-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV" -ItemType Directory -Force | Out-Null

            # CSV
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","ntuser.dat"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "\.reghive$","UsrClass.dat"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Rename-Item -NewName {$_.Name -replace "\.reghive$",""}
            & $RECmd -d "$OUTPUT_FOLDER\Registry\Registry" --bn "$SCRIPT_DIR\Tools\RECmd_BatchFiles\Kroll_Batch.reb" --csv "$OUTPUT_FOLDER\Registry\Kroll\CSV" --csvf "Kroll.csv" > "$OUTPUT_FOLDER\Registry\Kroll\Kroll_Batch.log" 2> $null
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "ntuse")} | Rename-Item -NewName {$_.Name -replace "ntuser\.dat$",".reghive"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -match "UsrClas")} | Rename-Item -NewName {$_.Name -replace "UsrClass\.dat$",".reghive"}
            Get-ChildItem "$OUTPUT_FOLDER\Registry\Registry" | Where-Object {($_.FullName -notmatch "\.reghive$")} | Rename-Item -NewName { $PSItem.Name + ".reghive" }

            # Rename PluginDetailFiles Directory
            $Directory = (Get-ChildItem "$OUTPUT_FOLDER\Registry\Kroll\CSV" -Directory | Select-Object FullName).FullName
            if ($Directory)
            {
                if (Test-Path "$Directory")
                {
                    Rename-Item -Path "$Directory" -NewName "PluginDetailFiles" -Force
                }
            }

            # Stats
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\Kroll_Batch.log")
            {
                $Total = Get-Content "$OUTPUT_FOLDER\Registry\Kroll\Kroll_Batch.log" | Select-String -Pattern "key/value pairs"
                Write-Host "[Info]  $Total"
            }

            # XLSX

            # Kroll.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\Kroll.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\Kroll.csv").length -gt 0kb)
                {
                    New-Item "$OUTPUT_FOLDER\Registry\Kroll\XLSX" -ItemType Directory -Force | Out-Null
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\Kroll.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\Kroll.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_Batch" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, G and L-N
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["G:G"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:N"].Style.HorizontalAlignment="Center"
                    # HorizontalAlignment "Left" of columns H-J
                    $WorkSheet.Cells["H:J"].Style.HorizontalAlignment="Left"
                    }
                }
            }

            # PluginDetailFiles
            New-Item "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles" -ItemType Directory -Force | Out-Null

            # Kroll_Adobe.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Adobe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Adobe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Adobe.csv" -Delimiter "," | Sort-Object { $_.LastOpened -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_Adobe.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_Adobe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-D, F and I-J
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["I:J"].Style.HorizontalAlignment="Center"
                    # HorizontalAlignment "Center" of column H
                    $WorkSheet.Cells["H:H"].Style.HorizontalAlignment="Right"
                    # HorizontalAlignment "Center" of header of column H
                    $WorkSheet.Cells["H1:H1"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_AppCompatFlags2.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_AppCompatFlags2.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_AppCompatFlags2.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_AppCompatFlags2.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_AppCompatFlags2.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_AppCompatFlags2" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column C
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_AppPaths.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_AppPaths.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_AppPaths.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_AppPaths.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_AppPaths.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_AppPaths" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A nd D
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_BamDam.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_BamDam.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_BamDam.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_BamDam.csv" -Delimiter "," | Sort-Object { $_.ExecutionTime -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_BamDam.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_BamDam" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column C
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_CIDSizeMRU.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_CIDSizeMRU.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_CIDSizeMRU.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_CIDSizeMRU.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_CIDSizeMRU.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_CIDSizeMRU" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns C-E
                    $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_DeviceClasses.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_DeviceClasses.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_DeviceClasses.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_DeviceClasses.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_DeviceClasses.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_DeviceClasses" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_FileExts.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_FileExts.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_FileExts.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_FileExts.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_FileExts.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_FileExts" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns D-F
                    $WorkSheet.Cells["D:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_FirstFolder.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_FirstFolder.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_FirstFolder.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_FirstFolder.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_FirstFolder.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_FirstFolder" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns C-F
                    $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_JumplistData.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_JumplistData.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_JumplistData.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_JumplistData.csv" -Delimiter "," | Sort-Object { $_.ExecutedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_JumplistData.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_JumplistData" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column C
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_KnownNetworks.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_KnownNetworks.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_KnownNetworks.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_KnownNetworks.csv" -Delimiter "," | Sort-Object { $_.LastConnectedLOCAL -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_KnownNetworks.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_KnownNetworks" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-K
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_LastVisitedPidlMRU.csv --> No Excel Support

            # Kroll_MountedDevices.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_MountedDevices.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_MountedDevices.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_MountedDevices.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_MountedDevices.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_MountedDevices" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                    }
                }
            }

            # Kroll_NetworkAdapters.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_NetworkAdapters.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_NetworkAdapters.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_NetworkAdapters.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_NetworkAdapters.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_NetworkAdapters" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_OpenSavePidlMRU.csv --> No Excel Support

            # Kroll_Products.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Products.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Products.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Products.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_Products.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_Products" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-H 
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:H"].Style.HorizontalAlignment="Center"

                    }
                }
            }

            # Kroll_ProfileList.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_ProfileList.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_ProfileList.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_ProfileList.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_ProfileList.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_ProfileList" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_RecentDocs.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_RecentDocs.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_RecentDocs.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_RecentDocs.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_RecentDocs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_RecentDocs" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-D and F-I
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:I"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_Services.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Services.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Services.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Services.csv" -Delimiter "," | Sort-Object { $_.OpenedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_Services.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_Services" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B, D and F-J
                    $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_Taskband.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Taskband.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Taskband.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_Taskband.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_Taskband.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_Taskband" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns D-E
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_TaskCache.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TaskCache.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TaskCache.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TaskCache.csv" -Delimiter "," | Sort-Object { $_.CreatedOn -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_TaskCache.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_TaskCache" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_TimeZoneInfo.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TimeZoneInfo.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TimeZoneInfo.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TimeZoneInfo.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_TimeZoneInfo.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_TimeZoneInfo" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column D
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    # HorizontalAlignment "Left" of columnc C and E
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Left"
                    $WorkSheet.Cells["E:E"].Style.HorizontalAlignment="Left"
                    }
                }
            }

            # Kroll_TrustedDocuments.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TrustedDocuments.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TrustedDocuments.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TrustedDocuments.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_TrustedDocuments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_TrustedDocuments" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C and F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:C"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_TypedURLs.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TypedURLs.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TypedURLs.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_TypedURLs.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_TypedURLs.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_TypedURLs" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-E
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:E"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_UnInstall.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UnInstall.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UnInstall.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UnInstall.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_UnInstall.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_UnInstall" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, D and F-H
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_USB.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_USB.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_USB.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_USB.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_USB.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_USB" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and D-H
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["D:H"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_USBSTOR.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_USBSTOR.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_USBSTOR.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_USBSTOR.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_USBSTOR.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_USBSTOR" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-M
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:M"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_UserAccounts.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UserAccounts.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UserAccounts.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UserAccounts.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_UserAccounts.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_UserAccounts" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:AE1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A, C-O and Q-AE
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:O"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["Q:AE"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_UserAssist.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UserAssist.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UserAssist.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_UserAssist.csv" -Delimiter "," | Sort-Object { $_.LastExecuted -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_UserAssist.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_UserAssist" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns D-G
                    $WorkSheet.Cells["D:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_VolumeInfoCache.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_VolumeInfoCache.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_VolumeInfoCache.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_VolumeInfoCache.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_VolumeInfoCache.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_VolumeInfoCache" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_WindowsPortableDevices.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_WindowsPortableDevices.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_WindowsPortableDevices.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_WindowsPortableDevices.csv" -Delimiter "," | Sort-Object { $_.Timestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_WindowsPortableDevices.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_WindowsPortableDevices" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-G
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:G"].Style.HorizontalAlignment="Center"
                    }
                }
            }

            # Kroll_WordWheelQuery.csv
            if (Test-Path "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_WordWheelQuery.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_WordWheelQuery.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\Registry\Kroll\CSV\PluginDetailFiles\Kroll_WordWheelQuery.csv" -Delimiter "," | Sort-Object { $_.LastWriteTimestamp -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Registry\Kroll\XLSX\PluginDetailFiles\Kroll_WordWheelQuery.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kroll_WordWheelQuery" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A and C-F
                    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }
    else
    {
        Write-Host "[Error] RECmd.exe NOT found." -ForegroundColor Red
    }
}

}

#endregion Kroll_Batch

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region LNK

Function LNK {

# Check if YARA exists
if (Test-Path "$yara64")
{
    # Get Start Time
    $startTime_YARA = (Get-Date)

    # Simple YARA Scanner
    Write-Output "[Info]  Scanning for Windows Shortcut Files (LNK) w/ YARA [time-consuming task] ... "
    New-Item "$OUTPUT_FOLDER\LNK" -ItemType Directory -Force | Out-Null
    $LNKRule = "$SCRIPT_DIR\Rules\LNK.yar"
    & $yara64 -p 4 -r -f -w -N "$LNKRule" "$DriveLetter\forensic\ntfs" > "$OUTPUT_FOLDER\LNK\stdout.txt" 2> $null

    # -N   do not follow symlinks when scanning
    # -p   use the specified NUMBER of threads to scan a directory
    # -r   recursive search directories (follows symlinks)
    # -f   fast matching mode
    # -w   disable warnings

    # Get End Time
    $endTime_YARA = (Get-Date)

    # Scan Duration
    '[Info]  YARA scan duration: {0:hh} h {0:mm} min {0:ss} sec' -f ($endTime_YARA-$startTime_YARA)

    # Stats
    if ((Test-Path "$OUTPUT_FOLDER\LNK\stdout.txt") -And ((Get-Item "$OUTPUT_FOLDER\LNK\stdout.txt").length -gt 0kb))
    {
        Get-Content "$OUTPUT_FOLDER\LNK\stdout.txt" | ForEach-Object{($_ -split "LNK ")[-1]} > "$OUTPUT_FOLDER\LNK\LNK-Files.txt"
        Remove-Item "$OUTPUT_FOLDER\LNK\stdout.txt" -Force
        $Matches = [string]::Format('{0:N0}',(Get-Content "$OUTPUT_FOLDER\LNK\LNK-Files.txt" | Measure-Object –Line).Lines)
        Write-Host "[Info]  $Matches SHLLINK artifacts found"
    }

    # lnk_parser
    if (Test-Path "$lnk_parser")
    {
        if (Test-Path "$entropy")
        {
            Write-Output "[Info]  Parsing SHLLINK artifacts (LNK) w/ lnk_parser ... "
            New-Item "$OUTPUT_FOLDER\LNK\lnk_parser\CSV" -ItemType Directory -Force | Out-Null
            $LNK_LIST = Get-Content "$OUTPUT_FOLDER\LNK\LNK-Files.txt"

            # Add CSV Header
            Write-Output '"target_full_path","target_modification_time","target_access_time","target_creation_time","target_size","target_hostname","lnk_full_path","lnk_modification_time","lnk_access_time","lnk_creation_time"' | Out-File "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv"

            ForEach( $LNK_FILE in $LNK_LIST )
            {
                & $lnk_parser -p $LNK_FILE --output-format csv --no-headers | Out-File "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv" -Append
            }

            # Custom CSV (for Hunting Malicious LNK Files)
            $LNK_LIST | Foreach-Object {

                $File = $_
                $MD5 = Get-FileHash "$File" -Algorithm MD5 -ErrorAction SilentlyContinue
                $SHA1 = Get-FileHash "$File" -Algorithm SHA1 -ErrorAction SilentlyContinue
                $SHA256 = Get-FileHash "$File" -Algorithm SHA256 -ErrorAction SilentlyContinue
                $FileInfo = Get-Item -Force "$File" -ErrorAction SilentlyContinue
                $LNK_PARSER_JSON = (& $lnk_parser -p $File --output-format json | ConvertFrom-Json)
                $full_path = $LNK_PARSER_JSON | Select-Object @{Name="full_path"; Expression={$_.lnk_file_metadata.full_path}}
                $lnk_modification_time = $LNK_PARSER_JSON | Select-Object @{Name="lnk_modification_time"; Expression={$_.lnk_file_metadata.mtime}}
                $lnk_access_time = $LNK_PARSER_JSON | Select-Object @{Name="lnk_access_time"; Expression={$_.lnk_file_metadata.atime}}
                $lnk_creation_time = $LNK_PARSER_JSON | Select-Object @{Name="lnk_creation_time"; Expression={$_.lnk_file_metadata.ctime}}
                $LocalBasePath = $LNK_PARSER_JSON | Select-Object @{Name="local_base_path"; Expression={$_.link_info.local_base_path}}
                $HotKey = $LNK_PARSER_JSON | Select-Object @{Name="hot_key"; Expression={$_.shell_link_header.hot_key}}
                $FileEntropy = & $entropy "$File" | ForEach-Object{($_ -split "\s+")[0]}

                New-Object -TypeName PSObject -Property @{
                    "LNK Full Path" = $full_path.full_path
                    "LNK Modification Time" = $lnk_modification_time.lnk_modification_time
                    "LNK Access Time" = $lnk_access_time.lnk_access_time
                    "LNK Creation Time" = $lnk_creation_time.lnk_creation_time
                    "Target Full Path" = $LNK_PARSER_JSON.target_full_path
                    "Working Directory" = $LNK_PARSER_JSON.working_dir
                    "Arguments" = $LNK_PARSER_JSON.command_line_arguments
                    "Relative Path" = $LNK_PARSER_JSON.relative_path
                    "Icon Location" = $LNK_PARSER_JSON.icon_location
                    "Local Base Path" = $LocalBasePath.local_base_path
                    "Shortcut Key" = $HotKey.hot_key
                    "LNK Size" = $FileInfo.Length
                    MD5 = $MD5.Hash
                    SHA1 = $SHA1.Hash
                    SHA256 = $SHA256.Hash
                    Entropy = $FileEntropy
                }
            } | Select-Object "LNK Full Path","LNK Modification Time","LNK Access Time","LNK Creation Time","Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv"

            # XLSX

            # Check if PowerShell module 'ImportExcel' exists
            if (Get-Module -ListAvailable -Name ImportExcel) 
            {
                # lnk_parser.csv
                if (Test-Path "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv")
                {
                    if((Get-Item "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv").length -gt 0kb)
                    {
                        New-Item "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser.csv" -Delimiter ","
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX\lnk_parser.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "lnk_parser" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-D, F and H-J
                        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["F:F"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["H:J"].Style.HorizontalAlignment="Center"
                        # HorizontalAlignment "Center" of header of column E
                        $WorkSheet.Cells["E1:E1"].Style.HorizontalAlignment="Center"
                        }
                    }
                }

                # lnk_parser-hunt.csv
                # https://attack.mitre.org/techniques/T1547/009/
                if (Test-Path "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv")
                {
                    if((Get-Item "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv").length -gt 0kb)
                    {
                        New-Item "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX" -ItemType Directory -Force | Out-Null
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\lnk_parser\XLSX\lnk_parser-hunt.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "lnk_parser-hunt" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns B-D, K and L-P
                        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }
        }
        else
        {
            Write-Host "[Error] entropy.exe NOT found." -ForegroundColor Red
        }
    }
    else
    {
        Write-Host "[Error] lnk_parser_x86_64.exe NOT found." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] yara64.exe NOT found." -ForegroundColor Red
}

}

Function LNK_Hunt {

# Hunting Malicious LNK Files
# https://attack.mitre.org/techniques/T1547/009/
if (Test-Path "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv")
{
    if((Get-Item "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv").length -gt 0kb)
    {
        New-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV" -ItemType Directory -Force | Out-Null
        New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX" -ItemType Directory -Force | Out-Null

        # Target Full Path (lnk_parser)

        # Target Full Path: C:\Google\AutoIt3.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Google\\AutoIt3\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using AutoIt3.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-AutoIt3.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-AutoIt3.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AutoIt3.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
 
        # Target Full Path: C:\Windows\System32\cmd.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\cmd\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using cmd.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-cmd.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-cmd.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "cmd.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target FUll Path: C:\Windows\System32\mshta.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\mshta\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using mshta.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-mshta.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-mshta.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "mshta.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\msiexec.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\msiexec\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
        
        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using msiexec.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-msiexec.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-msiexec.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "msiexec.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using powershell.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-powershell.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-powershell.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "powershell.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\rundll32.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\rundll32\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using rundll32.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-rundll32.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-rundll32.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "rundll32.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\schtasks.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\schtasks\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using schtasks.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-schtasks.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-schtasks.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "schtasks.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Target Full Path: C:\Windows\System32\wscript.exe
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Target Full Path" -match "C:\\Windows\\System32\\wscript\.exe")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) using wscript.exe detected [Target Full Path] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\TargetFullPath-wscript.exe.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\TargetFullPath\TargetFullPath-wscript.exe.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "wscript.exe" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Arguments

        # Long Argument (more than 50 characters)
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {(($_."Arguments").Length -gt "50")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ Long Argument detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Argument.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Long-Argument.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Long Argument" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Long Whitespace (more than 3 characters)
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Arguments" -match "\s{3,}")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ Long Whitespace detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Long-Whitespace.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Long-Whitespace.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Long Whitespace" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Windows shortcut file (LNK) contains suspicious strings: http://
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Arguments" -match "http://")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Windows shortcut file (LNK) contains suspicious strings: http:// [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-http.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Suspicious-Strings-CommandLine-http.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "http" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Windows shortcut file (LNK) contains suspicious strings: https://
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Arguments" -match "https://")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Windows shortcut file (LNK) contains suspicious strings: https:// [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Arguments-Suspicious-Strings-CommandLine-https.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Arguments\Arguments-Suspicious-Strings-CommandLine-https.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "https" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Relative Path

        # Long Relative Path
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {($_."Relative Path" -match "\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ Long Relative Path detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\RelativePath" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\RelativePath-Long-Relative-Path.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\RelativePath\RelativePath-Long-Relative-Path.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Long Relative Path" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Misc

        # Suspicious LNK Size
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {([int]$_."LNK Size" -gt "1000")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File Size detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-LNK-Size.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc\Misc-Suspicious-LNK-Size.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Suspicious LNK Size" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Suspicious High Entropy (equal or higher than 6.5)
        $Import = Import-Csv "$OUTPUT_FOLDER\LNK\lnk_parser\CSV\lnk_parser-hunt.csv" -Delimiter "," | Where-Object {([int]$_."Entropy" -ge "6.5")} | Sort-Object { $_.lnk_modification_time -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious LNK File(s) w/ High Entropy detected [Arguments] (Count: $Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv" -NoTypeInformation

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv")
            {
                if((Get-Item "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv").length -gt 0kb)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\LNK\Hunt\CSV\Misc-Suspicious-High-Entropy.csv" -Delimiter "," | Select-Object "LNK Full Path",@{Name='LNK Modification Time';Expression={([datetime]$_."LNK Modification Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Access Time';Expression={([datetime]$_."LNK Access Time").ToString("yyyy-MM-dd HH:mm:ss")}},@{Name='LNK Creation Time';Expression={([datetime]$_."LNK Creation Time").ToString("yyyy-MM-dd HH:mm:ss")}},"Target Full Path","Working Directory","Arguments","Relative Path","Icon Location","Local Base Path","Shortcut Key","LNK Size","MD5","SHA1","SHA256","Entropy" | Sort-Object { $_."LNK Creation Time" -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\LNK\Hunt\XLSX\Misc\Misc-Suspicious-High-Entropy.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "High Entropy" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns B-D, K and L-P
                    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["K:K"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["L:P"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }
}

}

#endregion LNK

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Modules

# Status: Experimental
# The recovered files are often partial. Often the metadata isn't yet read into memory (it's read on-demand on first use from disk) or paged out. File hashes are more or less useless since you'll never recover the whole file from memory.
# But it seems that in some cases it's working better than expected and helps you to find evil.

# https://github.com/ufrisk/MemProcFS/wiki/FS_Process_Modules

Function Modules {

# Modules
Write-Host "[Info]  Analyzing Reconstructed Process Modules ... "
New-Item "$OUTPUT_FOLDER\sys\modules\CSV" -ItemType Directory -Force | Out-Null

if (!(Test-Path "$entropy"))
{
    Write-Host "[Error] entropy.exe NOT found." -ForegroundColor Red
}

$Modules = Get-ChildItem -Path "$DriveLetter\pid\*\modules\*.exe\pefile.dll" -Recurse | ForEach-Object { $_.FullName }

$Modules | Foreach-Object {

    $File = $_
    $MD5 = Get-FileHash "$File" -Algorithm MD5 -ErrorAction SilentlyContinue
    $SHA1 = Get-FileHash "$File" -Algorithm SHA1 -ErrorAction SilentlyContinue
    $SHA256 = Get-FileHash "$File" -Algorithm SHA256 -ErrorAction SilentlyContinue
    $ProcessId = $File | ForEach-Object{($_ -split "\\")[2]}
    $FullPath = $File.Replace("pefile.dll", "fullname.txt")
    $ImagePath = Get-Content -Path $FullPath
    $FileName = Split-Path $ImagePath -Leaf
    $FileInfo = Get-Item -Force "$File" -ErrorAction SilentlyContinue
    $Length = $FileInfo.Length
    $InternalName = $FileInfo.VersionInfo.InternalName
    $OriginalFileName = $FileInfo.VersionInfo.OriginalFileName
    $FileDescription = $FileInfo.VersionInfo.FileDescription
    $CompanyName = $FileInfo.VersionInfo.CompanyName
    $FileVersion = $FileInfo.VersionInfo.FileVersion
    $Language = $FileInfo.VersionInfo.Language
    $ProductName = $FileInfo.VersionInfo.ProductName

    if (Test-Path "$entropy")
    {
        $FileEntropy = & $entropy "$File" | ForEach-Object{($_ -split "\s+")[0]}
    }
    else
    {
        $FileEntropy = ""
    }

    $LastAccessTimeUtc = $FileInfo.LastAccessTimeUtc

    # CSV
    New-Object -TypeName PSObject -Property @{
        "File Name"         = $FileName
        "PID"               = $ProcessId
        "Internal Name"     = $InternalName
        "Original FileName" = $OriginalFileName
        "File Description"  = $FileDescription
        "Image Path"        = $ImagePath
        "File Version"      = $FileVersion
        "Company Name"      = $CompanyName
        "Product Name"      = $ProductName
        "Language"          = $Language
        "Bytes"             = $Length
        "File Size"         = Get-FileSize($Length)
        "File Path"         = $File
        "MD5"               = $MD5.Hash
        "SHA1"              = $SHA1.Hash
        "SHA256"            = $SHA256.Hash
        "Entropy"           = $FileEntropy
        "Last Access Time"  = $LastAccessTimeUtc
    }
} | Select-Object "File Name","PID","Internal Name","Original FileName","File Description","Image Path","File Version","Company Name","Product Name","Language","Bytes","File Size","File Path","Entropy","Last Access Time","MD5","SHA1","SHA256" | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\sys\modules\CSV\modules-draft.csv" -Encoding UTF8

# Whitelist
$Data = Get-Content "$OUTPUT_FOLDER\sys\modules\CSV\modules-draft.csv" | ConvertFrom-Csv
$Data | Where-Object {$_."Image Path" -notmatch  "\\SystemRoot\\system32\\ntoskrnl\.exe"} | Export-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Encoding UTF8
Remove-Item "$OUTPUT_FOLDER\sys\modules\CSV\modules-draft.csv" -Force

# Count
$Import = Import-Csv -Path "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter ","
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
Write-Output "[Info]  $Count Reconstructed Process Modules found"

# Check if PowerShell module 'ImportExcel' exists
if (Get-Module -ListAvailable -Name ImportExcel) 
{
    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv")
    {
        if((Get-Item "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv").length -gt 0kb)
        {
            New-Item "$OUTPUT_FOLDER\sys\modules\XLSX" -ItemType Directory -Force | Out-Null
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\sys\modules\XLSX\modules.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Modules" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-B, G-J and N-R
            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["G:J"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["N:R"].Style.HorizontalAlignment="Center"
            # HorizontalAlignment "Center" of columns K-L
            $WorkSheet.Cells["K:L"].Style.HorizontalAlignment="Right"
            # HorizontalAlignment "Center" of header of columns K-L
            $WorkSheet.Cells["K1:L1"].Style.HorizontalAlignment="Center"

            # Threat Hunting

            # Fields are missing / empty (W/ Rule Priority)

            # "Internal Name" and "Original FileName" and "File Description" and "Company Name" --> Red
            $HighColor = [System.Drawing.Color]::FromArgb(255,0,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=AND($C1="",$D1="",$E1="",$H1="")' -BackgroundColor $HighColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {(($_."Internal Name" -eq "") -and ($_."Original FileName" -eq "") -and ($_."File Description" -eq "") -and ($_."Company Name" -eq ""))}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Missing Internal Name, Original FileName, File Description, and Company Name detected [Modules] (Count: $Count)" -ForegroundColor Red
            }

            # "File Description" or "Company Name": Empty --> Orange
            $MediumColor = [System.Drawing.Color]::FromArgb(255,192,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=OR($E1="",$H1="")' -BackgroundColor $MediumColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {(($_."File Description" -eq "") -or ($_."Company Name" -eq ""))}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Missing File Description and/or Company Name detected [Modules] (Count: $Count)" -ForegroundColor Yellow
            }

            # "Internal Name" or "Original FileName": Empty --> Yellow
            $LowColor = [System.Drawing.Color]::FromArgb(255,255,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' '=OR($C1="",$D1="")' -BackgroundColor $LowColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {(($_."Internal Name" -eq "") -or ($_."Original FileName" -eq ""))}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Missing Internal Name and/or Original FileName detected [Modules] (Count: $Count)" -ForegroundColor Yellow
            }

            # Mismatch on Original FileName
            $LowColor = [System.Drawing.Color]::FromArgb(255,255,0)
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D2:D$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$A2<>$D2' -BackgroundColor $LowColor
            $Import = Import-Csv "$OUTPUT_FOLDER\sys\modules\CSV\modules.csv" -Delimiter "," | Where-Object {($_."File Name" -notlike $_."Original FileName")}
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Mismatch on Original FileName detected [Modules] (Count: $Count)" -ForegroundColor Yellow
            }

            }
        }
    }
}

}

#endregion Modules

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region SecureArchive

Function SecureArchive {

# Creating Secure Archive
if (Test-Path "$7za") 
{
    if (Test-Path "$OUTPUT_FOLDER") 
    {
        Write-Output "[Info]  Preparing Secure Archive Container ... "
        & $7za a -mx5 -mhe "-p$PASSWORD" -t7z "$OUTPUT_FOLDER.7z" "$OUTPUT_FOLDER\*" > $null 2>&1
    }

    # Archive Size
    $Length = (Get-Item -Path "$OUTPUT_FOLDER.7z").Length
    $Size = Get-FileSize($Length)
    Write-Output "[Info]  Archive Size: $Size"

    # Cleaning up
    if (Test-Path "$OUTPUT_FOLDER")
    {
        Get-ChildItem -Path "$OUTPUT_FOLDER" -Recurse | Remove-Item -Force -Recurse
        Remove-Item "$OUTPUT_FOLDER" -Force
    }
}
else
{
    Write-Host "[Error] 7za.exe NOT found." -ForegroundColor Red
}

}

#endregion SecureArchive

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

Function Footer {

# Shutting Down (Unmount)
if (Get-Process -Name "MemProcFS" -ErrorAction SilentlyContinue)
{
    # MessageBox UI
    $Form = New-Object System.Windows.Forms.Form
    $Form.TopMost = $true
    $MessageBody = "Happy Hunting!`n`nMemProcFS - The Memory Process File System by Ulf Frisk`nhttps://github.com/ufrisk/MemProcFS`n`nPress OK to shutdown virtual file system (Unmount)`n`nNote: Elasticsearch will also be stopped."
    $MessageTitle = "MemProcFS-Analyzer.ps1 (https://lethal-forensics.com/)"
    $ButtonType = "OK"
    $MessageIcon = "Info"
    $Result = [System.Windows.Forms.MessageBox]::Show($Form, $MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

    if ($Result -eq "OK" ) 
    {
        Write-Output "[Info]  Shutting Down (Unmount) ..."
        Start-Sleep -Seconds 1

        # MemProcFS
        [void] [System.Reflection.Assembly]::LoadWithPartialName("'Microsoft.VisualBasic")
        [void] [System.Reflection.Assembly]::LoadWithPartialName("'System.Windows.Forms")
        $Process = Get-Process | Where-Object {$_.Name -eq "MemProcFS"}
        [Microsoft.VisualBasic.Interaction]::AppActivate($Process.ID)
        [System.Windows.Forms.SendKeys]::SendWait("^{c}")
        [System.Windows.Forms.SendKeys]::SendWait("^{c}")

        # Kibana
        if ($Kibana_Termination)
        {
            $Kibana_Termination.CloseMainWindow() > $null
        }

        # Elasticsearch
        if ($Elasticsearch_Termination)
        {
            $Elasticsearch_Termination.CloseMainWindow() > $null
        }
    }
}

# Set Progress Preference back to default
$ProgressPreference = 'Continue'

# Stop logging
Write-Output ""
Stop-Transcript

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"
$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Set Windows Title back to default
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Main

# Main
Header
Updater
#Elasticsearch
MicrosoftDefender
MemProcFS
#ELKImport
ClamAVUpdate
ClamAV
Documents
KrollBatch
#LNK
#LNK_Hunt
Modules
SecureArchive
Footer

#endregion Main