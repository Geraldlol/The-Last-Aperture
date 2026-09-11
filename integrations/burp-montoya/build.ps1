[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MontoyaApiJar,

    [string]$OutJar = (Join-Path $PSScriptRoot 'dist\last-aperture-burp-montoya.jar')
)

$ErrorActionPreference = 'Stop'
$apiJar = [System.IO.Path]::GetFullPath($MontoyaApiJar)
$outputJar = [System.IO.Path]::GetFullPath($OutJar)
$candidateJar = $outputJar + '.partial.' + [Guid]::NewGuid().ToString('N')
$sourceRoot = Join-Path $PSScriptRoot 'src\main\java'
$manifest = Join-Path $PSScriptRoot 'MANIFEST.MF'
$buildRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("last-aperture-burp-build-" + [Guid]::NewGuid().ToString('N'))
$classRoot = Join-Path $buildRoot 'classes'
$emptySourceRoot = Join-Path $buildRoot 'empty-sourcepath'

if (-not (Test-Path -LiteralPath $apiJar -PathType Leaf)) {
    throw 'MontoyaApiJar must name an existing local JAR.'
}
if ([System.IO.Path]::GetExtension($apiJar) -ne '.jar') {
    throw 'MontoyaApiJar must end in .jar.'
}
if (Test-Path -LiteralPath $outputJar) {
    throw 'Output already exists. Builds never replace files.'
}

$javac = Get-Command javac -ErrorAction Stop
$jar = Get-Command jar -ErrorAction Stop
$javaVersion = (& $javac.Source -version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $javaVersion -notmatch 'javac\s+(\d+)') {
    throw 'Unable to determine the javac version.'
}
$major = [int]$Matches[1]
if ($major -lt 17 -or $major -gt 21) {
    throw "Use JDK 17 through 21 to build a Burp-compatible extension; found $javaVersion."
}

New-Item -ItemType Directory -Path $classRoot | Out-Null
New-Item -ItemType Directory -Path $emptySourceRoot | Out-Null
New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($outputJar)) -Force | Out-Null

try {
    $sources = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter '*.java' | Sort-Object FullName | ForEach-Object FullName)
    if ($sources.Count -eq 0) { throw 'No Java sources found.' }
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $compileDiagnostics = (& $javac.Source --release 17 -encoding UTF-8 -proc:none -implicit:none --source-path $emptySourceRoot -classpath $apiJar -d $classRoot @sources 2>&1 | Out-String)
        $compileExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if (-not [string]::IsNullOrWhiteSpace($compileDiagnostics)) {
        [Console]::Error.Write($compileDiagnostics)
    }
    if ($compileDiagnostics -match '(?im)An exception has occurred in the compiler|^\s*Error:\s*internal error:') {
        throw 'javac reported an internal compiler exception; no JAR was accepted.'
    }
    if ($compileExitCode -ne 0) { throw "javac failed with exit code $compileExitCode." }
    if (Test-Path -LiteralPath (Join-Path $classRoot 'burp')) {
        throw 'The supplied classpath leaked Burp API classes into the build.'
    }

    & $jar.Source --create --file $candidateJar --manifest $manifest -C $classRoot .
    if ($LASTEXITCODE -ne 0) { throw "jar failed with exit code $LASTEXITCODE." }
    $entries = @(& $jar.Source --list --file $candidateJar)
    if ($LASTEXITCODE -ne 0 -or $entries -contains 'burp/' -or $entries -notcontains 'dev/lastaperture/burp/LastApertureBurpExtension.class') {
        throw 'Built JAR contents failed the extension isolation check.'
    }
    [System.IO.File]::Move($candidateJar, $outputJar)
    Write-Output $outputJar
}
finally {
    if (Test-Path -LiteralPath $candidateJar) {
        Remove-Item -LiteralPath $candidateJar -Force
    }
    if (Test-Path -LiteralPath $buildRoot) {
        Remove-Item -LiteralPath $buildRoot -Recurse -Force
    }
}
