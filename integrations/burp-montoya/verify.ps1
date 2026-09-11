[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MontoyaApiJar
)

$ErrorActionPreference = 'Stop'
$apiJar = [System.IO.Path]::GetFullPath($MontoyaApiJar)
if (-not (Test-Path -LiteralPath $apiJar -PathType Leaf)) {
    throw 'MontoyaApiJar must name an existing local JAR.'
}

$javac = Get-Command javac -ErrorAction Stop
$java = Get-Command java -ErrorAction Stop
$node = Get-Command node -ErrorAction Stop
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("last-aperture-burp-verify-" + [Guid]::NewGuid().ToString('N'))
$extensionJar = Join-Path $tempRoot 'last-aperture-burp-montoya.jar'
$classRoot = Join-Path $tempRoot 'test-classes'
$emptySourceRoot = Join-Path $tempRoot 'empty-sourcepath'
$capture = Join-Path $tempRoot 'sanitized.har'
$testSource = Join-Path $PSScriptRoot 'src\test\java\dev\lastaperture\burp\ExporterSelfTest.java'
$pathSeparator = [System.IO.Path]::PathSeparator

New-Item -ItemType Directory -Path $classRoot | Out-Null
New-Item -ItemType Directory -Path $emptySourceRoot | Out-Null
try {
    & (Join-Path $PSScriptRoot 'build.ps1') -MontoyaApiJar $apiJar -OutJar $extensionJar | Out-Null

    $compileClasspath = "$apiJar$pathSeparator$extensionJar"
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $compileDiagnostics = (& $javac.Source --release 17 -encoding UTF-8 -proc:none -implicit:none --source-path $emptySourceRoot -classpath $compileClasspath -d $classRoot $testSource 2>&1 | Out-String)
        $compileExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if (-not [string]::IsNullOrWhiteSpace($compileDiagnostics)) {
        [Console]::Error.Write($compileDiagnostics)
    }
    if ($compileDiagnostics -match '(?im)An exception has occurred in the compiler|^\s*Error:\s*internal error:') {
        throw 'conformance harness javac reported an internal compiler exception.'
    }
    if ($compileExitCode -ne 0) { throw "conformance harness compilation failed with exit code $compileExitCode." }

    $runtimeClasspath = "$apiJar$pathSeparator$extensionJar$pathSeparator$classRoot"
    & $java.Source -ea -classpath $runtimeClasspath dev.lastaperture.burp.ExporterSelfTest $capture
    if ($LASTEXITCODE -ne 0) { throw "conformance harness failed with exit code $LASTEXITCODE." }

    & $node.Source (Join-Path $PSScriptRoot 'scripts\verify-har.mjs') $capture
    if ($LASTEXITCODE -ne 0) { throw "HAR import verification failed with exit code $LASTEXITCODE." }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
