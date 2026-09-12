$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class LastApertureDurableMove {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MoveFileExW(
        string existingFileName,
        string newFileName,
        int flags
    );
}
'@

while (($line = [Console]::In.ReadLine()) -ne $null) {
    $requestId = $null
    try {
        $request = $line | ConvertFrom-Json
        $requestId = $request.id
        if (($request.source -isnot [string]) -or ($request.destination -isnot [string])) {
            throw [System.ArgumentException]::new('source and destination must be strings')
        }
        $flags = 0x8 # MOVEFILE_WRITE_THROUGH
        if ($request.replace -eq $true) {
            $flags = $flags -bor 0x1 # MOVEFILE_REPLACE_EXISTING
        }
        $moved = [LastApertureDurableMove]::MoveFileExW(
            $request.source,
            $request.destination,
            $flags
        )
        if (-not $moved) {
            $win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $message = [ComponentModel.Win32Exception]::new($win32Error).Message
            $response = @{
                id = $requestId
                ok = $false
                win32_error = $win32Error
                message = $message
            }
        } else {
            $response = @{ id = $requestId; ok = $true }
        }
    } catch {
        $response = @{
            id = $requestId
            ok = $false
            win32_error = $null
            message = $_.Exception.Message
        }
    }
    [Console]::Out.WriteLine(($response | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
}
