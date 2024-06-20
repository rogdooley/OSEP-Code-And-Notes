
### Windbg Commands

| Command   | Description                                                       |
| --------- | ----------------------------------------------------------------- |
| x         | examine all symbols that match a given string (eg `x amsi!Amsi*`) |
| bg        | set a break point                                                 |
| g         | let process continue                                              |
| r         | dump resister                                                     |
| r r\<reg> | dump a particular register value                                  |
| u         | unassemble (go to that memory address)                            |

### Analyzing AmsiScanBuffer

```c
HRESULT AmsiScanBuffer(
  HAMSICONTEXT amsiContext,
  PVOID buffer,
  ULONG length,
  LPCWSTR contentName,
  HAMSISESSION amsiSession,
  AMSI_RESULT *result
);
```

- launch Powershell window
- launch Windbg
- attach Windbg to Powershell session
- in Windbg set a break point for AmsiScanBuffer
```cmd
bp Amsi!AmsiScanBuffer
```
- allow the powershell interactivity to continue using `g` in Windbg
- on the powershell cmd line, type `'amsituils` to trigger AMSI
```powershell
'amsiutils'
```
![[Pasted image 20240620102817.png]]
- find the return instruction is c3
- ![[Pasted image 20240620113152.png]]
- ![[Pasted image 20240620115410.png]]
- apparently we want to overwrite the address highlighted in gray (TODO: figure out why exactly)
- in Windbg `u 00007ffd72e9387b` to move to that address
- ![[Pasted image 20240620115618.png]]
- overwrite with this command `eb 00007ffd72e9387b c3 90 90` (90 are nop)
- ![[Pasted image 20240620115805.png]]
- now that address is altered to `ret` instead of `mov edi,r8d`

### Websites viewed for reference

- https://thalpius.com/2021/10/14/microsoft-windows-antimalware-scan-interface-bypasses/
- https://www.rewterz.com/blog/how-i-bypassed-amsi-statically-using-windbg
- https://rxored.github.io/post/csharploader/bypassing-amsi-with-csharp/#amsiscanbuffer
- https://medium.com/@sam.rothlisberger/amsi-bypass-memory-patch-technique-in-2024-f5560022752b
