
- PInvoke.Thread
```csharp
The call is ambiguous between the following methods or properties: 'PInvoke.CreateThread(SECURITY_ATTRIBUTES?, UIntPtr, LPTHREAD_START_ROUTINE, void*, THREAD_CREATION_FLAGS, uint*)' and 'PInvoke.CreateThread(SECURITY_ATTRIBUTES*, UIntPtr, LPTHREAD_START_ROUTINE, void*, THREAD_CREATION_FLAGS, uint*)'
```

```cpp
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```
- 
```csharp
PInvoke.CreateThread(
					
)
```