export TARGET=10.10.209.99
mkdir -p ~/CTFs/silverplatter
cd ~/CTFs/silverplatter

export TARGET=10.10.4.109
cd ~/CTFs/silverplatter

# Enumeration
<details>

<summary> 

```
nmap -p$(nmap -p- --min-rate=1000 -T4 $TARGET | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) -sV -Pn $TARGET -oA ${TARGET}
```

</summary>

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-02 19:38 EDT
Nmap scan report for 10.10.209.99
Host is up (0.16s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
8080/tcp open  http-proxy
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=4/2%Time=67EDCA76%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close
SF:\r\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Wed
SF:,\x2002\x20Apr\x202025\x2023:38:29\x20GMT\r\n\r\n<html><head><title>Err
SF:or</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTPO
SF:ptions,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\n
SF:Content-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Wed,\x2
SF:002\x20Apr\x202025\x2023:38:29\x20GMT\r\n\r\n<html><head><title>Error</
SF:title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPReque
SF:st,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\x
SF:20Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nCont
SF:ent-Type:\x20text/html\r\nDate:\x20Wed,\x2002\x20Apr\x202025\x2023:38:3
SF:0\x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\x
SF:20Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Gen
SF:ericLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x20
SF:0\r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(
SF:SSLSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:
SF:\x200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTTP
SF:/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x
SF:20close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,
SF:42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConne
SF:ction:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPDS
SF:tring,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\
SF:nConnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n
SF:");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.25 seconds
```

</details>

We see 3 ports are open - 22, 80, 8080. Without ssh credentials and spending days brute forcing, we'll look into 80 and 8080. Most likely will be http so we enumerate the port with http scripts.

<details>

<summary> 
	
```
nmap -Pn -sV -p 80 "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oX ${TARGET}_http_script.xml $TARGET
```
	
</summary>


```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-02 19:38 EDT
Nmap scan report for 10.10.209.99
Host is up (0.16s latency).

Bug in http-security-headers: no string output.
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-methods: 
|_  Supported Methods: GET HEAD
| http-traceroute: 
|_  Possible reverse proxy detected.
|_http-mobileversion-checker: No mobile version detected.
|_http-malware-host: Host appears to be clean
| http-comments-displayer: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.209.99
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 637
|     Comment: 
|         /* Image */
|     
|     Path: http://10.10.209.99:80/assets/js/util.js
|     Line number: 299
|     Comment: 
|         
|         
|         
|                */
|     
|     Path: http://10.10.209.99:80/assets/js/util.js
|     Line number: 3
|     Comment: 
|         
|         
|         
|                */
|     
|     Path: http://10.10.209.99:80/
|     Line number: 45
|     Comment: 
|         <!-- Intro -->
|     
|     Path: http://10.10.209.99:80/
|     Line number: 337
|     Comment: 
|         <!-- Scripts -->
|     
|     Path: http://10.10.209.99:80/
|     Line number: 37
|     Comment: 
|         <!--<li><a href="#elements">Elements</a></li>-->
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 930
|     Comment: 
|         /* Table */
|     
|     Path: http://10.10.209.99:80/assets/js/main.js
|     Line number: 1
|     Comment: 
|         
|         
|         
|         
|         */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 1234
|     Comment: 
|         /* Header */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 3
|     Comment: 
|         /*
|               Dimension by HTML5 UP
|               html5up.net | @ajlkn
|               Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
|         */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 1622
|     Comment: 
|         /* Footer */
|     
|     Path: http://10.10.209.99:80/
|     Line number: 60
|     Comment: 
|         <!-- About -->
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 111
|     Comment: 
|         /* Type */
|     
|     Path: http://10.10.209.99:80/assets/js/browser.min.js
|     Line number: 1
|     Comment: 
|         /* browser.js v1.0.1 | @ajlkn | MIT licensed */
|     
|     Path: http://10.10.209.99:80/
|     Line number: 327
|     Comment: 
|         <!-- Footer -->
|     
|     Path: http://10.10.209.99:80/
|     Line number: 70
|     Comment: 
|         <!-- Contact -->
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 1500
|     Comment: 
|         /* Main */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 579
|     Comment: 
|         /* Box */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 302
|     Comment: 
|         /* Form */
|     
|     Path: http://10.10.209.99:80/assets/js/util.js
|     Line number: 521
|     Comment: 
|         
|         
|         
|         
|                */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 1106
|     Comment: 
|         /* BG */
|     
|     Path: http://10.10.209.99:80/assets/js/jquery.min.js
|     Line number: 1
|     Comment: 
|         /*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */
|     
|     Path: http://10.10.209.99:80/assets/js/util.js
|     Line number: 37
|     Comment: 
|         
|         
|         
|         
|                */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 998
|     Comment: 
|         /* Button */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 74
|     Comment: 
|         /* Basic */
|     
|     Path: http://10.10.209.99:80/
|     Line number: 17
|     Comment: 
|         <!-- Wrapper -->
|     
|     Path: http://10.10.209.99:80/
|     Line number: 83
|     Comment: 
|         <!-- Elements -->
|     
|     Path: http://10.10.209.99:80/assets/js/breakpoints.min.js
|     Line number: 1
|     Comment: 
|         /* breakpoints.js v1.0 | @ajlkn | MIT licensed */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 600
|     Comment: 
|         /* Icon */
|     
|     Path: http://10.10.209.99:80/
|     Line number: 52
|     Comment: 
|         <!-- Work -->
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 773
|     Comment: 
|         /* Actions */
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 722
|     Comment: 
|         /* List */
|     
|     Path: http://10.10.209.99:80/
|     Line number: 20
|     Comment: 
|         <!-- Header -->
|     
|     Path: http://10.10.209.99:80/
|     Line number: 334
|     Comment: 
|         <!-- BG -->
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 895
|     Comment: 
|         /* Icons */
|     
|     Path: http://10.10.209.99:80/
|     Line number: 2
|     Comment: 
|         
|         
|         
|         
|         -->
|     
|     Path: http://10.10.209.99:80/
|     Line number: 42
|     Comment: 
|         <!-- Main -->
|     
|     Path: http://10.10.209.99:80/assets/css/main.css
|     Line number: 1179
|     Comment: 
|_        /* Wrapper */
|_http-exif-spider: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-feed: Couldn't find any feeds.
| http-headers: 
|   Server: nginx/1.18.0 (Ubuntu)
|   Date: Wed, 02 Apr 2025 23:38:16 GMT
|   Content-Type: text/html
|   Content-Length: 14124
|   Last-Modified: Wed, 01 May 2024 16:59:11 GMT
|   Connection: close
|   ETag: "663274df-372c"
|   Accept-Ranges: bytes
|   
|_  (Request type: HEAD)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-errors: Couldn't find any error pages.
|_http-date: Wed, 02 Apr 2025 23:38:11 GMT; -3s from local time.
| http-vhosts: 
|_128 names had status 200
| http-sitemap-generator: 
|   Directory structure:
|     /
|       Other: 1
|     /assets/css/
|       css: 2
|     /assets/js/
|       js: 5
|     /images/
|       jpg: 3
|   Longest directory structure:
|     Depth: 2
|     Dir: /assets/js/
|   Total files found (by extension):
|_    Other: 1; css: 2; jpg: 3; js: 5
|_http-chrono: Request times for /; avg: 662.06ms; min: 542.93ms; max: 726.51ms
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.tenable.com/plugins/nessus/55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://www.securityfocus.com/bid/49303
|_http-referer-checker: Couldn't find any cross-domain scripts.
| http-enum: 
|_  /README.txt: Interesting, a readme.
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 369.09 seconds
```

</details>

A nginx web server running 1.18.0. Nothing special from the comments as they are just dividers for each sections. 

Some of the directory structure output seems interesting, will note for later. 

CVE2011-3192 for DoS but we're here to root so I'm ignoring this.

http-enum shows a /README.txt, will note for later.

Nothing special for User Agents.

Looks like we have the following tasks for port 80:
- Check directory structure for interesting folders and files
- Check /README.txt for any notes of use
- Visit the website directly

Checking directories comes up with all "403 forbidden"

README.txt shows possible use of HTML5 UP and some credits. Not sure if this is the right direction.

Home page of $TARGET is a HTML5 UP design screen:
![83b84da402ca2d288f48e73abd2b70e5.png](../../../_resources/83b84da402ca2d288f48e73abd2b70e5.png)

Intro:
![8ed03d2ed8feb6a95c9b69c9f43aadd5.png](../../../_resources/8ed03d2ed8feb6a95c9b69c9f43aadd5.png)

Work:
![7f8e7afb5515e36336d7533c89873002.png](../../../_resources/7f8e7afb5515e36336d7533c89873002.png)

About:
![b864f947456eaba323b06cd377df18ec.png](../../../_resources/b864f947456eaba323b06cd377df18ec.png)

Contact:
![39c1d55a03b12a252e52edcbfa4c5ccd.png](../../../_resources/39c1d55a03b12a252e52edcbfa4c5ccd.png)

A lot of references to "1337" and "h4x0r" and a youtube channel hyperlinked with nothing. Tyler Ramsbey seems to be a possible user. Maybe tramsbey, tylerr, tyler.r, t.ramsbey? 

Contact shows "Silverpeas" and a username of "scr1ptkiddy". Source page shows that the 4 buttons under are supposed to have icons of social media websites.

Also shown by the source code are additional parts of the html code not being used such as a submit form, radio buttons, and other examples. Trying to access this with #elements as you can find it as an article id. For example: 10.10.209.99/#elements.  Submitting forms return with 405 Not Allowed.

Next is to use FFuF to fuzz search 8080. port 80 server was slightly scanned by nmap script so if I can't find anything on 8080, I'll revisit.

<details>
<summary>

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.209.99:8080/FUZZ
```

</summary>

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.209.99:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

website                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 163ms]
console                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 159ms]
:: Progress: [220559/220559] :: Job [1/1] :: 254 req/sec :: Duration: [0:15:07] :: Errors: 0 ::
```
	
</details>

My Box timed out here so IPs won't match up

Trying to access these directories match the 302 status, leading to a redirect. 8080 leads to a 404 not found. /console leads to another 404. /website leads to a Forbidden.

Tried multiple wordlists under Web-Content. directory-list-2.3-medium, dsstorewordlist, common, raft-medium-words-lowercast, big, raft-large-words-lowercase, nginx,  Apache. I found a new directory named weblib but this also returns Forbidden

Trying the much larger /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt got me silverpeas which ends up with a login page. There was that "scr1ptkiddy" account found possibly from earlier, I'll try to brute force that tomorrow as it's late now (0230~ EST)

Found some credentials:
tim
cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol

# Exploitation

# Post Exploitation

# Priv Esc
