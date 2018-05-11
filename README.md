# IoT-SecurityChecker
This software was developed as part of my Master degree thesis project @ University of Milan in order to automate the discovery and exploitation process of IoT devices. This project aims to be a starting point for further research, a framework to be enriched with new modules, exploits and techniques. Actually IoT-SecurityChecker is able to identify any device present inside a network using a port scan application (masscan), perform different brute-force attacks and probe some IoT exploits against the identified targets to validate the presence of known vulnerabilities.
### Main Features
Below is provided a list of the main activity and probe that IoT-SecurityCheker is able to perform:

- Service discovery and banner grabbing with [masscan][7]
- SSH Bruteforce
- FTP Bruteforce
- TELNET Bruteforce
- HTTP [Bruteforce][1]
- Cisco-PVC-2300 [Exploit][2]
- DLink dcs-lig-httpd [Exploit][3]
- h264_dvr_rce Exploit [Exploit][4]
- Humax HG100R-* Authentication Bypass [Exploit][5]
- /rom-0 information disclosure [Exploit][6]
- Trendnet TV-IP410WN [Exploit][2]
- CVE-2017-17101 [Exploit][8] (tested but NOT IN THE SOURCE due to responsible disclosure)
 
### Architecture
![alt text](https://github.com/c0mix/IoT-SecurityChecker/resources/images/architettura.png "Architecture")

### Case Study



## Setup


## Execute

## Screenshots & Video Demo

## Reference & Thanks


[1]: https://github.com/erforschr/http-auth-bruteforcer
[2]: https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf
[3]: https://www.coresecurity.com/advisories/d-link-ip-cameras-multiple-vulnerabilities
[4]: http://www.kerneronsec.com/2016/02/remote-code-execution-in-cctv-dvrs-of.html
[5]: https://www.cvedetails.com/cve/CVE-2017-11435/
[6]: http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/
[7]: https://github.com/robertdavidgraham/masscan
[8]: https://medium.com/@lorenzo.comi93/break-into-2k-ip-camera-cb65bbac9e8c
## Disclaimer