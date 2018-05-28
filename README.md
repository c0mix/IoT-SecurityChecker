# IoT-SecurityChecker
[![python](https://img.shields.io/badge/python-3.4-blue.svg)](https://www.python.org/downloads/)
![OS](https://img.shields.io/badge/OS-Ubuntu-orange.svg)

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
![alt text](/resources/images/architettura.png "Architecture")

1. **The Knowledge DB** file (here you can see a small [sample](/resources/iotDetectionKeyword.txt)) contains all the information and data that have been acquired
during the knowledge-building phase of the thesis. It can be updated on the
fly as new information are collected (for example looking for a new IoT product, exploit or manufacturer).
2. **The Scanner** manages and starts the hosts discovery process, you can find all the ports and configuration in the dedicated [class](/scanners/Masscan_Scanner.py). The scanning operations are run using masscan (https://github.com/robertdavidgraham/masscan).
3. **Bruteforcers classes** are capable of executing a dictionary attack on the following services: ftp,
telenet, ssh, http basic. The dictionary provided as wordlist are built based on the knowledge (in this repo you can find only small wordlists used for demo purpose).
4. **Exploit classes** are able to execute a set of exploits that addresses well-know IoT
vulnerabilities. As for dictionary, the exploits list derives from the knowledge.
The available exploits are 5 (plus one not public):
    - Cisco-PVC-2300 : the web camera Cisco PVC-2300 is affected by several
vulnerabilities that may allow a unauthenticated user to login and access to
multiple functionalities. The developed exploit tries to login and download
the device configuration to read username and password
    - Dlink : a set of Dlink webcams are affected by different vulnerabilities that
mainly permits OS command injection. The developed exploit test each one
of these vulnerabilities
    - h264-dvr-RCE : a set of devices identified by the caption  that
have been used by several companies may suffer Remote Command Injection. This vulnerability allows an attacker to execute any command on the
vulnerable device. The exploit verifies the vulnerabilities attempting to crete
a file on the target device.
    - Humax-HG100R: the Humax Wifi Router is vulnerable to Authentication
Bypass attack by sending specific crafted request to the management console.
If the console is public exposed an attacker can exploit it and may get access
to confidential information.
    - Rom-0 : a set of network appliances from companies such as ZTE, TP-Link,
ZynOS and Huawei are vulnerable to Authentication Bypass attacks. An
attacker can access confidential data sending a crafted HTTP request to the
/rom=o resource
    - TV-IP410wn: Trendnet TV-IP410WN webcams are vulnerable to Remote
Command Execution attacks. The developed exploits verifies the vulnerability by executing the ls command on the target device.
    - CVE-2017-17101: several webcams and baby monitors from Apexis company are
vulnerable to Credential Injection. An attacker by using a crafted http request may obtain full admin access. This vulnerability has been discovered
during this work and has been marked by CVE-2017-17101.
5. **The Engine** manages all operations and exchanges of information through all
modules. The user can set up the scan and then the Engine is in charge of
starting the scanning, redirect data to parser and then DBs, setting up the
execution of the Exploiter and Authenticator based on the results.
6. **Utils** provides a series of functionality, for example validate input and output.
7. **The Parser classes** handle and filter outputs from many different tools integrated in the software and create also a human readable output.

## Setup & Run
1. Install masscan, following the instruction (https://github.com/robertdavidgraham/masscan) and optionally patch it in order to add the timestamp field inside the scan output (https://hml.io/2016/01/20/masscan-logging-demystified/)
2. Clone this repo: 
```bash
git clone https://github.com/c0mix/IoT-SecurityChecker.git
cd IoT-SecurityChecker
```
3. Install all the decencies by running: 
```bash
pip3 install -r requirements.txt
```
4. Configure and tune your knowledge base and your wordlists by editing the following files:
```
/resources/iotDetectionKeyword.txt
/resources/wordlists/FTP_credentials.txt
/resources/wordlists/HTTP_credentials.txt
/resources/wordlists/SSH_credentials.txt
/resources/wordlists/Telnet_credentials.txt
```
5. Run the program giving sudo privileges or with root user:
```bash
sudo python3 IoT-SecurityChecker.py <target> <options>
```

### Case Study
We run the IoT Security Checker in a custom scenario that have been built
specifically to satisfy the tools characteristics. The following figure shows the networks
with all nodes. 
![alt text](/resources/images/testcase.png "Test Case Lab")
The experimental scenario is composed by a private network containing the scanner node, a vulnerable wireless cam and a Cloud Nas. All nodes
access Internet through a Netgear router. A Wireless cam and a remote router are
added to the scenario and reachable from the private network through Internet.
The IoT Security Checker was executed from the scanner node with following
command:
```bash
sudo python3 IoT-SecurityChecker.py target.txt -m 300 -w 15 -E ALL -B ALL -T 2 -o result.csv
```
Where `target.txt` contains three different targets: the private network (192.168.0.0/24) and the two public IPs (109.115.179.138, 13.113.110.137).
`-m 300 -w 15` are specific parameters to instruct masscan on how to run the scan.
In details, they require to use no more than 300 packages for second and wait
15 seconds once the scan is done to get the results.
`-B ALL -E ALL -T 2` instructs Authenticator (-B) and Exploiter (-E) to run
all possibile authentications and exploits but using a maximum of 2 threads.
`-o results.csv` specifies to store the final results in csv format in `result.csv` file.

| IP              |   Port   |   Service   |   Module               | Notes                                          
|:---------------|:--:|:-------:| :--------------------:| :--------------------------------------------------------- 
| 192.168.0.10    | 23 | Telnet  | TelnetAuthenticator  | Telnet Access found username: adm password:                
| 192.168.0.9     | 23 | Telnet  | TelnetAuthenticator  | Telnet Access found username: adm password:                
| 192.168.0.9     | 22 | SSH     | SSHAuthenticator     | SSH Access found username: test password: admin            
| 192.168.0.9     | 21 | FTP     | FTPAuthenticator     | FTP Access found username: anonymous password:             
| 192.168.0.9     | 21 | FTP     | FTPAuthenticato      | FTP Access found username: user password: test             
| 13.113.110.137  | 81 | HTTP    | HttpAuthenticator    | Http Access found username: test password: test            
| 109.115.179.138 | 80 | HTTP    | Rom-0                | http://109.115.179.138:80/rom-0                            
| 192.168.0.10    | 80 | HTTP    | CVE-2017-17101       | http://192.168.0.10:80 new credentials are admin:hacked 


## Reference & Thanks
- I wanna thank [Enrico Milanese](https://www.linkedin.com/in/enricomilanese/) who inspired and really helped me with this project.
- Thanks to researchers of the University of Milan [Sesar Lab](http://sesar.di.unimi.it/), in particular Prof. Marco Anisetti, Dott. Filippo Gaudenzi and Prof. Claudio Ardagna)
- Many thanks to all the researchers that inspired me with their work and effort to make these devices safer (see the link in the main feature section)


[1]: https://github.com/erforschr/http-auth-bruteforcer
[2]: https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf
[3]: https://www.coresecurity.com/advisories/d-link-ip-cameras-multiple-vulnerabilities
[4]: http://www.kerneronsec.com/2016/02/remote-code-execution-in-cctv-dvrs-of.html
[5]: https://www.cvedetails.com/cve/CVE-2017-11435/
[6]: http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/
[7]: https://github.com/robertdavidgraham/masscan
[8]: https://medium.com/@lorenzo.comi93/break-into-2k-ip-camera-cb65bbac9e8c
## Disclaimer
This software was not tested in a real "wild" environment, use at your own risk! 