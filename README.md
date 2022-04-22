<h1>HawkEye-CyberDefenders WriteUp</h1> 

**Scenario:**
An accountant at your organization received an email regarding an invoice with a download link. Suspicious network traffic was observed shortly after opening the email. As a SOC analyst, investigate the network trace and analyze exfiltration attempts.

[Challenge Link](https://cyberdefenders.org/blueteam-ctf-challenges/91)

<h2>main tools:</h2>

1.wireshark

2.iplocation.net 

3.https://whois.domaintools.com

4.https://www.virustotal.com
<h3>CHALLENGE QUESTIONS</h3>

**Q1**. How many packets does the capture have?

In Wireshark to view all packets captured in your file **Statistics=>Capture file properties** and then scroll down to measurement section 
![totalPackets](/images/noPackets.png)
___
**Q2**. At what time was the first packet captured?

from the same windown scroll up to the time of first packet put add 4 to hours to convert to UTC
![first packet](/images/timeOfFirstPacket.png)
___
**Q3**. What is the duration of the capture?

from the same section 

![duration](/images/duration.png)
___
**Q4**. What is the most active computer at the link level?

to view the most active device at link level (mac address) **Statistics=>Endpoints=>Ethernet**
![mac](/images/mac.png)
___
**Q5**. Manufacturer of the NIC of the most active system at the link level?

to get this information we can search about manufacturer of this mac address on google and we will get it
![man](/images/man.png)

answer: Hewlett-Packard
___
**Q6**. Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?

also we can search about this information in google 
answer: Palo Alto
___
**Q7**. The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture?

**Statistics=>Endpoints=>IPV4**
![IP](/images/PrivateIps.png)
here we get four ips put as we know .255 assigned to **Broadcast** so we have only three private ips in organization
___
**Q8**. What is the name of the most active computer at the network level?

host name usually is a **DHCP** information so by mac or ip of the device we can filter by dhcp and expand packet to get this information

![name](/images/nameOfActive.png)

___
**Q9**. What is the IP of the organization's DNS server?

we can filter by dns to find the dns's query and ip of dns server

![dns](/images/dns.png)
___
**Q10**. What domain is the victim asking about in packet 204?

first as usuall, filter on packet 204 by **frame.number==204** in search bar and will find this packet is dns packet, then will expand this packet, and expand the dns section to find the domain name

![domainName](/images/domainName.png)

answer: proforma-invoices.com
___
**Q11**. What is the IP of the domain in the previous question?

in packet 204, there is information that the response of this packet in packet 206
![response_packet](/images/res.png)

so we will filter by this packet and expand it to see the response 

![responseIp](/images/response.png)
answer: 217.182.138.150
___
**Q12**.Indicate the country to which the IP in the previous section belongs.

we can search on iplocation.net by ip to get the country

![location](/images/ipLocation.png)
___
**Q13**.What operating system does the victim's computer run?

**HTTP Request** usually contain user-agent infromation such as user OS, so we will filter by **http** and expand **GET** packet, and expand it, and expand http section, and get our target

![os](/images/os.png)

answer: Windowns NT 6.1
___
**Q14**.What is the name of the malicious file downloaded by the accountant?

if we filter by **GET** method
![get_req](/images/get_req.png)
we see that this packet contain exe file and this is our target

answer: tkraw_Protected99.exe
___
**Q15**. What is the md5 hash of the downloaded file?

so we will download this file and generate hash value 
to download/export from wireshark **File=>Export object=>HTTP** and select our file and save

to generate md5 hash "type in terminal"
**md5 tkraw_Protected99.exe**

answer: 71826ba081e303866ce2a2534491a2f7 
___
**Q16**. What is the name of the malware according to Malwarebytes?

we can use tool named VirusTotal by the hash value of virus and search the name of this malware according to anti-virus 
![malwarebyte](/images/malwarebyte.png)
___
**Q17**. What software runs the webserver that hosts the malware?

the webserver that host the malware appear in **http response** so we can get the response to the packet that contain the malware and expand it to get the name
![software](/images/software.png)

answer: litespeed
___
**Q18**. What is the public IP of the victim's computer?

if we search in **GET** requests made by victim we will find that there is a packet request
whatismyipaddress.com so we can know the public ip of victim from the response to this packet

![Public ip](/images/publicIp.png)
___
**Q19**. In which country is the email server to which the stolen information is sent?

so if we filter on **SMTP** protocol wish responsable to mails we will find that victim recives mails from this ip 
![mailIP](/images/mailIp.png)
so we will take this ip and search on iplocation.net to find country

![mailCountry](/images/mailCountry.png)
___
**Q20**. What is the domain's creation date to which the information is exfiltrated?

so if we search about **SMTP REQ** we will find that victim communicate with this mail
![smtpReq](/images/smtpReq.png)
so if we extract the domain name from this mail which is macwinlogistics.in and search about it on this website https://whois.domaintools.com/
we will find the creation date
![creationDate](/images/createdDate.png)
___
**Q21**. Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent?

we will follow **TCP stream** and the first line contain the software and other inforamtion
![softwareStolen](/images/softwareStolen.png) 
___
**Q22**. To which email account is the stolen information sent?

as we do above we can see the stmp traffic and see from and to email 
![email](/images/email.png)
**sales.del@macwinlogistics.in**
___
**Q23**. What is the password used by the malware to send the email?

as we do above we can see the stmp traffic and see that there is an encoded password in traffic
![password](/images/password.png)
so if we decode it we will get the password
**Sales@23**
___
**Q24**. Which malware variant exfiltrated the data?

if we track the **STMP** traffic we will find this packet
![message](/images/message.png)
if we expand this packet, and scrool down we will find the palin text message 
and in this message we will find the malware name ant its variant
![malvar](/images/malvar.png)
___
**Q25**.What are the bankofamerica access credentials? (username:password)

in this palin text message also we will find the username and password to access
![credentials](/images/usrPass.png)
___
**Q26**.Every how many minutes does the collected data get exfiltrated?

if we track the stmp traffic we will notice that every 10 minutes data get exfiltrated
![time](/images/minutes.png)





