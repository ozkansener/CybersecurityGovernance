# Cyber Security Governance
Ozkan Sener
Vrije Universiteit Amsterdam
ozkansener@gmail.com

In today's world everybody gives advice in cybersecurity and a layman person (business executive or IT manager) does not know whether they have good advice or not.
This guide is a checklist for beginners and this checklist can be improved so any feedback is welcome. This guide was created in July 2018 and is regularly updated. 
This defence would not hold against state hackers, but will help you in your defence as an average size company againt most attacks.
Cyber security is about creating barries (there is unfortenely not more you could do) and by doing this narrow the vision of the hacker.
Be carefull that you don't do this that you don't know what it's effect is. Very often security engineers create new holes after they think that they have implemented a security measure.

Before you do anything create an attack tree.
Examples of different levels of attacks trees:

https://attack.mitre.org/wiki/Main_Page


Security measures can be classified in four categories:

1. preventive measures
2. detective measures
3. response measures
4. remedial measures

Good security is build from the inside to the outside. People think security as a layer, but should be seen as a policy. Layers are independently that creates complexity physical, perimeter, network, host , application data layer.
Below we describe some basic measurements you can take to protect your enterprise against hackers(there are many more) and a strategy.

1. Physical Layer: chain link fence, security guard physical local, monitoring, badge readers
2. Perimeter layer: Firewalls, NextGen L7 Firewall VPN, reverse proxy forward proxies, intrusion detection, single sign on, multi factor authentication
3. Network layer: windows communication control, web application firewall, data acquisition network, Network access control, Logical access control, Network time protocol, wireless networks security, password management, security operation center
4. Host:host based firewalls, anti virus & malware, Vulnerability scanning & patching, CMDB and asset management, server access control, Os hardening guidelines, Mobile devices and MDM, privileged access management, thumb drive protection
5. Application: SSL cert, Role Based Access Control, Application code review, Key Management systems, Source code management security, Sandboxing, Virtualization
6. Data: data encryption, data loss prevention, DDOS, Data backup
Compliance (Glue all together): Policies Procedures & Awareness (training): Governance, risk and compliance tool, business continuity and disaster recovery.
7. Certification: Soc 2, ISO 27001, Privacy Shield, GDPR, change management, identity management and identity training, incident management, HR background checks


# Security Strategies

-   Least priviledge: don't allow more than you need
-   Defense in depth: have multiple security mechanisms
-   Diversity of defence: have different security mechanisms
-   Choke point: force attackers to use a narrow channel
-   Weakest link: don't divert your attention from them
-   Fail safe stance: fail in a way denying access
-   Default permit (or deny) stance
-   Universal participation: one opt-out can endanger all the rest
-   Simplicity

# Hardware-based Access Control
-   Protection problem: prevent processes from interfering
-   Confinement problem: prevent prevent non-authorized communication
-   Protection rings: levels of protection
-   Trusted computing

# Operating System Access Control
-   Groups and roles
-   Access control lists
-   Blacklisting and whitelisting
-   Capabilities
-   Sandboxing

# Security by Obscurity
## Not effective when it:

-   is the only security
-   is not real obscurity
-   prevents accurate determination of a product's security
-   is given irrational confidence

## Valid when it:

-   helps to avoid vulnerability targetting (hiding equipment and versions)
-   complements other measures
-   hinders social engineering attacks (e.g. hide hostnames behind firewall)
-   is used to protect other measures such as intrusion detection


# Firewalls

-   Restricts people to enter at a carefully controlled point
-   Prevents attackers from getting close to other defenses
-   Restricts people to leaving at a carefully controlled point
-   Firewall can ensure that traffic is acceptable
-   Focus of security decisions
-   Enforce security policy
-   Log network activity
-   Limit exposure of one part of the organisation to others

### Firewall Technologies

-   Packet filtering
-   Proxy services
-   Network address translation
-   Virtual private network
-   Application-level gateway
-  Circuit-level gateway

### Packet filtering (example)
#### ﻿﻿﻿ Determine packet characteristics
address
protocol
port
#### Associate with a network interface (in/outbound)
#### Associate with other packets
    -   reply
    -   fragmentation
    -   duplication
    -   count
#### Action:
    -   Send
    -   Drop
    -   Reject (return an error)
    -   Log
    -   Raise an alarm

##### Advantages
    -   Easy to protect a network through the router
    -   Efficient
    -   Widely available
##### Disadvantages
    -   Difficult to setup
    -   Some prolicies can not be enforced
    -   Reduces router performance

##  Firewall Architectures

-   Screening Router
-   Dual-homed Host
-   Screened Host
-   Screened Subnet
-   Internal Firewall
-   Personal Firewall

## A firewall can not protect against:

-   malicious insiders
-   connections that circumvent it
-   completely new threats
-   some viruses
-   the administrator that does not correctly set it up


# It is good practice to types of attack
-   Probe: a few tries to break in
-   Attack: concerted attempt
-   Break-in: host has been compromised
## Probe
A few (random) tries to break in.
-   Try to access insecure services
-   Try common names (anonumous, guest)
-   Address probing
-   Port scanning

## Attack
Concerted break-in attempt.

-   Multiple failed attempts to valid accounts
-   Attempts over a lengthy period from the same host
-   Successful login from unknown site
-   Increases in incoming / outgoing traffic

## Break in
Host has been compromised.

-   Deleted or modified log files
-   Installation of a _rootkit_
-   Programs behave in a strange way
-   Unexpected logins to privileged users
-   New services running
-   Changed login prompt
-   New programs running
-   Unaxpected changes in disk space usage
-   Probes from inside the network

## Maintenance is important

-   Backup
-   Manage accounts
-   Keep disk clean (so that you can recognise intrusion signs)
-   Rotate logs

## Monitoring

-   Signs for a compromise
-   Attacks
-   Log
    -   Dropped and rejected packets
    -   Denied connections
    -   Rejected connection attempts
    -   Username and time of successful connections (bastion hosts)
    -   Error messages
-   Do not log passwords (and failed user names as they might be passwords)

## Updating

-   Subscribe to mailing lists
-   Check vendor patches
-   Upgrade when needed (and only then)
## VPN Architecture

-   Site-to-site: used to connect organisational branches
-   Remote access
-   Extranet

## Tunneling

-   Each packet is encapsulated
-   Can provide:
    -   Confidentiality
    -   Integrity
    -   Authenticity

# Defence in Depth Example

## 2 Layers

1.  Firewall
2.  Host based packet filtering

## 5 Layers

(Increase security on the Internet side to handle DDOS attacks)

1.  Border router
2.  Network management system
3.  Intrusion detection system
4.  Firewall
5.  Host based packet filtering

## 8 Layers

(Increase security on the workstation side to handle internal attacks)

1.  Border router
2.  Network management system
3.  Intrusion detection system
4.  Firewall
5.  Host based packet filtering
6.  Log analysis and alert
7.  File integrity validation
8.  Cryptography

## Consideration
If you really want security also look for items like:
1. Data diode
2. Secunet
3. Hardware Firewall
4. Etc.

## Others
Email Spoofing: SPF, DKIM and DMARC
DNSSEC, TLS


## Monitoring
1. Egress filtering
2. Ingress filtering
3. etc


## Prepared if hacked
1. You should have limited the access from the internet to vulnerable hosts as much as possible.
2. Shutdown the compromised servers and go on the fallback or backup server and block the attacks. The backup server only has read access and writes are done in manully where each write operation is manually checked for intrusion or unauthorized operation.
3. Contact the police or if you are managing a critical infrastructure your local NCSC.
4. Learning how you have been hacked is very important in order to prevent the attack.

## Untrusted files
We see very often that Human Resource Management has to open a resume or they have to open a file from somebody who they don't know.


1. Save as and save in an isolated location (sandbox the execution), especially if you do not trust it.
2. scan the virus scanner extra.
3. Do not let Windows suppress the extensions of files anyway
4. DO NOT open the file by double clicking on it (but by opening it from the application).
5. Have a backup and restore if it goes wrong (hence the isolated location for storage (sandbox)

## Protect protcols for example RDP
1. Segment your network so that any computer intrusion has limited consequences.
2. Manage all devices via Out-of-Band network management.
3. Perform hardening on all network equipment.
4. Ensure that the RDP server - or the server running the RDP service - is provided with the latest updates and security patches.
5. Set a different port than the default port 3389 for the RDP protocol.
6. Make an inventory of all external links with your network.
7. Limit external links to only the most necessary links.
8. Make an inventory of the links that use the RDP and other protocols.
9. Assess the necessity of using the RDP or any other protocol. If there is no need to use the protocol, switch it off.
10. If the use of the RDP or another protocol is necessary, ensure that the connection to the remote computer is via a VPN connection.
11. If possible, use additional security measures such as an authentication token.
12. Disable the use of the Internet if a VPN tunnel connection is active on the remote computer.
13. Set a maximum log duration for RDP sessions. Automatically disconnect the connection after, for example, 5 minutes.
14. Set IP restrictions on the firewall so that only authorized computers can set up an RDP session.
15. Configure access at all times based on authentication. Possibly two-factor authentication.
16. Use strong passwords for logging in.
17. Use different named management accounts.
18. Limit the number of sign-in attempts on all accounts.

## Hardware
Buy hardware that you can trust. We know that different goverments are placing chips backdoors inside computers to manipulate them.
For example the best router is a router that you have built yourself and where intelligence services and other hackers do not just have a ready-made hack as you probably have for the routers what you bought from the Cisco, ZTE or other routers.
To configure such a router you need an APU2c4 which costs a few hundred euros. You can then find out whether you are going for a linux (iptables) or openbsd (pf) based on your firewall.

## Audit
### OS
https://cisofy.com/lynis/

### Webbrowser audit
https://www.ssllabs.com
https://browseraudit.com/#

### Audit
Auditing is crucial for discovering your vulnerabilities


## Learning curve
There is no standard way of security. Documentation is very important to understand why things are happening the way it happens, because large companies have many services running and some of these are not so often used but also to know when an intruder is inside your network.
You have to understand that great hackers have for almost everything a backdoor so what you see and what is happening in reality can be different therefore you need multiple types of inspections from mulitple location!

## Other tips
1. Use SPF and DMARC to protect your email domain.
2. Perform security test.

# Questions:
Ozkan Sener
Vrije Universiteit Amsterdam
ozkansener@gmail.com
