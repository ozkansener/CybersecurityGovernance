# Cyber Security Governance
Ozkan Sener
Vrije Universiteit Amsterdam
ozkansener@gmail.com

In today's world everybody gives advice in cybersecurity and a layman person (business executive or IT manager) does not know whether they have good advice or not.
This guide is a checklist for beginners and this checklist can be improved so any feedback is welcome. This guide was created in July 2018 and is regularly updated. 
This defence would not hold against state hackers, but will help you in your defence as an average size company againt most attacks.
Cyber security is about creating barries (there is unfortenely not more you could do) and by doing this narrow the vision of the hacker.


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

## Untrusted files
We see very often that Human Resource Management has to open a resume or they have to open a file from somebody who they don't know.


1. Save as and save in an isolated location (sandbox the execution), especially if you do not trust it.
2. scan the virus scanner extra.
3. Do not let Windows suppress the extensions of files anyway
4. DO NOT open the file by double clicking on it (but by opening it from the application).
5. Have a backup and restore if it goes wrong (hence the isolated location for storage (sandbox)

## Hardware
Buy hardware that you can trust. We know that different goverments are placing chips inside computers to manipulate them.

# Questions:
Ozkan Sener
Vrije Universiteit Amsterdam
ozkansener@gmail.com
