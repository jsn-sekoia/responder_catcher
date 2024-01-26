# Overview

**Responder_catcher** is a Python script to detect responder (and other network poisoners).  He sends llmnr/mdns requests, captures and parses the answers in order to send them to a third party tool (a SIEM for example). 

![Responder Catcher](responder_catcher.png?raw=true "Responder_catcher")

# How it works

The extension operates by sending :
- A llmnr/mdns query for "wpad.local" to a multicast address
- A llmnr/mdns query for 10 random hostname on .local domain
the random hostname are created via a list comprehension (variable lhost) and correspond to this regex : `DESKTOP-[A-Z0-9]{7}`

In parallel two listers (1 per protocol) are created to record the responses to the requests. We consider that we are poisoned if for several different queries we get the same answer. 

The returned data contains the source IP and the source mac address of the responding machine. This allows to quickly identify the rogue device

# Install and Run

Requires Python 3.6+ (tested on Python 3.7 and 3.9)
Queries are forged using Scapy, so it is necessary that the lib is installed 
```
git clone https://github.com/J2r2mCyb3r/responder_catcher.git    
cd responder_catcher    
pip3 install -r requirements.txt
```
Run in simple mode (result print on screen - like on sceenshot above):
`sudo python3 responder_catcher.py -i {interface used to send query}`

# Usage

Used -h to print help
```
Usage: responder_catcher.py [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -u USERNAME, --username=USERNAME
                        login to authenticate Http post query
  -p PASSWORD, --password=PASSWORD
                        password to authenticate Http post query
  -d DEST, --dest=DEST  url or host - where result send
  -i IFACE, --iface=IFACE
                        interface used for send and receive llmnr/mdns query
  -m METHOD, --method=METHOD 
                        method used to send result : syslog, post. Default
                        print on term
```
