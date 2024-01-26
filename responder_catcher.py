import sys
import optparse
from scapy.all import *
import socket
import requests
import threading
import random
import time
import struct
import fcntl
import binascii

usage = 'usage: %prog [options]'
version = '%prog v1 - no more responder !'

class send():
    def __init__(self, options):
        self.username = options.username
        self.password = options.password
        self.dest = options.dest
        self.method = options.method
        self.res = {}

    def send_log(self, message):
        if self.method == 'syslog': 
            if not self.dest:
                print('missing arg dest, check usage')
                sys.exit(0)
            facility_level = 14 
            msg = ','.join('='.join((k,str(v))) for (k,v) in message.items())
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = '<%d>%s' %  (facility_level, msg)
            sock.sendto(data.encode(), (self.dest, 514))
            sock.close()
        elif self.method == 'post':
            if not self.dest: 
                 print('missing arg interface, check usage')
                 sys.exit(0)
            if self.username and self.password :
                r = requests.post(self.dest, json = message, auth = (self.username, self.password))
            else:
                r = requests.post(self.dest, json = message)
            if r.status_code == 401:
                print('Unauthorized to send data, check credentials')
                sys.exit(0)
            if r.status_code != 200:
                print('error during sending log, check param')
                sys.exit(0)
        else:
            print(message)

    def parse_llmnr(self, pkt, host):
        try :
            self.res['src_mac'] = pkt[0].src
            self.res['src_ip'] = pkt[0][1].src
            self.res['dest_ip'] = pkt[0][1].dst
            self.res['src_port'] = pkt[0][2].sport
            self.res['dest_port'] = pkt[0][2].dport
            self.res['query'] = pkt[0][5].rrname.decode('utf8')
            self.res['answer'] = pkt[0][5].rdata
        except Exception as e:
            self.res['query'] = host
            self.res['answer'] = 'llmnr response error'

    def parse_mdns(self, pkt, host):
        try:
            for p in pkt :
                try :
                    query = p[0][4].rrname.decode('utf-8').split('.')[0]
                    if query == host:
                        self.res['query'] = query
                        self.res['answer'] = p[0][4].rdata
                        self.res['src_mac'] = p[0].src
                        self.res['src_ip'] = p[0][1].src
                        self.res['dest_ip'] = p[0][1].dst
                        self.res['src_port'] = p[0][2].sport
                        self.res['dest_port'] = p[0][2].dport
                    else:
                        next
                except Exception as e2:
                    next
            if 'query' not in self.res:
                self.res['query'] = host
                self.res['answer'] = 'no mdns response'
        except Exception as e:
            self.res['query'] = host
            self.res['answer'] = 'mdns response error'


    def parse_pkt(self, pkt, host, proto):
        self.res['source'] = 'responder_catcher'
        self.res['proto'] = proto
        if pkt and proto == 'LLMNR':
            self.parse_llmnr(pkt, host)
        elif pkt and proto == 'MDNS':
            self.parse_mdns(pkt, host)
        else:
            self.res['query'] = host
            self.res['answer'] = 'timeout'
        self.send_log(self.res)

def catch(listener, port, host, iface, options, ip, proto):
    if proto == 'LLMNR':
        pkt = sniff(iface = iface, filter = 'udp dst port '+str(port), timeout = 20, stop_filter = lambda p: listener.is_set())
    if proto == 'MDNS':
        pkt = sniff(iface = iface, filter = 'udp src port 5353 and not src '+str(ip), count = 40, timeout = 20)
    if len(pkt) == 0:
        send(options).parse_pkt(False, host, proto)
    else:
        send(options).parse_pkt(pkt, host, proto)

def get_ip(iface):
    return socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s', iface.encode()))[20:24])

def get_mac(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s',  bytes(iface[:15], 'utf-8')))
    return ''.join(l + ':' * (n % 2 == 1) for n, l in enumerate(binascii.hexlify(info[18:24]).decode('utf-8')))[:-1]

def main():
    parser = optparse.OptionParser(usage = usage, version = version)
    parser.add_option('-u', '--username', type = 'string', dest = 'username', help = 'login to authenticate Http post query')
    parser.add_option('-p', '--password', type = 'string', dest = 'password', help = 'password to authenticate Http post query')
    parser.add_option('-d', '--dest', type = 'string', dest = 'dest', help = 'url or host - where result send')
    parser.add_option('-i', '--iface', type = 'string', dest = 'iface', help = 'interface used for send and receive llmnr/mdns query')
    parser.add_option('-m', '--method', type = 'string', dest = 'method', help = 'method used to send result : syslog, post. Default print on term')
    (options, args) = parser.parse_args()

    if not options.iface:
        print('missing arg interface, check usage')
        sys.exit(0)

    lint = [random.randrange(34000, 60000, 1) for i in range (200)]
    lhost =  ['DESKTOP-' + ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(7)) for i in range(15)]
    lhost.append('wpad.local')
    listener_thread = threading.Event() 
    ip = get_ip(options.iface)
    mac = get_mac(options.iface)
    ip_llmnr = '224.0.0.252'
    ip_mdns = '224.0.0.251'
    mac_llmnr = '01:00:5e:00:00:fc'
    mac_mdns = '01:00:5e:00:00:fb'

    for host in lhost:
        time.sleep(random.randint(15,30))
        port = random.choice(lint)
        id = random.choice(lint)
        t = threading.Thread(target=catch, args=(listener_thread, port, host, options.iface, options, ip, 'MDNS',))
        t.start()
        t2 = threading.Thread(target=catch, args=(listener_thread, port, host, options.iface, options, ip, 'LLMNR',))
        t2.start()
        listener_thread.set()

        llmnr = Ether(src=mac, dst=mac_llmnr)/IP(dst=ip_llmnr, src=ip)/UDP(sport=port, dport=5355)/LLMNRQuery(id=id, qdcount=1, qd=DNSQR(qname=host, qtype=255))
        mdns = Ether(src=mac, dst=mac_mdns)/IP(dst=ip_mdns, src=ip)/UDP(sport=5353, dport=5353)/DNS(qd=DNSQR(qname=host + '.local', qtype=255))
        t.join(2)
        t2.join(2)
        if t.is_alive() and t2.is_alive():
            sendp(mdns, iface=options.iface)
            sendp(llmnr, iface=options.iface)
        
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('End by user - Keyboard interrupt')
    except Exception as e:
        print(e)
