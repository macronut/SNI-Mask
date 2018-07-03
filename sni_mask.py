from __future__ import with_statement
import sys
import socket
import select, threading
import SocketServer
import struct, random
import logging

INTERFACE = ('0.0.0.0', 443)
WAN = ''
KEEPALIVE = True

HOSTS = {
    'api.twitter.com'    : (0, 0.1, 10, 0, [], ['104.244.45.247']),
    'twitter.com'        : (0, 0.1, 10, 0, [], ['104.244.45.254']),
    'mobile.twitter.com' : (0, 0.1, 10, 0, [], ['104.244.45.247', '104.244.45.255']),
    'abs.twimg.com'      : (0, 0.1, 10, 0, [], ['104.244.43.98', '104.244.46.135', '104.244.43.130', '104.244.43.66']),
    'pbs.twimg.com'      : (0, 0.1, 10, 0, [], ['104.244.43.98', '104.244.46.135', '104.244.43.2', '104.244.43.66']),
    'video.twimg.com'    : (0, 0.1, 10, 0, [], ['104.244.43.98', '104.244.43.2', '104.244.43.66', '104.244.43.106']),
    'abs-0.twimg.com'    : (0, 0.1, 10, 0, [], ['104.244.43.98', '104.244.46.135', '104.244.43.130', '104.244.43.2']),
    'www.instagram.com'                : (0, 0.1, 10, 0, [], ['31.13.75.174', '31.13.73.172', '31.13.73.174', '31.13.72.172',]),
    'i.instagram.com'                  : (0, 0.1, 10, 0, [], ['31.13.75.174', '31.13.73.172', '31.13.73.174', '31.13.72.172',]),
    'graph.instagram.com'              : (0, 0.1, 10, 0, [], ['31.13.75.174', '31.13.73.172', '31.13.73.174', '31.13.72.172',]),
    'scontent-sit4-1.cdninstagram.com' : (0, 0.1, 0, 0, [], ['31.13.75.174', '31.13.73.172', '31.13.73.174', '31.13.72.172',]),
    'scontent-lax3-2.cdninstagram.com' : (0, 0.1, 0, 0, [], ['31.13.75.174', '31.13.73.172', '31.13.73.174', '31.13.72.172',]),
    'scontent-ams3-1.cdninstagram.com' : (0, 0.1, 0, 0, [], ['31.13.75.174', '31.13.73.172', '31.13.73.174', '31.13.72.172',]),
    'SNI'                : (0, 1, 12, 0, [], ['213.184.119.13', '213.184.119.116', '213.184.119.30', '213.184.119.97', '213.184.119.110', '213.184.119.118', '213.184.119.2', '213.184.119.44', '213.184.119.36', '213.184.119.46', '213.184.119.117', '213.184.119.120', '213.184.119.80', '213.184.119.9', '213.184.119.86', '213.184.119.57', '213.184.119.99', '213.184.119.32', '213.184.119.10', '213.184.119.70', '213.184.119.75', '213.184.119.84', '213.184.119.49', '213.184.119.124', '213.184.119.61', '213.184.119.62', '213.184.119.98', '213.184.119.79', '213.184.119.60', '213.184.119.15', '213.184.119.14', '213.184.119.122', '213.184.119.76', '213.184.119.39', '213.184.119.90', '213.184.119.65', '213.184.119.7', '213.184.119.50', '213.184.119.54', '213.184.119.77', '213.184.119.82', '213.184.119.64', '213.184.119.28', '213.184.119.51', '213.184.119.114', '213.184.119.20', '213.184.119.112', '213.184.119.6', '213.184.119.68', '213.184.119.113', '213.184.119.66', '213.184.119.21', '213.184.119.53', '213.184.119.17', '213.184.119.34', '213.184.119.67', '213.184.119.83', '213.184.119.8', '213.184.119.93', '213.184.119.18', '213.184.119.94', '213.184.119.100', '213.184.119.102', '213.184.119.45', '213.184.119.96', '213.184.119.56', '213.184.119.29', '213.184.119.89', '213.184.119.108', '213.184.119.58', '213.184.119.87', '213.184.119.119', '213.184.119.125', '213.184.119.35', '213.184.119.123', '213.184.119.71', '213.184.119.121', '213.184.119.27', '213.184.119.23', '213.184.119.107', '213.184.119.48', '213.184.119.16', '213.184.119.52', '213.184.119.73', '213.184.119.31', '213.184.119.24', '213.184.119.78', '213.184.119.105', '213.184.119.85', '213.184.119.92', '213.184.119.103', '213.184.119.111', '213.184.119.74', '213.184.119.25', '213.184.119.41', '213.184.119.115', '213.184.119.88', '213.184.119.126', '213.184.119.43', '213.184.119.5', '213.184.119.59', '213.184.119.38', '213.184.119.101', '213.184.119.63', '213.184.119.3', '213.184.119.47', '213.184.119.81', '213.184.119.69', '213.184.119.55', '213.184.119.26', '213.184.119.19', '213.184.119.11', '213.184.119.4', '213.184.119.95', '213.184.119.22', '213.184.119.40', '213.184.119.106', '213.184.119.33', '213.184.119.12', '213.184.119.91', '213.184.119.42', ]),
    '.google.com'        : 'SNI',
    '*'                  : 'SNI'
    }

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    if len(msg) % 2 != 0:
        msg += '\0'
    s = 0
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8 ) + ord(msg[i+1])
        s = carry_around_add(s, w)
    return ~s & 0xffff

def move_https(sock, data):
    if data == '':
        sock.close()
        return True
    elif data[0] == '\x16':
        return False
    else:
        head = data.split('\r\n')
        method, res, ver = head[0].split(' ', 2)
        if method in ['GET', 'POST', 'HEAD']:
            host = head[1][6:]
            content = 'HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s%s\r\n\r\n' % (host, res)
            sock.send(content)
        sock.close()
        return True

class SNIProxy(SocketServer.StreamRequestHandler):
    remote = 0
    ready = False
        
    def parse(self, data):
        try:
            offset = 0
            ContentType, Version, Length = struct.unpack('!BHH', data[:5])
            offset += 5
            if ContentType != 22:
                return ''
            HandshakeType, HandshakeLength, HandshakeVersion = struct.unpack('!BxHH', data[offset:offset+6])
            offset += 6
            if HandshakeType != 1:
                return ''
            Random, SessionIDLength = struct.unpack('!32sB', data[offset:offset+33])
            offset += 33 + SessionIDLength
            CipherSuitersLength = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2 + CipherSuitersLength
            CompressionMethodsLenght = ord(data[offset])
            offset += 1 + CompressionMethodsLenght
            ExtensionsLength = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            ExtensionsEnd = offset + ExtensionsLength
            while offset < ExtensionsEnd:
                ExtensionType, ExtensionLength = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                if ExtensionType == 0:
                    ServerNameListLength = struct.unpack('!H', data[offset:offset+2])
                    offset += 2
                    ServerNameType, ServerNameLength = struct.unpack('!BH', data[offset:offset+3])
                    offset += 3
                    return data[offset:offset+ServerNameLength]
                else:
                    offset += ExtensionLength

            return ''
        except:
            return ''

    def forward(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(32768)
                    if len(data) <= 0:
                        break
                    remote.sendall(data)

                if remote in r:
                    data = remote.recv(32768)
                    if len(data) <= 0:
                        break
                    sock.sendall(data)
        except socket.error, e:
            print e
        finally:
            sock.close()
            remote.close()
            
    def connect(self, addr, data, sni, ttl, mss, event_connected, event_ready):
        global WAN
        try:
            isIPv6 = addr[0].find(':') != -1
            if isIPv6:
                remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
            if mss > 0:
                remote.setsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, mss)
            remote.settimeout(1.5)
            
            if ttl > 0:
                if isIPv6:
                    s_recv_tcp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
                else:
                    s_recv_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s_recv_tcp.connect(addr)
                remote.connect(addr)
                
                if self.remote:
                    s_recv_tcp.close()
                    remote.close()
                    return
                
                event_connected.set()
                self.remote = remote
                remote.settimeout(None)
                sockname = remote.getsockname()

                fakesni = 'thequickbrownfoxjumpsoverthelazydogthequickbrownfoxjumpsoverthelazydog'
                fakesni = fakesni[checksum(addr[0]) % 35:]
                fakesni = fakesni[:len(sni)-3] + '.me'
                fakedata = data.replace(sni, fakesni)
                #fakedata = ' ' * len(data)
                
                remote.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                offset = data.find(sni) + len(sni) / 2

                while not self.ready:
                    packet = s_recv_tcp.recv(2048)
                    
                    if isIPv6:
                        tcp_header = packet[:20]
                    else:
                        tcp_header = packet[20:40]
                    tcph = struct.unpack(b'!HHIIBBHHH', tcp_header)
                    sport, dport, seq, aseq, headlen, flags, win, chechsum, p = tcph
                    
                    if dport != sockname[1]:
                        continue

                    if self.ready:
                        s_recv_tcp.close()
                        remote.close()
                        return
                    
                    if ttl == 1:
                        tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq+1, 80, 24, 454, 0, 0)
                        packet = tcp_header + fakedata
                        s_recv_tcp.sendto(packet, (addr[0], 0))
                        remote.sendall(data[:offset])
                        s_recv_tcp.sendto(packet, (addr[0], 0))
                    elif ttl == 2:
                        tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq, 80, 24, 454, 0, 0)
                        tcp_packet = tcp_header + fakedata
                        if isIPv6:
                            psh = struct.pack(b'!16s16sIHBB', socket.inet_pton(socket.AF_INET6, sockname[0]), socket.inet_pton(socket.AF_INET6, addr[0]), len(tcp_packet), 0, 0, socket.IPPROTO_TCP)
                        else:
                            psh = struct.pack(b'!4s4sBBH', socket.inet_aton(sockname[0]), socket.inet_aton(addr[0]), 0, socket.IPPROTO_TCP, len(tcp_packet))
                        tcp_checksum = checksum(psh + tcp_packet)
                        tcp_header = struct.pack(b'!16sH2s', tcp_header[:16], tcp_checksum, tcp_header[18:])
                        packet = tcp_header + fakedata
                        s_recv_tcp.sendto(packet, (addr[0], 0))
                        remote.sendall(data[:offset])
                        s_recv_tcp.sendto(packet, (addr[0], 0))
                    else:
                        s_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                        iph = struct.unpack(b'!BBHHHBBH4s4s', packet[0:20])
                        ip_header = struct.pack('!BBHHHBBH4s4s' , 69, 0, 0, 47843, 16384, ttl, 6, 0, iph[9], iph[8])
                        tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq+1, 80, 24, 454, 0, 0)
                        tcp_packet = tcp_header + fakedata
                        psh = struct.pack(b'!4s4sBBH', iph[9], iph[8], 0, socket.IPPROTO_TCP, len(tcp_packet))
                        tcp_checksum = checksum(psh + tcp_packet)
                        tcp_header = struct.pack(b'!16sH2s', tcp_header[:16], tcp_checksum, tcp_header[18:])
                        packet = ip_header + tcp_header + fakedata
                        s_send.sendto(packet, (addr[0], 0))
                        remote.sendall(data[:offset])
                        s_send.sendto(packet, (addr[0], 0))
                        s_send.close()
                    break
            
                s_recv_tcp.close()
                
                if self.ready:
                    remote.close()
                    return
                
                remote.sendall(data[offset:])
            else:
                if self.remote:
                    remote.close()
                    return
                event_connected.set()
                self.remote = remote
                remote.settimeout(None)
                remote.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                remote.sendall(data)
            event_ready.set()
            self.ready = True
        except socket.error, e:
            logging.warn(sni + ' ' + str(e))
            return
     
    def handle(self):
        global HOSTS
        server_name = ''
        try:
            sock = self.connection
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            data = sock.recv(2048)
            port = 443
            
            if move_https(sock, data):
                return
            
            server_name = self.parse(data)
            remote = 0

            event_connected = threading.Event()
            event_ready = threading.Event()

            threadlist = []

            if HOSTS.has_key(server_name):
                rule = HOSTS[server_name]
            else:
                root_name = server_name[server_name.find('.'):]
                if HOSTS.has_key(root_name):
                    rule = HOSTS[root_name]
                else:
                    if HOSTS.has_key('*'):
                        rule = HOSTS['*']
                    else:
                        rule = None
            
            if rule:
                if isinstance(rule, str):
                    rule = HOSTS[rule]
                round_count, waittime, ttl, mss, goodlist, addrlist = rule

                if round_count > 0:
                    random.shuffle(goodlist)
                    random.shuffle(addrlist)
                else:
                    round_count = 1
                
                count = len(goodlist)
                for i in xrange(count):
                    addr = (goodlist[i], port)
                    c = threading.Thread(target=self.connect, args=(addr, data, server_name, ttl, mss, event_connected, event_ready,), name="connect")
                    c.start()
                    threadlist.append(c)
                    if i < count-1:
                        if event_connected.wait(timeout=waittime):
                            break
                    else:
                        event_connected.wait(timeout=2.0)
                        
                if self.remote == False:
                    for r in xrange(round_count):
                        count = len(addrlist)
                        for i in xrange(count):
                            addr = (addrlist[i], port)
                            c = threading.Thread(target=self.connect, args=(addr, data, server_name, ttl, mss, event_connected, event_ready,), name="connect")
                            c.start()
                            threadlist.append(c)
                            if i < count-1:
                                if event_connected.wait(timeout=waittime):
                                    break
                            else:
                                event_connected.wait()
                                
                        if self.remote:
                            goodlist.append(self.remote.getpeername()[0])
                            break
            else:
                logging.info('%s->%s %s' % (self.client_address[0], server_name, 'Unknow'))
                sock.close()
                return
            
            event_ready.wait()
            
            remote = self.remote
            global KEEPALIVE
            if KEEPALIVE:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 2)

            if remote:
                logging.info('%s->%s %s' % (self.client_address[0], server_name, remote.getpeername()[0]))
                self.forward(sock, remote)
            else:
                logging.info('%s->%s fail' % (self.client_address[0], server_name))
                sock.close()
        except socket.error, e:
            logging.warn(server_name + ' ' + str(e))
            sock.close()


def main():
    global PORT, LOCAL, IPv6
    
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    
    IPv6 = False
    global INTERFACE
     
    try:
        if IPv6:
            ThreadingTCPServer.address_family = socket.AF_INET6
        server = ThreadingTCPServer(INTERFACE, SNIProxy)
        logging.info("starting local at %s:%d" % tuple(server.server_address[:2]))
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        server.shutdown()
        sys.exit(0)
        
if __name__ == '__main__':
    main()
