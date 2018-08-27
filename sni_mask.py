from __future__ import with_statement
import sys
import socket
import select, threading
import SocketServer
import struct, random, time
import logging

INTERFACE = ('0.0.0.0', 443)
WAN = []
KEEPALIVE = True

HOSTS = {
    '.wikipedia.org'     : (0, 1, 12, 0, [], ['198.35.26.96']),
    '.m.wikipedia.org'   : (0, 1, 12, 0, [], ['198.35.26.96']),
    'SNI'                : (0, 1, 12, 0, [], ['69.162.113.194']),
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

def http_filter(data):
    if data.find(' HTTP/1.1\r\n') == -1:
        return data
    request = ''
    for line in data.split('\r\n'):
        if line[:9] == 'Referer: ':
            pass
        elif line[:17] == 'Accept-Language: ':
            request += 'Accept-Language: en\r\n'
        elif line == 'Connection: keep-alive\r\n':
            pass
        elif line[:8] == 'Cookie: ':
            pass
        elif line[:12] == 'User-Agent: ':
            if line.find('Mobile') != -1:
                request += 'User-Agent: Mozilla/5.0 (Android 6.0; Mobile; rv:58.0) Gecko/58.0 Firefox/58.0\r\n'
                #request += 'User-Agent: Mozilla/5.0 (iPod; CPU iPhone OS 12_0 like macOS) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/12.0 Mobile/14A5335d Safari/602.1.50\r\n'
            elif line.find('Table') != -1:
                request += 'User-Agent: Mozilla/5.0 (Android 6.0; Table; rv:58.0) Gecko/58.0 Firefox/58.0\r\n'
            else:
                request += 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0\r\n'
        elif line != '':
            request += line + '\r\n'
    return request + '\r\n'
    #return request.replace('\r\n', '\n') + '\n'

class SNIProxy(SocketServer.StreamRequestHandler):
    remote = 0
    
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
        
    def parse_http(self, data):
        if data[:4] in ['GET ', 'POST', 'HEAD']:
            head = data.split('\r\n')
            #method, res, ver = head[0].split(' ', 2)
            return head[1][6:]
        else:
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
            logging.warn('Forward: %s' % e)
        finally:
            sock.close()
            remote.close()

    def sendall(self, remote, s_send, ttl, aseq, seq, data, fakedata):
        sockname = remote.getsockname()
        addr = remote.getpeername()

        ip_sock = socket.inet_aton(sockname[0])
        ip_addr = socket.inet_aton(addr[0])
        
        ip_header = struct.pack('!BBHHHBBH4s4s' , 69, 0, 0, 47843, 16384, ttl, 6, 0, ip_sock, ip_addr)
        psh = struct.pack(b'!4s4sBBH', ip_sock, ip_addr, 0, socket.IPPROTO_TCP, 20 + len(fakedata))
            
        if ttl == 1:
            tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq+1, 80, 24, 454, 0, 0)
            packet = ip_header + tcp_header + fakedata
            s_send.sendto(packet, (addr[0], 0))
            remote.sendall(data)
            s_send.sendto(packet, (addr[0], 0))
        elif ttl == 2:
            tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq, 80, 24, 454, 0, 0)
            tcp_packet = tcp_header + fakedata
            tcp_checksum = checksum(psh + tcp_packet)
            tcp_header = struct.pack(b'!16sH2s', tcp_header[:16], tcp_checksum, tcp_header[18:])
            packet = ip_header + tcp_header + fakedata
            s_send.sendto(packet, (addr[0], 0))
            remote.sendall(data)
            s_send.sendto(packet, (addr[0], 0))
        else:
            tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq+1, 80, 24, 454, 0, 0)
            tcp_packet = tcp_header + fakedata
            tcp_checksum = checksum(psh + tcp_packet)
            tcp_header = struct.pack(b'!16sH2s', tcp_header[:16], tcp_checksum, tcp_header[18:])
            packet = ip_header + tcp_header + fakedata
            s_send.sendto(packet, (addr[0], 0))
            remote.sendall(data)
            s_send.sendto(packet, (addr[0], 0))
            
    def connect(self, addr, data, sni, ttl, mss, keep, event_connected, event_ready, mutex):
        global WAN
        sock = self.connection
        try:
            isIPv6 = addr[0].find(':') != -1
            if isIPv6:
                remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if WAN != []:
                wan = random.choice(WAN)
                remote.bind((wan, 0))
                
            if mss > 0:
                remote.setsockopt(socket.SOL_TCP, socket.TCP_MAXSEG, mss)
            remote.settimeout(3.0)
            s_recv_tcp = None
            seq = 0
            aseq = 0
            
            if ttl > 0:
                if isIPv6:
                    s_recv_tcp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
                else:
                    s_recv_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s_recv_tcp.connect(addr)
                remote.connect(addr)
                remote.settimeout(None)
                
                if mutex.acquire(2):
                    if event_connected.isSet() == False:
                        event_connected.set()
                    else:
                        mutex.release()
                        s_recv_tcp.close()
                        remote.close()
                        return
                else:
                    s_recv_tcp.close()
                    remote.close()
                    return
                
                while not event_ready.isSet():
                    packet = s_recv_tcp.recv(2048)
                    
                    if isIPv6:
                        tcp_header = packet[:20]
                    else:
                        tcp_header = packet[20:40]
                    tcph = struct.unpack(b'!HHIIBBHHH', tcp_header)
                    sport, dport, seq, aseq, headlen, flags, win, chechsum, p = tcph
                    
                    if dport == remote.getsockname()[1]:
                        break
                
                s_recv_tcp.close()
                
                s_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                
                if keep:
                    data = http_filter(data)
                    fakedata = ' ' * len(data)
                else:
                    fakedata = ' ' * len(data)
                
                remote.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                offset = data.find(sni) + len(sni) / 2
                
                self.sendall(remote, s_send, ttl, aseq, seq, data[:offset], fakedata)
                
                if event_ready.isSet():
                    s_send.close()
                    remote.close()
                    return
                
                remote.sendall(data[offset:])

                if keep:
                    rstword = ''
                    try:
                        aseq += len(data)
                        fdset = [sock, remote]
                        while True:
                            r, w, e = select.select(fdset, [], [])
                            if sock in r:
                                data = sock.recv(32768)
                                if len(data) <= 0:
                                    break
                                data = http_filter(data)
                                #print repr(data)
                                fakedata = data.replace(sni, fakesni)
                                offset = data.find(sni) + len(sni) / 2
                                self.sendall(remote, s_send, ttl, aseq, seq, data[:offset], fakedata)
                                remote.sendall(data[offset:])
                                #rstword = data
                                aseq += len(data)

                            if remote in r:
                                data = remote.recv(32768)
                                if len(data) <= 0:
                                    break
                                seq += len(data)
                                sock.sendall(data)
                    except socket.error, e:
                        logging.warn('Forward: %s %s' % (e, sni))
                        #print repr(rstword)
                    finally:
                        sock.close()
                        remote.close()
                s_send.close()
            else:
                remote.connect(addr)
                if mutex.acquire(2):
                    if self.remote:
                        mutex.release()
                        remote.close()
                        return
                    event_connected.set()
                else:
                    remote.close()
                    return
                self.remote = remote
                remote.settimeout(None)
                remote.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
                remote.sendall(data)
                if keep:
                    self.forward(sock, remote)
            self.remote = remote
            mutex.release()
            event_ready.set()
        except socket.error, e:
            logging.warn(sni + ' ' + str(e))
            return

    def handle_remote(self, rule, port, server_name, data, keep):
        try:
            event_connected = threading.Event()
            event_ready = threading.Event()
        
            round_count, waittime, ttl, mss, goodlist, addrlist = rule

            if round_count > 0:
                random.shuffle(goodlist)
                random.shuffle(addrlist)
            else:
                round_count = 1
                
            mutex = threading.Lock()
            count = len(goodlist)
            for i in xrange(count):
                addr = (goodlist[i], port)
                c = threading.Thread(target=self.connect, args=(addr, data, server_name, ttl, mss, keep, event_connected, event_ready, mutex,), name="connect")
                c.start()
                if i < count-1:
                    if event_connected.wait(timeout=waittime):
                        break
                else:
                    event_connected.wait(timeout=2.0)
                    
            if self.remote == False:
                goodlist = []
                for r in xrange(round_count):
                    count = len(addrlist)
                    for i in xrange(count):
                        addr = (addrlist[i], port)
                        c = threading.Thread(target=self.connect, args=(addr, data, server_name, ttl, mss, keep, event_connected, event_ready, mutex,), name="connect")
                        c.start()
                        if i < count-1:
                            if event_connected.wait(timeout=waittime):
                                break
                        else:
                            event_connected.wait()
                            
                    if self.remote:
                        goodlist.append(self.remote.getpeername()[0])
                        break
            event_ready.wait()
            return self.remote
        except socket.error, e:
            logging.warn(server_name + ' ' + str(e))
            return 0
            
    def handle(self):
        global HOSTS
        server_name = ''
        try:
            sock = self.connection
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            data = sock.recv(2048)

            server_name = self.parse_http(data)
            if server_name == '':
                server_name = self.parse(data)
                https = True
                port = 443
            else:
                https = False
                port = 80
            remote = 0

            root_name = server_name[server_name.find('.'):]
            if HOSTS.has_key(server_name):
                rule = HOSTS[server_name]
            else:
                if HOSTS.has_key(root_name):
                    rule = HOSTS[root_name]
                else:
                    if HOSTS.has_key('*'):
                        if move_https(sock, data):
                            return
                        rule = HOSTS['*']
                    else:
                        rule = None
            
            if rule:
                if isinstance(rule, str):
                    rule = HOSTS[rule]

                round_count, waittime, ttl, mss, goodlist, addrlist = rule

                if https:
                    remote = self.handle_remote(rule, port, server_name, data, False)
                    if remote:
                        global KEEPALIVE
                        if KEEPALIVE:
                            remote.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
                            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
                            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                        logging.info('%s->https://%s %s' % (self.client_address[0], server_name, remote.getpeername()[0]))
                        self.forward(sock, remote)
                    else:
                        logging.info('%s->%s fail' % (self.client_address[0], server_name))
                        sock.close()
                else:
                    logging.info('%s->http://%s' % (self.client_address[0], server_name))
                    self.handle_remote(rule, port, server_name, data, True)
            else:
                logging.info('%s->%s %s' % (self.client_address[0], server_name, 'Unknow'))
                sock.close()
                return
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
