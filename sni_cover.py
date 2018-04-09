from __future__ import with_statement
import sys
import socket
import select, threading
import SocketServer
import struct, random
import logging

INTERFACE = ('0.0.0.0', 443)
HOSTS = {
    'api.twitter.com'    : ['104.244.45.247'],
    'twitter.com'        : ['104.244.45.254'],
    'mobile.twitter.com' : ['104.244.45.247', '104.244.45.255'],
    'abs.twimg.com'      : ['104.244.43.98', '104.244.46.135', '104.244.43.130', '104.244.43.66'],
    'pbs.twimg.com'      : ['104.244.43.98', '104.244.46.135', '104.244.43.2', '104.244.43.66'],
    'video.twimg.com'    : ['104.244.43.98', '104.244.43.2', '104.244.43.66', '104.244.43.106'],
    'abs-0.twimg.com'    : ['104.244.43.98', '104.244.46.135', '104.244.43.130', '104.244.43.2'],
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
                    data = sock.recv(4096)
                    if len(data) <= 0:
                        break
                    remote.sendall(data)

                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    sock.sendall(data)
        finally:
            sock.close()
            remote.close()
            
    def connect(self, addr, data, sni, ttl, event_connected, event_ready):
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(1.0)

            s_recv_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s_recv_tcp.connect(addr)
            remote.connect(addr)

            if self.remote:
                remote.close()
                return
            
            event_connected.set()
            self.remote = remote
            remote.settimeout(None)
            
            sockname = remote.getsockname()
            fakedata = ' ' * len(data)
            
            while not self.ready:
                packet = s_recv_tcp.recv(2048)
                
                tcp_header = packet[20:40]
                tcph = struct.unpack(b'!HHIIBBHHH', tcp_header)
                sport, dport, seq, aseq, headlen, flags, win, chechsum, p = tcph
                if dport != sockname[1]:
                    continue
                if ttl == 1:
                    tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq, 80, 24, 454, 0, 0)
                    packet = tcp_header + fakedata
                    s_recv_tcp.sendto(packet, (addr[0], 0))
                    s_recv_tcp.sendto(packet, (addr[0], 0))
                elif ttl > 1:
                    s_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    iph = struct.unpack(b'!BBHHHBBH4s4s', packet[0:20])
                    ip_header = struct.pack('!BBHHHBBH4s4s' , 69, 0, 0, 47843, 16384, ttl, 6, 0, iph[9], iph[8])
                    tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq+1, 80, 24, 454, 0, 0)
                    tcp_packet = tcp_header + fakedata
                    psh = struct.pack(b'!4s4sBBH', iph[9], iph[8], 0, socket.IPPROTO_TCP, len(tcp_packet))
                    tcp_checksum = checksum(psh + tcp_packet)
                    tcp_header = struct.pack(b'!HHLLBBHHH', sockname[1], addr[1], aseq, seq+1, 80, 24, 454, tcp_checksum, 0)
                    packet = ip_header + tcp_header + fakedata
                    s_send.sendto(packet, (addr[0], 0))
                    s_send.sendto(packet, (addr[0], 0))
                    s_send.close()
                break
            s_recv_tcp.close()
            
            if self.ready:
                return
            
            remote.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            offset = data.find(sni) + 2
            remote.sendall(data[:offset])
            remote.sendall(data[offset:])
            
            event_ready.set()
            self.ready = True
        except socket.error, e:
            logging.warn(e)
            return
     
    def handle(self):
        global HOSTS
        try:
            sock = self.connection
            logging.info('connect from %s' % self.client_address[0])
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            data = sock.recv(2048)
            port = 443
            
            server_name = self.parse(data)
            remote = 0

            event_connected = threading.Event()
            event_ready = threading.Event()

            threadlist = []
            if HOSTS.has_key(server_name):
                addrlist = HOSTS[server_name]
                random.shuffle(addrlist)
                count = len(addrlist)
                for i in xrange(count):
                    addr = (addrlist[i], port)
                    c = threading.Thread(target=self.connect, args=(addr, data, server_name, 10, event_connected, event_ready,), name="connect")
                    c.start()
                    threadlist.append(c)
                    if i < count-1:
                        if event_connected.wait(timeout=0.1):
                            break
                    else:
                        event_connected.wait()
            
            event_ready.wait()
            
            remote = self.remote
            if remote:
                self.forward(sock, remote)
            else:
                sock.close()
        except socket.error, e:
            logging.warn(e)
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
