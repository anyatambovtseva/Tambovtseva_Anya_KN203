import socket
import struct
import time
import pickle
import os
from threading import Thread, Lock


class DNSCache:
    def __init__(self):
        self.records = {
            1: {},  # A
            28: {},  # AAAA
            2: {},  # NS
            12: {}  # PTR
        }
        self.lock = Lock()

    def add(self, rtype, key, value, ttl):
        expiry = time.time() + ttl
        with self.lock:
            if key not in self.records[rtype]:
                self.records[rtype][key] = []
            self.records[rtype][key].append((value, expiry))

    def get(self, rtype, key):
        now = time.time()
        with self.lock:
            if key in self.records[rtype]:
                valid_records = [rec[0] for rec in self.records[rtype][key] if rec[1] > now]
                if valid_records:
                    return valid_records
        return None

    def clean(self):
        now = time.time()
        with self.lock:
            for rtype in self.records:
                for key in list(self.records[rtype].keys()):
                    self.records[rtype][key] = [rec for rec in self.records[rtype][key] if rec[1] > now]
                    if not self.records[rtype][key]:
                        del self.records[rtype][key]

    def save(self, filename):
        with self.lock, open(filename, 'wb') as f:
            pickle.dump(self.records, f)

    def load(self, filename):
        if os.path.exists(filename):
            with self.lock, open(filename, 'rb') as f:
                self.records = pickle.load(f)
            self.clean()


class DNSServer:
    def __init__(self):
        self.cache = DNSCache()
        self.cache.load('dns_cache.pkl')
        self.running = True
        self.upstream_dns = ('8.8.8.8', 53)

    def start(self):
        Thread(target=self.cleaner).start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('0.0.0.0', 53))
            print("DNS server started on port 53")
            while self.running:
                try:
                    data, addr = s.recvfrom(512)
                    Thread(target=self.handle_query, args=(s, data, addr)).start()
                except Exception as e:
                    print(f"Server error: {e}")

    def cleaner(self):
        while self.running:
            self.cache.clean()
            time.sleep(5)

    def handle_query(self, sock, data, addr):
        try:
            id = data[:2]
            query = data[12:]
            qname, qtype = self.parse_question(query)

            print(f"Query: {qname} (type: {qtype}) from {addr[0]}")

            cached = self.cache.get(qtype, qname)
            if cached:
                print(f"Cache hit for {qname}")
                print("=== SERVING FROM CACHE ===")
                if qtype in (1, 28):  # A or AAAA record
                    for record in cached:
                        sock.sendto(self.build_response(id, qname, qtype, record), addr)
                    return

            print(f"Forwarding query for {qname}")
            response = self.forward_query(data)
            if response:
                self.parse_and_cache(response)
                sock.sendto(response, addr)
        except Exception as e:
            print(f"Query handling error: {e}")

    def forward_query(self, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(data, self.upstream_dns)
                return s.recv(512)
        except Exception as e:
            print(f"Forwarding error: {e}")
            return None

    def parse_question(self, data):
        parts = []
        pos = 0
        while True:
            length = data[pos]
            if length == 0:
                break
            parts.append(data[pos + 1:pos + 1 + length].decode('ascii', errors='ignore'))
            pos += 1 + length
        qname = '.'.join(parts).lower()
        qtype = struct.unpack('!H', data[pos + 1:pos + 3])[0]
        return qname, qtype

    def parse_and_cache(self, data):
        try:
            pos = 12
            qdcount = struct.unpack('!H', data[4:6])[0]
            for _ in range(qdcount):
                while data[pos] != 0:
                    pos += 1 + data[pos]
                pos += 5

            ancount = struct.unpack('!H', data[6:8])[0]
            nscount = struct.unpack('!H', data[8:10])[0]
            arcount = struct.unpack('!H', data[10:12])[0]

            for _ in range(ancount + nscount + arcount):
                pos, name, rtype, ttl, rdata = self.parse_rr(data, pos)
                name = name.lower()

                if rtype == 1:  # A record
                    ip = '.'.join(map(str, rdata))
                    self.cache.add(rtype, name, ip, ttl)
                    print(f"Cached A record: {name} -> {ip} (TTL: {ttl})")
                elif rtype == 28:  # AAAA record
                    ip = ':'.join(f'{x:02x}' for x in rdata)
                    self.cache.add(rtype, name, ip, ttl)
                    print(f"Cached AAAA record: {name} -> {ip} (TTL: {ttl})")
                elif rtype == 2:  # NS record
                    ns = rdata.lower()
                    self.cache.add(rtype, name, ns, ttl)
                    print(f"Cached NS record: {name} -> {ns} (TTL: {ttl})")
                elif rtype == 12:  # PTR record
                    ptr = rdata.lower()
                    self.cache.add(rtype, name, ptr, ttl)
                    print(f"Cached PTR record: {name} -> {ptr} (TTL: {ttl})")
        except Exception as e:
            print(f"Cache parsing error: {e}")

    def parse_rr(self, data, pos):
        name, pos = self.parse_name(data, pos)
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlength]

        if rtype in (1, 28):  # A or AAAA record
            rdata = tuple(rdata)
        elif rtype in (2, 12):  # NS or PTR record
            rdata, _ = self.parse_name(data, pos)

        pos += rdlength
        return pos, name, rtype, ttl, rdata

    def parse_name(self, data, pos):
        parts = []
        original_pos = pos
        while True:
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xc0:
                ptr = struct.unpack('!H', data[pos:pos + 2])[0] & 0x3fff
                part, _ = self.parse_name(data, ptr)
                parts.append(part)
                pos += 2
                break
            part = data[pos + 1:pos + 1 + length].decode('ascii', errors='ignore')
            parts.append(part)
            pos += 1 + length

        if original_pos != pos and (data[original_pos] & 0xc0):
            pos = original_pos + 2

        return '.'.join(parts), pos

    def build_response(self, id, qname, qtype, answer):
        response = bytearray()
        response += id  # Transaction ID
        response += b'\x81\x80'  # Flags (Standard query response, no error)
        response += b'\x00\x01'  # Questions
        response += b'\x00\x01'  # Answer RRs
        response += b'\x00\x00'  # Authority RRs
        response += b'\x00\x00'  # Additional RRs

        # Question section
        for part in qname.split('.'):
            response += bytes([len(part)]) + part.encode()
        response += b'\x00'
        response += struct.pack('!H', qtype)
        response += b'\x00\x01'

        # Answer section
        for part in qname.split('.'):
            response += bytes([len(part)]) + part.encode()
        response += b'\x00'
        response += struct.pack('!H', qtype)
        response += b'\x00\x01'
        response += b'\x00\x00\x00\x3c'

        if qtype == 1:  # A record
            response += b'\x00\x04'
            response += bytes(map(int, answer.split('.')))
        elif qtype == 28:  # AAAA record
            hex_parts = answer.split(':')
            ip_bytes = bytes.fromhex(''.join(hex_parts))
            response += b'\x00\x10'
            response += ip_bytes

        return bytes(response)

    def shutdown(self):
        print("\nShutting down server...")
        self.running = False
        self.cache.save('dns_cache.pkl')
        print("Cache saved to dns_cache.pkl")


if __name__ == '__main__':
    server = DNSServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.shutdown()
