#!/usr/bin/env python

from audioop import add
import sys
import socket
import _thread
import re
from datetime import datetime
import time
from xml import dom
import argparse
import dns.rdataclass, dns.resolver, dns.rdtypes

parser = argparse.ArgumentParser()

parser.add_argument(
    "--file", "-f", help="Path for hosts file", type=str, required=False
)
parser.add_argument(
    "--blocked_domains",
    "-b",
    help="List of domains to block",
    nargs="+",
    required=False,
)
parser.add_argument(
    "--name_servers",
    "-n",
    help="List of self.name_servers present on the machine",
    nargs="+",
    required=False,
)


# DNSQuery class from http://code.activestate.com/recipes/491264-mini-fake-dns-server/
class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ""

        tipo = (data[2] >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.domain += data[ini + 1 : ini + lon + 1].decode("ascii") + "."
                ini += lon + 1
                lon = data[ini]

    def response(self, ip):
        packet = b""
        if self.domain:
            packet += self.data[:2] + b"\x81\x80"
            packet += (
                self.data[4:6] + self.data[4:6] + b"\x00\x00\x00\x00"
            )  # Questions and Answers Counts
            packet += self.data[12:]  # Original Domain Name Question
            packet += b"\xc0\x0c"  # Pointer to domain name
            packet += b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # Response type, ttl and resource data length -> 4 bytes
            packet += str.join("", map(lambda x: chr(int(x)), ip.split("."))).encode(
                "latin"
            )  # 4bytes of IP
        return packet


class DNSServer:
    def __init__(self, file: str, blocked_domains: map, name_servers: list) -> None:
        self.hostsfile = file
        self.host_ip_map: map = {}
        self.blocked_domains = blocked_domains
        self.name_servers = name_servers
        self.local_resolver: dns.resolver.Resolver = dns.resolver.Resolver()
        self.local_resolver.nameservers = self.name_servers
        self.udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start_server(self):
        if self.hostsfile is not None:
            self.host_ip_map = self.get_host_ip_map(self.hostsfile)

        try:
            host = "127.0.0.1"
            port = 53
            print(f"######## Starting DNS server on {host}:{port} ")
            self.udps.bind((host, port))
        except Exception as e:
            print("Failed to create socket on UDP port 53:", e)
            sys.exit(1)

        print("SimpleDNSServer :: hosts file -> %s\n" % self.hostsfile)

        try:
            while 1:
                data, addr = self.udps.recvfrom(1024)
                _thread.start_new_thread(
                    self.query_and_send_back_ip, (data, addr, datetime.now())
                )
        except KeyboardInterrupt:
            print("\n^C, Exit!")
        except Exception as e:
            print("\nError: %s" % e)
        finally:
            self.udps.close()

    def get_host_ip_map(self, hostsfile):
        host_ip_map = {}
        try:
            f = open(hostsfile)
            for l in f.readlines():
                if not l.startswith("#"):
                    addrs = re.findall("[^\s]+", l)
                    if len(addrs) > 1:
                        for ad in addrs[1:]:
                            host_ip_map[ad] = addrs[0]

        except:
            pass
        finally:
            if not f:
                f.close()

        return host_ip_map

    def query_and_send_back_ip(self, data, addr, reqtime):
        try:
            p = DNSQuery(data)
            print(
                "%s Request domain: %s from %s"
                % (reqtime.strftime("%H:%M:%S.%f"), p.domain, addr[0])
            )
            ip = self.get_ip_address_by_domain(p.domain)
            self.udps.sendto(p.response(ip), addr)
            dis = datetime.now() - reqtime

            print(
                "%s Request from %s cost %s : %s -> %s"
                % (
                    reqtime.strftime("%H:%M:%S.%f"),
                    addr[0],
                    dis.seconds + dis.microseconds / 1000000,
                    p.domain,
                    self.get_ip_address_by_domain(p.domain),
                )
            )
        except Exception as e:
            print("query for:%s error:%s" % (p.domain, e))

    # get_ip_address by domain name
    def get_ip_address_by_domain(self, domain):
        ip_address = "127.0.0.1"
        domain: str = domain.rstrip(".")
        if domain in self.host_ip_map:
            ip_address = self.host_ip_map[domain]
        elif domain in self.blocked_domains:
            return ""
        else:
            answers: dns.resolver.Answer = self.local_resolver.resolve(domain)
            ip_address = answers[0].address

        # else:
        #     list = socket.getaddrinfo(
        #         domain,
        #         80,
        #         socket.AddressFamily.AF_UNSPEC
        #     )
        #     if len(list) > 0:
        # ip_address = list[0][4][0]
        return ip_address


def usage():
    print("")
    print("Usage:")
    print("")
    print("\t# SimpleDNSServer [hosts file]")
    print("")
    print("Description:")
    print("")
    print("\tSimpleDNSServer will redirect DNS query to local machine.")
    print("")
    print("\tYou can optionally specify a hosts file to the command line:\n")
    print("\t\t# SimpleDNSServer hosts\n")
    print(
        "\tThe ip address will be chosen prior to system hosts setting and remote dns query from local machine. \n"
    )
    print(
        "\tIf SimpleDNSServer and the DNS setting machine are same, you should set an optional DNS server in the DNS setting to avoid DNS query failure caused by redirecting recursively.\n"
    )
    print("")

    sys.exit(1)


if __name__ == "__main__":
    args = parser.parse_args()
    file = args.file
    blocked_domains: set = (
        set(args.blocked_domains) if args.blocked_domains is not None else {}
    )
    name_servers: list = args.name_servers if args.name_servers is not None else []
    print("Args passed --->", args)
    server = DNSServer(
        file=file, blocked_domains=blocked_domains, name_servers=name_servers
    )
    server.start_server()
