#! /usr/bin/env python
# -*- coding: utf8 -*-

import argparse
import socket
from SocketServer import ThreadingUDPServer, DatagramRequestHandler

from dnslib import DNSRecord
import logbook

import icmp


class ProxyHandler(DatagramRequestHandler):
    '''DNS Proxy Server'''
    def handle(self):
        data, client = self.request

        domain = str(DNSRecord.parse(data).q.qname)
        logbook.info("query name: {}".format(domain))

        basic_domain = ".".join(domain.rstrip(".").split(".")[-2:])
        logbook.info(basic_domain)
        if basic_domain in CHINA_DOMAIN_LIST or basic_domain.endswith("cn"):
            logbook.info("Go dirty DNS")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (args.dirty, 53))
            try:
                dns_body, _ = sock.recvfrom(8192)
            except socket.timeout:
                logbook.warning("timeout")
                client.close()
                return
        else:
            logbook.info("Go ICMP DNS")
            remote = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            identifier = self.client_address[1]
            send_packet = icmp.pack(identifier, 53, data)
            remote.sendto(send_packet, (args.remote, 1))
            try:
                dns_body = icmp.unpack(remote.recv(8192))
            except:
                logbook.warning("timeout")
                client.close()
                return

        try:
            ip_list = "\n".join(
                [str(r.rdata) for r in DNSRecord.parse(dns_body).rr]
                )
        except Exception, e:
            logbook.error(e)
            ip_list = "error occur!"
        logbook.info("record name:\n{}".format(ip_list))

        client.sendto(dns_body, self.client_address)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument(
        "--port", "-p", type=int, default=53,
        metavar="<port>",
        help="Local proxy port (default:53)")
    p.add_argument(
        "--address", "-a", default="127.0.0.1",
        metavar="<address>",
        help="Local proxy listen address (default:all)")
    p.add_argument(
        "--remote", "-r", default="23.226.226.196",
        metavar="<remote dns server>",
        help="Upstream DNS server (default:23.226.226.196)")
    p.add_argument(
        "--dirty", "-d", default="114.114.114.114",
        metavar="<china dirty dns server>",
        help="Dirty DNS server (default:114.114.114.114)")
    args = p.parse_args()

    china_list_file = open("./china_domain.txt")
    CHINA_DOMAIN_LIST = china_list_file.read().split('\n')
    china_list_file.close()

    socket.setdefaulttimeout(1)
    server = ThreadingUDPServer((args.address, args.port), ProxyHandler)
    logbook.info(
        "Start proxy server at {}:{}"
        .format(args.address, args.port))

    server.serve_forever()
