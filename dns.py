#! /usr/bin/env python
# -*- coding: utf8 -*-

import argparse
import socket
from SocketServer import ForkingUDPServer, DatagramRequestHandler
import struct


from dnslib import DNSRecord
import logbook

import icmp


class ProxyHandler(DatagramRequestHandler):
    '''DNS Proxy Server'''
    def handle(self):
        data, client = self.request
        logbook.info(
            "query name: {}".format(DNSRecord.parse(data).q.qname))

        remote = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        identifier = self.client_address[1]
        send_packet = icmp.pack(identifier, 53, data)
        remote.sendto(send_packet, (args.remote, 1))
        dns_body = icmp.unpack(remote.recv(8192))

        ip_list = "\n".join(
            [str(r.rdata) for r in DNSRecord.parse(dns_body).rr]
            )
        logbook.info("record name:\n{}".format(ip_list))

        client.sendto(dns_body, self.client_address)

#         send_data = struct.pack("!H", len(data)) + data
#         recv_data = send_tcp(send_data)
#         if recv_data:
#             recv_data = recv_data[2:]
#             ip_list = "\n".join(
#                 [str(r.rdata) for r in DNSRecord.parse(recv_data).rr]
#                 )
#             logbook.info("record name:\n{}".format(ip_list))
#             client.sendto(recv_data, self.client_address)
#
# def send_tcp(data):
#     """
#         Helper function to send/receive DNS TCP request
#         (in/out packets will have prepended TCP length header)
#     """
#     sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#     sock.connect((args.dns, args.dns_port))
#     sock.sendall(data)
#     response = sock.recv(8192)
#     try:
#         assert len(response) >= 2
#     except AssertionError:
#         sock.close()
#         logbook.error("ops! empty response")
#     else:
#         length = struct.unpack("!H",bytes(response[:2]))[0]
#         while len(response) - 2 < length:
#             response += sock.recv(8192)
#         sock.close()
#         return response


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument(
        "--port","-p", type=int, default=53,
        metavar="<port>",
        help="Local proxy port (default:53)")
    p.add_argument(
        "--address", "-a", default="127.0.0.1",
        metavar="<address>",
        help="Local proxy listen address (default:all)")
    p.add_argument(
        "--remote", "-r", default="chashuibiao.org",
        metavar="<remote dns server>",
        help="Upstream DNS server (default:chashuibiao.org)")
    args = p.parse_args()

    server = ForkingUDPServer((args.address, args.port), ProxyHandler)
    logbook.info(
        "Start proxy server at {}:{}"
        .format(args.address, args.port))
    logbook.info(
        "Connect DNS server at {}".format(args.remote))

    server.serve_forever()
