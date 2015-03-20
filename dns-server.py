#!/usr/bin/env python
# -*- coding: utf8 -*-

import argparse
import socket
import SocketServer

import logbook

import icmp
from ThreadedICMPServer import ThreadedICMPServer


class ICMPRequestHandler(SocketServer.BaseRequestHandler):
    '''
    ICMP
    '''
    def handle(self):
        raw_data, local = self.request
        identifier, sequence, content = icmp.unpack_reply(raw_data)
        logbook.info("address: {} sequence: {}"
                     .format(self.client_address[0], sequence))

        if sequence == 53:
            remote = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM)
            remote.sendto(content, (args.dns, args.dns_port))
            icmp_body, _ = remote.recvfrom(8192)
        else:
            logbook.warn(repr(content))
            icmp_body = content

        logbook.info("send back the content")
        packet = icmp.pack_reply(identifier, sequence, icmp_body)
        local.sendto(packet, self.client_address)


if __name__ == '__main__':
    from os.path import join, dirname, abspath, exists
    server_log_file = join(dirname(abspath(__file__)), "server.log")
    if not exists(server_log_file):
        open(server_log_file, "w").close()

    local_log = logbook.FileHandler(server_log_file)
    local_log.format_string = (
        u'[{record.time:%H:%M:%S}] '
        u'lineno:{record.lineno} '
        u'{record.level_name}:{record.message}')
    local_log.push_application()

    p = argparse.ArgumentParser(description="DNS Proxy Server")
    p.add_argument(
        "--upstream", "-u", default="8.8.8.8:53",
        metavar="<dns server:port>",
        help="Upstream DNS server:port (default:8.8.8.8:53)")
    args = p.parse_args()

    args.dns, _, args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    server = ThreadedICMPServer(('0.0.0.0', 1), ICMPRequestHandler)
    logbook.info("start ICMP server...")
    server.serve_forever()
