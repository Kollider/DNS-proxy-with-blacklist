# -*- coding: utf-8 -*-
from __future__ import print_function

from dnslib.proxy import *

blacklist = ['facebook.com', 'vk.com', 'twitter.com', 'google.com']


class ProxyResolver(BaseResolver):
    def __init__(self, address, port, timeout=0):
        self.address = address
        self.port = port
        self.timeout = timeout

    def resolve(self, request, handler):
        try:
            flag = 1
            for i in blacklist:
                if i in str(request):
                    reply = request.reply()
                    reply.header.rcode = getattr(RCODE, 'REFUSED')
                    for j in range(3):
                        print('\nThis address is in the blacklist!\n')
                    flag = 0
            if flag:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.address, self.port, timeout=self.timeout)
                else:
                    proxy_r = request.send(self.address, self.port, tcp=True, timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)

        except socket.timeout:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        return reply


if __name__ == '__main__':

    import argparse, time

    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port", "-p", type=int, default=53, metavar="<port>", help="Local proxy port (default:53)")
    p.add_argument("--address", "-a", default="127.0.0.1", metavar="<address>",
                   help="Local proxy listen address (default:all)")
    p.add_argument("--upstream", "-u", default="8.8.8.8:53", metavar="<dns server:port>",
                   help="Upstream DNS server:port (default:8.8.8.8:53)")
    p.add_argument("--tcp", action='store_true', default=False, help="TCP proxy (default: UDP only)")
    p.add_argument("--timeout", "-o", type=float, default=5, metavar="<timeout>", help="Upstream timeout (default: 5s)")
    p.add_argument("--passthrough", action='store_true', default=False,
                   help="Dont decode/re-encode request/response (default: off)")
    p.add_argument("--log", default="request,reply,truncated,error",
                   help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix", action='store_true', default=False,
                   help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns, _, args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    print("Starting Proxy Resolver (%s:%d -> %s:%d) [%s]" % (
        args.address or "*", args.port,
        args.dns, args.dns_port,
        "UDP/TCP" if args.tcp else "UDP"))

    resolver = ProxyResolver(args.dns, args.dns_port, args.timeout)
    handler = PassthroughDNSHandler if args.passthrough else DNSHandler
    logger = DNSLogger(args.log, args.log_prefix)
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger,
                           handler=handler)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger,
                               handler=handler)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)
