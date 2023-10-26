import argparse
import time
from ipaddress import ip_address

from dnslib import RR, A, DNSLabel
from dnslib.dns import CLASS, QTYPE, RD, RDMAP
from dnslib.server import BaseResolver, DNSServer


class Record:
    def __init__(self, rname, rtype, rdata, rclass="IN", ttl=300) -> None:
        """A DNS record

        Args:
            name (str): name of the record (i.e. 'example.com')
            type (str): type of the record (i.e. 'A')
            data (str): the actual data to store in the record (i.e. '1.2.3.4')

        """
        self.rname = DNSLabel(rname)
        self.rtype = getattr(QTYPE, rtype)
        self.rclass = getattr(CLASS, rclass)
        rd = RDMAP.get(rtype, RD)
        self.rdata = rd(rdata)
        self.ttl = ttl

        self.rr = RR(
            rname=self.rname,
            ttl=self.ttl,
            rclass=self.rclass,
            rtype=self.rtype,
            rdata=self.rdata,
        )

    def matches(self, qname, qtype):
        return qname == self.rname and qtype == self.rtype


class Resolver(BaseResolver):
    """A basic DNS resolver"""

    def __init__(self, default_ip):
        super().__init__()
        self.records = []
        self.default_ip = default_ip

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype

        for record in self.records:
            if record.matches(qname, qtype):
                reply.add_answer(record.rr)

        # if no record was found and the query is of type A, return a default answer
        if not reply.rr and qtype == QTYPE.A:
            reply.add_answer(
                RR(rname=qname, rtype=qtype, ttl=300, rdata=A(self.default_ip))
            )

        return reply

    def add_record(self, *args, **kwargs):
        self.records.append(Record(*args, **kwargs))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Mock DNS Server")
    p.add_argument(
        "--address",
        "-a",
        type=ip_address,
        required=True,
        help="Address in DNS response",
    )

    args = p.parse_args()
    ip = str(args.address)

    resolver = Resolver(ip)
    server = DNSServer(resolver, port=10053)

    server.start_thread()

    try:
        while server.isAlive():
            time.sleep(5)
    except KeyboardInterrupt:
        pass
