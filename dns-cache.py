from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A
from socketserver import ThreadingUDPServer, BaseRequestHandler
import socket

class DNSResolver:
    ROOT_DNS_IP = '198.41.0.4'

    @classmethod
    def resolve_query(cls, dns_request):
        query_domain = str(dns_request.q.qname)
        response = DNSRecord(
            DNSHeader(id=dns_request.header.id, qr=1, aa=1, ra=1), q=dns_request.q
        )

        ns_server_ip = cls.ROOT_DNS_IP
        while True:
            ns_response = cls.send_dns_request(ns_server_ip, query_domain)

            if ns_response.header.rcode == 0:
                for rr in ns_response.rr:
                    response.add_answer(RR(rr.rname, rr.rtype, rr.rclass, rr.ttl, A(str(rr.rdata))))
            else:
                break

            if not ns_response.auth:
                break

            ns_server_ip = str(ns_response.auth[0].rdata)

        return response

    @classmethod
    def send_dns_request(cls, ns_server_ip, query_domain):
        query = DNSRecord(q=DNSQuestion(query_domain))
        ns_server_address = (ns_server_ip, 53)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(query.pack(), ns_server_address)
            data, _ = s.recvfrom(1024)

        return DNSRecord.parse(data)


class DNSRequestHandler(BaseRequestHandler):
    def handle(self):
        data, client_socket = self.request
        dns_request = DNSRecord.parse(data)

        if dns_request.q.qtype == 1:
            response = DNSResolver.resolve_query(dns_request)
            client_socket.sendto(response.pack(), self.client_address)


if __name__ == "__main__":
    server_address = ('127.0.0.1', 53)
    with ThreadingUDPServer(server_address, DNSRequestHandler) as server:
        print(f"DNS server listening on {server_address[0]}:{server_address[1]}")
        server.serve_forever()