"""Translate Scapy packets to bounded, payload-free metadata."""
from datetime import datetime, timezone
import re
from scapy.all import ARP, DNS, Ether, IP, IPv6, TCP, UDP, ICMP
from netlens.models import PacketSummary
from netlens.explanations import explain


HTTP_START = re.compile(rb"^(?:(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) [^\r\n ]+ HTTP/1\.[01]|HTTP/1\.[01] [1-5][0-9]{2})(?:[ \r\n]|$)")


def detect_protocol(packet, tcp, udp, ip) -> str:
    # DNS must be decoded as DNS, not just sent to a familiar port.
    if packet.haslayer(DNS) and (tcp or udp):
        return "DNS"
    if tcp:
        payload = bytes(tcp.payload)[:512]
        if HTTP_START.match(payload):
            return "HTTP"
        # Recognize a plausible TLS record header; a port alone is not evidence.
        if (len(payload) >= 5 and payload[0] in (20, 21, 22, 23)
                and payload[1] == 3 and payload[2] <= 4
                and 0 < int.from_bytes(payload[3:5], "big") <= 18432):
            return "TLS"
        return "TCP"
    if udp:
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6) and ip.nh == 58:
        return "ICMPv6"
    return "IPv6" if packet.haslayer(IPv6) else "IPv4" if packet.haslayer(IP) else "Other"


def normalize_packet(packet, packet_id: int, session_id: str) -> PacketSummary:
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    eth = packet.getlayer(Ether)
    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    transport = tcp or udp
    protocol = detect_protocol(packet, tcp, udp, ip)
    event_type = None
    if protocol == "DNS":
        event_type = "dns_response" if packet[DNS].qr else "dns_query"
    elif protocol == "HTTP":
        event_type = "http_response" if bytes(tcp.payload).startswith(b"HTTP/") else "http_request"
    elif protocol == "TLS":
        event_type = "tls_record"
    elif protocol == "TCP":
        flags = int(tcp.flags)
        event_type = "tcp_reset" if flags & 4 else "tcp_reply" if flags & 2 and flags & 16 else "tcp_connect" if flags & 2 else "tcp_close" if flags & 1 else "tcp"
    elif protocol == "UDP":
        event_type = "udp"
    elif protocol == "ARP":
        event_type = "arp"
    elif protocol in ("ICMP", "ICMPv6"):
        event_type = "icmp"
    elif protocol in ("IPv4", "IPv6"):
        event_type = "ip"
    result = PacketSummary(id=packet_id, session_id=session_id,
        timestamp=datetime.fromtimestamp(float(packet.time), timezone.utc),
        source=str(ip.src) if ip else None, destination=str(ip.dst) if ip else None,
        protocol=protocol, transport_protocol="TCP" if tcp else "UDP" if udp else None, length=len(packet),
        source_port=int(transport.sport) if transport else None,
        destination_port=int(transport.dport) if transport else None,
        source_mac=str(eth.src) if eth else None, destination_mac=str(eth.dst) if eth else None,
        ttl=int(ip.ttl) if ip and packet.haslayer(IP) else int(ip.hlim) if ip else None,
        tcp_flags=str(tcp.flags) if tcp else None, event_type=event_type)
    result.explanation = explain(result)
    return result
