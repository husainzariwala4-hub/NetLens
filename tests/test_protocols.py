from scapy.all import ARP, DNS, DNSQR, Ether, ICMPv6EchoRequest, IP, IPv6, Raw, TCP, UDP

from netlens.parser import normalize_packet


def summary(packet):
    # Decode serialized packets as Scapy does for capture.
    return normalize_packet(Ether(bytes(packet)), 1, "test-session")


def test_dns_is_recognized_without_storing_query():
    packet = Ether() / IP() / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="private.example"))
    result = summary(packet)
    assert (result.protocol, result.transport_protocol) == ("DNS", "UDP")
    assert "private.example" not in result.model_dump_json()


def test_http_request_response_and_payload_privacy():
    for content in (b"GET /private HTTP/1.1\r\nHost: example.com\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"):
        result = summary(Ether() / IP() / TCP(sport=1234, dport=80) / Raw(content))
        assert (result.protocol, result.transport_protocol) == ("HTTP", "TCP")
        assert "private" not in result.model_dump_json()


def test_tls_record_and_port_only_are_distinct():
    tls = summary(Ether() / IP() / TCP(sport=1234, dport=443) / Raw(b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"))
    port_only = summary(Ether() / IP() / TCP(sport=1234, dport=443, flags="S"))
    assert (tls.protocol, tls.transport_protocol) == ("TLS", "TCP")
    assert port_only.protocol == "TCP"


def test_arp_and_icmpv6():
    assert summary(Ether() / ARP()).protocol == "ARP"
    assert summary(Ether() / IPv6() / ICMPv6EchoRequest()).protocol == "ICMPv6"
