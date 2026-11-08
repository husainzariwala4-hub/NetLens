import pytest
from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP

from netlens.parser import normalize_packet


def normalized(packet):
    return normalize_packet(Ether(bytes(packet)), 1, "test")


@pytest.mark.parametrize(("response", "expected"), [(0, "DNS query"), (1, "DNS response")])
def test_dns_query_and_response_have_different_explanations(response, expected):
    packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=53 if response else 12345, dport=12345 if response else 53) / DNS(qr=response, qd=DNSQR(qname="private.example"))
    result = normalized(packet)
    assert result.explanation.title == expected
    assert "192.0.2.1" in result.explanation.description
    assert "192.0.2.2" in result.explanation.description
    assert "private.example" not in result.model_dump_json()
    assert result.explanation.limitation


@pytest.mark.parametrize(("flags", "expected"), [("S", "Connection attempt"), ("SA", "Connection reply"), ("R", "Connection reset"), ("F", "Connection closing"), ("A", "TCP traffic")])
def test_tcp_flags_describe_observed_event(flags, expected):
    packet = Ether() / IP() / TCP(flags=flags)
    assert normalized(packet).explanation.title == expected


def test_http_and_tls_do_not_claim_more_than_observed():
    http = normalized(Ether() / IP() / TCP() / Raw(b"GET /private HTTP/1.1\r\n\r\n"))
    tls = normalized(Ether() / IP() / TCP() / Raw(b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"))
    assert http.explanation.title == "Web request"
    assert "private" not in http.model_dump_json()
    assert tls.explanation.title == "Possible encrypted connection"
    assert "not proof" in tls.explanation.limitation


def test_unknown_packet_does_not_invent_endpoints():
    result = normalized(Ether(type=0x9000) / Raw(b"data"))
    assert result.explanation.title == "Other network activity"
    assert "unknown source" in result.explanation.description
    assert "unknown destination" in result.explanation.description
