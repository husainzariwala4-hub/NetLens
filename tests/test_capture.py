import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw

from netlens.capture import CaptureError, CaptureService


class FakeThread:
    def __init__(self):
        self.alive = True

    def is_alive(self):
        return self.alive

    def join(self, timeout=None):
        pass


class FakeSniffer:
    instances = []

    def __init__(self, **kwargs):
        self.options = kwargs
        self.thread = FakeThread()
        self.running = False
        self.instances.append(self)

    def start(self):
        self.running = True
        self.options["started_callback"]()

    def stop(self, join=True):
        self.running = False
        self.thread.alive = False


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setattr("netlens.capture.AsyncSniffer", FakeSniffer)
    monkeypatch.setattr("netlens.capture.get_if_list", lambda: ["authorized", "other"])
    return CaptureService({"authorized"}, capacity=2)


def test_authorization_and_lifecycle(service):
    assert service.interfaces() == [{"name": "authorized", "allowed": True}, {"name": "other", "allowed": False}]
    with pytest.raises(CaptureError, match="not authorized"):
        service.start("other")
    status = service.start("authorized")
    assert status.state == "running" and status.session_id
    with pytest.raises(CaptureError, match="already active"):
        service.start("authorized")
    assert service.stop().state == "idle"
    assert service.stop().state == "idle"
    assert service.start("authorized").session_id != status.session_id


def test_bounded_metadata_filter_and_no_payload(service):
    service.start("authorized")
    for packet in [IP(src="192.0.2.1", dst="192.0.2.2") / TCP() / Raw(b"secret"),
                   IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(), Ether()]:
        service._record(packet)
    status = service.status()
    assert (status.captured, status.dropped) == (3, 1)
    packets, total = service.packets(0, 10)
    assert total == 2
    assert packets[0].source == "2001:db8::1"
    assert packets[1].source is None
    assert "secret" not in str([packet.model_dump() for packet in packets])
    filtered, count = service.packets(0, 10, "udp")
    assert count == 1 and filtered[0].protocol == "UDP"
    service.stop()


def test_malformed_packet_does_not_break_capture(service):
    service.start("authorized")
    service._record(object())
    assert service.status().captured == 0
    assert service.status().state == "running"
    service.stop()


def test_unexpected_sniffer_exit_reports_error(service):
    service.start("authorized")
    service._sniffer.running = False
    service._sniffer.thread.alive = False
    assert service.status().state == "error"


def test_technical_packet_metadata(service):
    service.start("authorized")
    service._record(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.0.2.1", dst="192.0.2.2", ttl=42) / TCP(sport=1234, dport=443, flags="S") / Raw(b"private payload"))
    item = service.packets(0, 10)[0][0]
    assert (item.source_port, item.destination_port, item.ttl, item.tcp_flags) == (1234, 443, 42, "S")
    assert item.source_mac == "00:11:22:33:44:55"
    assert "private payload" not in item.model_dump_json()
    service.stop()


def test_new_capture_discards_prior_buffer(service):
    service.start("authorized")
    service._record(IP() / TCP())
    service.stop()
    assert service.packets(0, 10)[1] == 1
    service.start("authorized")
    assert service.packets(0, 10)[1] == 0
    service.stop()


def test_late_start_is_stopped_after_startup_timeout(monkeypatch):
    class LateSniffer(FakeSniffer):
        def start(self):
            self.running = True

    monkeypatch.setattr("netlens.capture.AsyncSniffer", LateSniffer)
    monkeypatch.setattr("netlens.capture.get_if_list", lambda: ["authorized"])
    service = CaptureService({"authorized"})
    with pytest.raises(CaptureError, match="Could not start"):
        service.start("authorized")
    sniffer = service._sniffer
    assert service.status().state == "error"
    sniffer.options["started_callback"]()
    assert not sniffer.running
    assert not sniffer.thread.is_alive()
