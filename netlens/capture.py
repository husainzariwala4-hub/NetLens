"""Bounded, metadata-only live capture, independent of the HTTP layer."""
import logging
import threading
from collections import deque
from uuid import uuid4

from scapy.all import AsyncSniffer, get_if_list

from netlens.models import CaptureStatus, PacketSummary
from netlens.parser import normalize_packet

logger = logging.getLogger(__name__)


class CaptureError(Exception):
    pass


class CaptureService:
    def __init__(self, allowed_interfaces: set[str], capacity: int = 5000):
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.allowed_interfaces = allowed_interfaces
        self.capacity = capacity
        self._packets: deque[PacketSummary] = deque(maxlen=capacity)
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._sniffer = None
        self._status = CaptureStatus(state="idle")
        self._next_id = 1

    def interfaces(self) -> list[dict]:
        return [{"name": name, "allowed": name in self.allowed_interfaces} for name in get_if_list()]

    def status(self) -> CaptureStatus:
        with self._lock:
            if self._status.state == "running" and self._sniffer and not self._sniffer.running:
                self._status.state = "error"
                self._status.error = "Capture stopped unexpectedly; check capture permissions and interface availability."
            return self._status.model_copy()

    def start(self, interface: str) -> CaptureStatus:
        with self._lifecycle:
            with self._lock:
                if self._sniffer and self._sniffer.thread and self._sniffer.thread.is_alive():
                    raise CaptureError("A capture is already active or still stopping.")
                if interface not in self.allowed_interfaces:
                    raise CaptureError("Interface is not authorized in NETLENS_ALLOWED_INTERFACES.")
                if interface not in get_if_list():
                    raise CaptureError("Interface is not available.")
                self._packets.clear()
                self._status = CaptureStatus(state="starting", interface=interface, session_id=str(uuid4()))
                ready = threading.Event()
                aborted = threading.Event()

                def started():
                    ready.set()
                    if aborted.is_set():
                        sniffer.stop(join=False)

                sniffer = AsyncSniffer(iface=interface, store=False, prn=self._record, started_callback=started)
                self._sniffer = sniffer
            try:
                sniffer.start()
                if not ready.wait(3):
                    aborted.set()
                    # Handle either ordering of the timeout and the startup callback.
                    if ready.is_set():
                        try:
                            sniffer.stop(join=False)
                        except Exception:
                            logger.exception("late_capture_stop_failed")
                    with self._lock:
                        self._status.state = "error"
                        self._status.error = "Could not start capture. Check permissions, Npcap/libpcap, and the interface."
                    raise CaptureError(self._status.error)
                with self._lock:
                    self._status.state = "running"
                    logger.info("capture_started interface=%s session=%s", interface, self._status.session_id)
                    return self._status.model_copy()
            except CaptureError:
                raise
            except Exception as exc:
                with self._lock:
                    self._status.state = "error"
                    self._status.error = "Could not start capture. Check permissions and the capture driver."
                logger.exception("capture_start_failed")
                raise CaptureError(self._status.error) from exc

    def stop(self) -> CaptureStatus:
        with self._lifecycle:
            with self._lock:
                sniffer = self._sniffer
                if not sniffer or not sniffer.thread or not sniffer.thread.is_alive():
                    if self._status.state != "error":
                        self._status.state = "idle"
                    return self._status.model_copy()
                self._status.state = "stopping"
            try:
                sniffer.stop(join=False)
                sniffer.thread.join(timeout=3)
            except Exception as exc:
                with self._lock:
                    self._status.state = "error"
                    self._status.error = "Could not stop capture cleanly."
                raise CaptureError(self._status.error) from exc
            with self._lock:
                if sniffer.thread.is_alive():
                    self._status.state = "error"
                    self._status.error = "Capture is still stopping; retry shortly."
                    raise CaptureError(self._status.error)
                self._status.state = "idle"
                self._status.error = None
                logger.info("capture_stopped session=%s", self._status.session_id)
                return self._status.model_copy()

    def _record(self, packet) -> None:
        try:
            with self._lock:
                summary = normalize_packet(packet, self._next_id, self._status.session_id)
                self._next_id += 1
                self._status.captured += 1
                if len(self._packets) == self.capacity:
                    self._status.dropped += 1
                self._packets.append(summary)
        except Exception:
            logger.exception("packet_metadata_failed")

    def packets(self, offset: int, limit: int, protocol: str | None = None) -> tuple[list[PacketSummary], int]:
        with self._lock:
            items = list(self._packets)
        if protocol:
            items = [packet for packet in items if packet.protocol.casefold() == protocol.casefold()]
        return items[offset:offset + limit], len(items)
