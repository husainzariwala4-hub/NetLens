"""Evidence-based, deterministic descriptions of individual packet events."""
from netlens.models import PacketExplanation, PacketSummary


def explain(packet: PacketSummary) -> PacketExplanation:
    source = packet.source or "an unknown source"
    destination = packet.destination or "an unknown destination"
    endpoints = f"This packet traveled from {source} to {destination}. "
    details = {
        "dns_query": ("DNS query", "A device is asking a DNS service for information about a name. This can be a step in finding the address of a website or another service, similar to looking up a contact before calling.", "A DNS lookup does not tell us whether a website was opened or whether the request succeeded. The queried name is not stored."),
        "dns_response": ("DNS response", "A DNS service is replying to a request for information about a name. The answer may help a device find a service it wants to contact.", "A response can also report that a name was not found or another error. This summary does not include the name or answer."),
        "http_request": ("Web request", "A device sent a recognizable HTTP request. A browser or another application might send a request like this to ask a web service for a page or resource.", "This packet alone does not show whether the request succeeded; the URL and contents are not stored."),
        "http_response": ("Web response", "A device sent a recognizable HTTP response, which can be part of a web service's reply to an earlier request.", "This summary does not show the response status or its contents and cannot establish what happened in the whole exchange."),
        "tls_record": ("Possible encrypted connection", "The packet contains a pattern that looks like a TLS record. TLS is often used to protect communication between an application and a service, such as a secure website.", "This is a packet-level match, not proof of the application or what was exchanged. NetLens does not decrypt the traffic."),
        "tcp_connect": ("Connection attempt", "This TCP packet asks to start a connection. Applications often do this before exchanging data with another device.", "One request does not show whether the connection was accepted or why it was attempted."),
        "tcp_reply": ("Connection reply", "This TCP packet replies to a request to start a connection. It is one step in establishing a connection between devices.", "This single packet does not confirm that the full connection was established."),
        "tcp_reset": ("Connection reset", "This TCP packet signals that a connection should be reset. This can happen for ordinary reasons, such as a service refusing or closing a connection.", "The packet does not reveal the reason for the reset."),
        "tcp_close": ("Connection closing", "This TCP packet signals that one side is finished sending data on a connection.", "The packet alone does not show the reason for closing or the complete connection history."),
        "tcp": ("TCP traffic", "This packet uses TCP, a protocol applications commonly use to exchange data as part of a connection.", "The packet alone does not tell us which application sent it or what the complete exchange means."),
        "udp": ("UDP traffic", "This packet uses UDP, a protocol applications can use to send individual messages. It is used for many purposes, including calls, games, and name lookups.", "UDP alone does not identify the application or confirm that the message arrived."),
        "arp": ("Local network address lookup", "This ARP packet is part of matching network addresses to hardware addresses on a local IPv4 network, which helps devices send traffic nearby.", "This summary does not tell us the full request or whether it received a reply."),
        "icmp": ("Network control message", "This ICMP message carries network status or diagnostic information. Messages like these can be used to check reachability or report a delivery problem.", "The message type and code are not available in this summary, so its specific purpose is unknown."),
        "ip": ("Network packet", "This packet uses IP, the addressing system that helps route traffic between devices.", "There is not enough information here to identify the application or the purpose of this packet."),
        "unknown": ("Other network activity", "A network packet was observed, but the available details do not identify its specific purpose.", "The protocol or endpoints may be unavailable in this summary."),
    }
    title, description, limitation = details.get(packet.event_type or "unknown", details["unknown"])
    return PacketExplanation(title=title, description=endpoints + description, limitation=limitation)
