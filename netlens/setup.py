"""Support the interactive Windows capture launcher."""
import json
import sys
from scapy.all import get_working_ifaces
from scapy.config import conf

if __name__ == "__main__":
    if sys.argv[1:] == ["driver"]:
        print("ready" if conf.use_pcap else "missing")
    elif sys.argv[1:] == ["interfaces"]:
        print(json.dumps([{"name": str(i.name), "description": str(i.description), "id": str(i.network_name)} for i in get_working_ifaces()]))
    else:
        raise SystemExit("Expected driver or interfaces")
