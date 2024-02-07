"""
This script can be used to see if dhcp server is sending correct next server and file for pxe boot

Run this script to send different dhcp offers from different clients
This script also captures packets but looks like sometime scapy misses

you can also use tcpdump to see offer replies and check if filename are correct
sudo tcpdump -i eth0  udp port 67 and port 68 -vvvv
"""

import sys
import time
import random
import struct
from scapy.all import *
import datetime

def mac_to_bytes(mac_addr):
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")
    
    opt_map = get_opt_map(p[DHCP][0].options)
    if xid not in xid_map:
        return
    if opt_map['message-type'] == 2: #offer
        xid_map[xid]['offer'] = p
        print(f"got {xid_map[xid]['desc']}")
        print_packet(p)

def print_packet(p):
    bootp = p[BOOTP][0]
    macaddr = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", bootp.chaddr[:6])
    sname = bootp.sname.decode().rstrip('\0')
    _file = bootp.file.decode().rstrip('\0')
    print(f"server name: {sname}, file: {_file}")

usecases = [
    ("pxe", None, 'PXEClient:Arch:00000', None),
    ("ipxe", "iPXE", 'PXEClient:Arch:00000', None),
    ("ipxe uefi 7", 'iPXE', 'PXEClient:Arch:00007:UNDI:003000', 7),
    ("ipxe uefi 9", 'iPXE', 'PXEClient:Arch:00009:UNDI:003010', 9),
    ("uefi 7", None,'PXEClient:Arch:00007:UNDI:003000', 7),
    ("uefi 9",None,'PXEClient:Arch:00009:UNDI:003010', 9),
    ("uefi arm", None,'xxx', 0xb), # arm
    ("uefi http",None,'HTTPClient', 0x10), #
    ("uefi http arm",None,'HTTPClient', 0x13), # arm
    ]

# usecases = [
#     ("ipxe", "iPXE", 'PXEClient:Arch:00000', None),
#     ("ipxe uefi 7", 'iPXE', 'PXEClient:Arch:00007:UNDI:003000', 7),
#     ("ipxe uefi 9", 'iPXE', 'PXEClient:Arch:00009:UNDI:003010', 9)
#     ]

print("Start sniffing...")
sniffer = AsyncSniffer(count=100, filter="udp port 68 or port 68", prn=process_packet, stop_filter=stop_filter, timeout=60)
sniffer.start()

# mac_str = Ether().src
mac_str = get_macvlan("test1")
print(f"Sending packets for mac {mac_str}")
xid_map = {}
for desc, user_class, vendor_class_id, arch in usecases:
    packet = create_dhcp_discover(mac_str, user_class, vendor_class_id, arch)
    sendp(packet, iface="eth0")  # Replace "eth0" with your network interface
    xid = packet[BOOTP].xid
    xid_map[xid] = {'desc' : desc, 'discover': None, 'offer': None}
    # infoblox xid is reverse endian
    infoblox_xid = '%x'%struct.unpack('I',struct.pack('>I', xid))
    print(f"   Sent DHCP Discover packet[0x{xid:x} {infoblox_xid}] for {desc}: User Class: {user_class}, Vendor Class: {vendor_class_id} Arch: {arch}")
    time.sleep(5)

# final wait for any remaining packets
if sniffer.running:
    try:
        sniffer.join()
        sniffer.stop()
    except Exception as e:
        print("error:",e)

for k, v in xid_map.items():
    print(v['desc'])
    if v['offer'] is None:
        print("No offer received")
    else:
        print_packet(v['offer'])
