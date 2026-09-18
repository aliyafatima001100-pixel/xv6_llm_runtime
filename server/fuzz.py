from scapy.all import *

def send_test(packet, label):
    print(f"\nsending: {label}")
    send(IP(dst="10.0.0.2")/packet, iface="tap0")

# Valid packet
send_test(UDP(sport=1234, dport=2000)/Raw(b"packet 1"), "valid")

# Bad checksum
send_test(UDP(sport=1234, dport=2000, chksum=0xdead)/Raw(b"packet 2"), "bad checksum")

# Length mismatch - declared longer than payload
send_test(UDP(sport=1234, dport=2000, len=100)/Raw(b"packet 3"), "length too long")

# Empty payload
send_test(UDP(sport=1234, dport=2000)/Raw(b""), "empty payload")

# Closed port
send_test(UDP(sport=1234, dport=9999)/Raw(b"packet 4"), "closed port")
