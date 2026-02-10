# Task 3: ARP Poisoning and MITM Attack Report

## 1. Code Developed
- **arp_scapy.py**: A Scapy script that performs bidirectional ARP poisoning between Alice and Bob, while simultaneously sniffing for transit HTTP traffic to provide terminal proof.
- **bob_mitm.py**: A mitmproxy script that detects the specific response from Bob's server and replaces it with "This is not Bob!".

## 2. Methodology
1. **Network Setup**: Initialized three Docker containers (Alice, Bob, Mallory) on a private bridge network.
2. **ARP Poisoning**: Ran Scapy on Mallory to map Mallory's MAC address to both Alice's and Bob's IPs in their respective caches.
3. **Traffic Redirection**: Used `iptables` on Mallory to redirect incoming port 80 traffic to port 8080 (mitmproxy).
4. **Interception**: Used `mitmproxy` in transparent mode to modify the data payload in transit.

## 3. Challenges & Learnings
- **Bidirectional Poisoning**: Discovered that poisoning only one target results in a "half-duplex" MITM where return traffic is lost. Both sides must be poisoned.
- **Transparent Proxying**: Learned that `mitmproxy` requires a specific `iptables` rule to handle traffic not originally destined for its local port.
- **Security Implications**: This task demonstrated that unencrypted HTTP provides zero integrity or confidentiality at the link layer.

## 4. Final Verification
- **Alice's View**: `curl http://172.31.0.3` returned "This is not Bob!".
- **IP Forwarding Check**: After the experiment, IP forwarding was verified to be disabled (`0`) on the host/containers where appropriate to prevent persistent security risks.