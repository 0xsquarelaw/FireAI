from scapy.all import sniff, IP, TCP, UDP, ICMP

# Accountant to limit the amount of processed packages
packet_count = 0

# Package number: IP Origin -> IP Destination Protocol: Origin port -> Type of traffic target
# Where:
# - "Package number "is a counter who indicates the order of the captured package.
# - "IP Origin" is the IP address of origin of the package.
# - "IP destination" is the IP destination address of the package.
# - "protocol" indicates the protocol used (TCP, UDP, ICMP, etc.).
# - "Port Origin" is the port of origin of the package.
# - "Destiny port" is the destination port of the package.
# - "Type of traffic" indicates the type of traffic captured (TCP, UDP, ICMP).
# Callback function to process each captured package
def process_packet(packet):
    global packet_count
    if packet.haslayer(IP):
        packet_count += 1
        #Package number, IP source, IP destination
        print(f"{packet_count}  | {packet[IP].src} -> {packet[IP].dst}", end=" ")

        if packet.haslayer(TCP):
            # TCP protocol, Origin port, destination port
            print(f"|  TCP: {packet[TCP].sport} -> {packet[TCP].dport}", end=" ")

        elif packet.haslayer(UDP):
            # UDP protocol, Origin Port, puertoDestination
            print(f"|  UDP: {packet[UDP].sport} -> {packet[UDP].dport}", end=" ")

        elif packet.haslayer(ICMP):
            # ICMP Protocol, Type, Code
            print(f"| ICMP: {packet[ICMP].type}/{packet[ICMP].code}", end=" ")

        print(f" |PAYLOAD  -> {packet.payload} LEN -> {len(packet)} TIME -> {packet.time} ID -> {packet.id}", end = " ")
        

        # MAC address of origin and destination
        print(f" | {packet.src} {packet.dst}", end = " ")
        
        print()
        print()

# | IP O -> IP D |Transport Protocol type - SPORT DPORT | payload bytes time ID | smacDmac |Type of traffic| 

# Capture packages on the network
print("Starting packages capture...")
sniff(prn=process_packet)
