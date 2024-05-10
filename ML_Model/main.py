from scapy.all import *
import time
from anomalia import AnomalIA
import warnings
warnings.filterwarnings("ignore")

# Global variables to maintain the state of the connections and the time of the last package
last_time = None
last_size = None

# Global variables to maintain the status of connections
connection_states = {}
src_dport_counts = {}
dst_sport_counts = {}
dst_src_counts = {}

# Function to calculate the destination bits rate
def calculate_dload(packet):
    global last_time, last_size
    current_time = time.time()
    size = len(packet)
    if last_time is None:
        last_time = current_time
        last_size = size
        return 0.0
    else:
        # Calculate the destination bits rate in bits per second
        dload = abs((size - last_size) / (current_time - last_time))
        last_time = current_time
        last_size = size
        return dload

# Function to update connections counts
def update_connection_counts(packet, src_ip, dst_ip, src_port, dst_port, proto):
    global connection_states, src_dport_counts, dst_sport_counts, dst_src_counts

    # Update connection counts according to the protocol
    if proto == 6:  # TCP
        tcp_layer = packet.getlayer(TCP)
        if tcp_layer:
            flags = tcp_layer.sprintf('%TCP.flags%')
            connection_states[(src_ip, dst_ip)] = flags
            src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
            dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
            dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1
            
            # Increase the life time of the connection state
            ttl = packet[IP].ttl if IP in packet else 0
            connection_states[(src_ip, dst_ip, "ct_state_ttl")] = ttl
            
            connection_states[(src_ip, dst_ip, "ct_src_dport_ltm")] = tcp_layer.sport
            connection_states[(src_ip, dst_ip, "ct_dst_sport_ltm")] = tcp_layer.dport
            connection_states[(src_ip, dst_ip, "ct_dst_src_ltm")] = dst_src_counts[(src_ip, dst_ip)]
            
    elif proto == 17:  # UDP
        connection_states[(src_ip, dst_ip)] = 0  # State 0 for UDP
        src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
        dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
        dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1
    elif proto == 1:  # ICMP
        connection_states[(src_ip, dst_ip)] = 0  # State 0 for ICMP
        src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
        dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
        dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1

# Callback function to process each captured package
def process_packet(packet):
    global last_time, last_size

    printed_something = False  # Auxiliary variable to verify if something has been printed

    if IP in packet:
        proto = packet[IP].proto
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Assign value 1 if the protocol is TCP, 2 if you are UDP, 3 if it is ICMP, 0 if it is not
        if proto == 6:  # TCP
            protocol_label = "1"
            state = packet[TCP].sprintf('%TCP.flags%')
            state_INT = 1 if state == "INT" else 0
            state_CON = 1 if state == "CON" else 0
            state_FIN = 1 if state == "FIN" else 0
            sttl = packet[IP].ttl if IP in packet else 0
            swin = packet[TCP].window
            dwin = packet[TCP].options[3][1] if packet[TCP].options and len(packet[TCP].options) > 3 else 0  # Extract dwin if it exists
        elif proto == 17:  # UDP
            protocol_label = "2"
            sttl = packet[IP].ttl if IP in packet else 0
            swin = 0  # There is no window field at UDP
            dwin = 0
            state = None
            state_INT = None
            state_CON = None
            state_FIN = None
        elif proto == 1:  # ICMP
            protocol_label = "3"
            sttl = packet[IP].ttl if IP in packet else 0
            swin = 0  # There is no window field in ICMP
            dwin = 0
            state = None
            state_INT = None
            state_CON = None
            state_FIN = None
        else:
            protocol_label = "0"
            state_code = 0
            state_INT = 0
            state_CON = 0
            state_FIN = 0
            sttl = packet[IP].ttl if IP in packet else 0
            swin = 0
            dwin = 0
            state = None
            state_INT = None
            state_CON = None
            state_FIN = None

        if proto == 6:#TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # Calculate the destination bits rate
            dload = calculate_dload(packet)
            
            # Update connection counts
            update_connection_counts(packet, src_ip, dst_ip, src_port, dst_port, proto)
            
            # Print the package details if something is printed
            data = {
                "sttl": sttl,
                "state_INT": state_INT,
                "ct_state_ttl": 0,
                "proto_tcp": 1 if proto == 6 else 0,
                "swin": swin,
                "dload": dload,
                "state_CON": state_CON,
                "dwin": dwin,
                "state_FIN": state_FIN
            }
            # print(data)
            if ia.predict_anomaly(data) == 1:
                printed_something = True
                print("ATTACK!")
                print("Type of anomaly:", ia.predict_attack(data))
            print(f"PROTO: {protocol_label}, IPSRC: {src_ip} : SPORT: {src_port}, IPDST: {dst_ip} : DPORT: {dst_port}, STATE: {state}, STTL: {sttl}, DLOAD: {dload}, SWIN: {swin}, DWIN: {dwin}, STATE_INT: {state_INT}, STATE_CON: {state_CON}, STATE_FIN: {state_FIN}")
            print("Anomalous traffic")
            #print(f"PROTO: {protocol_label}, IPSRC: {src_ip} : SPORT: {src_port}, IPDST: {dst_ip} : DPORT: {dst_port}, STATE: {state}, STTL: {sttl}, DLOAD: {dload}, SWIN: {swin}, DWIN: {dwin}, STATE_INT: {state_INT}, STATE_CON: {state_CON}, CT_STATE_TTL: {connection_states.get((src_ip, dst_ip, 'ct_state_ttl'), STATE_FIN: {state_FIN}")
            #print()
            #print()

        elif proto == 17:#UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # Calculate the destination bits rate
            dload = calculate_dload(packet)
            
            # Update connection counts
            update_connection_counts(packet, src_ip, dst_ip, src_port, dst_port, proto)
            
            # Print the package details if something is printed
            data = {
                "sttl": sttl,
                "state_INT": state_INT,
                "ct_state_ttl": 0,
                "proto_tcp": 1 if proto == 6 else 0,
                "swin": swin,
                "dload": dload,
                "state_CON": state_CON,
                "dwin": dwin,
                "state_FIN": state_FIN
            }
            # print(data)
            if ia.predict_anomaly(data) == 1:
                printed_something = True
                print("ATTACK!")
                print("Type of anomaly:", ia.predict_attack(data))
                print("Anomalous traffic")
            print(f"PROTO: {protocol_label}, IPSRC: {src_ip} : SPORT: {src_port}, IPDST: {dst_ip} : DPORT: {dst_port}, STATE: {state}, STTL: {sttl}, DLOAD: {dload}, SWIN: {swin}, DWIN: {dwin}, STATE_INT: {state_INT}, STATE_CON: {state_CON}, STATE_FIN: {state_FIN}")
            #print()
            #print()
        
        elif proto == 1:#ICMP
            src_port = packet[ICMP].sport
            dst_port = packet[ICMP].dport
            # Calculate the destination bits rate
            dload = calculate_dload(packet)

            # Update connection counts
            update_connection_counts(packet, src_ip, dst_ip, src_port, dst_port, proto)

            # Print the package details if something is printed
            data = {
                "sttl": sttl,
                "state_INT": state_INT,
                "ct_state_ttl": 0,
                "proto_tcp": 1 if proto == 6 else 0,
                "swin": swin,
                "dload": dload,
                "state_CON": state_CON,
                "dwin": dwin,
                "state_FIN": state_FIN
            }
            # print(data)
            if ia.predict_anomaly(data) == 1:
                printed_something = True
                print("ATTACK!")
                print("Type of anomaly:", ia.predict_attack(data))
            print(f"PROTO: {protocol_label}, IPSRC: {src_ip} : SPORT: {src_port}, IPDST: {dst_ip} : DPORT: {dst_port}, STATE: {state}, STTL: {sttl}, DLOAD: {dload}, SWIN: {swin}, DWIN: {dwin}, STATE_INT: {state_INT}, STATE_CON: {state_CON}, STATE_FIN: {state_FIN}")
            #print()
            #print()

    # If nothing has been printed, print "false"
    if not printed_something:
        print("Normal...")

# Start capture of packages
ia = AnomalIA(
    "models/Anomalies_Detector/anomalies_rf.pkl",
    "models/Anomalies_Detector/attacks_rf.pkl"
)
sniff(prn=process_packet, store=0)