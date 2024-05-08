import os
import pyshark
from scapy.all import wrpcap, PacketList


def split_pcap_by_ip(src_folder, dst_folder):
    os.makedirs(dst_folder, exist_ok=True)

    for filename in os.listdir(src_folder):
        if filename.endswith(".pcap"):
            file_path = os.path.join(src_folder, filename)
            cap = pyshark.FileCapture(file_path, only_summaries=False, keep_packets=True)

            packets_by_src_ip = {}
            packets_by_dst_ip = {}

            for packet in cap:
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    if src_ip not in packets_by_src_ip:
                        packets_by_src_ip[src_ip] = []
                    if dst_ip not in packets_by_dst_ip:
                        packets_by_dst_ip[dst_ip] = []

                    packets_by_src_ip[src_ip].append(packet)
                    packets_by_dst_ip[dst_ip].append(packet)
                except AttributeError:
                    # Handles packets that do not have IP layer (e.g., ARP)
                    continue

            for ip, pkts in packets_by_src_ip.items():
                new_filename = os.path.join(dst_folder, f"{ip}_src_{filename}")
                wrpcap(new_filename, PacketList(pkts))

            for ip, pkts in packets_by_dst_ip.items():
                new_filename = os.path.join(dst_folder, f"{ip}_dst_{filename}")
                wrpcap(new_filename, PacketList(pkts))

            cap.close()


def main():
    src_folder = 'path_to_your_source_folder'
    dst_folder = 'path_to_your_destination_folder'
    split_pcap_by_ip(src_folder, dst_folder)


if __name__ == '__main__':
    main()
