import csv
import os
import shutil
import scapy.all as scapy
from math import floor

# List of client details containing tuples of (IP, MAC)
client_details = [
    ("10.0.0.3", "00:00:00:00:00:03"),
    ("10.0.0.4", "00:00:00:00:00:04"),
    ("10.0.0.5", "00:00:00:00:00:05"),
    ("10.0.0.6", "00:00:00:00:00:06"),
    ("10.0.0.7", "00:00:00:00:00:07"),
    ("10.0.0.8", "00:00:00:00:00:08"),
    ("10.0.0.9", "00:00:00:00:00:09"),
    ("10.0.0.10", "00:00:00:00:00:010"),
]


def change_ip_mac(packet, prefix, internal_ip, internal_mac, external_ip, external_mac):
    if packet[scapy.IP].src.startswith(prefix):
        packet[scapy.IP].src = internal_ip
        packet[scapy.Ether].src = internal_mac
    else:
        packet[scapy.IP].src = external_ip
        packet[scapy.Ether].src = external_mac

    if packet[scapy.IP].dst.startswith(prefix):
        packet[scapy.IP].dst = internal_ip
        packet[scapy.Ether].dst = internal_mac
    else:
        packet[scapy.IP].dst = external_ip
        packet[scapy.Ether].dst = external_mac

    # Recalculate checksums
    del packet[scapy.IP].chksum
    if packet.haslayer(scapy.TCP):
        del packet[scapy.TCP].chksum
    elif packet.haslayer(scapy.UDP):
        del packet[scapy.UDP].chksum
    elif packet.haslayer(scapy.ICMP):
        del packet[scapy.ICMP].chksum

    return packet


def split_pcap_by_ip_mac(src_folder, dst_folder, prefix, client_details):
    # Clear and recreate the destination folder
    if os.path.exists(dst_folder):
        shutil.rmtree(dst_folder)
    os.makedirs(dst_folder, exist_ok=True)

    for idx, (internal_ip, internal_mac) in enumerate(client_details):
        client_folder = os.path.join(dst_folder, f'client_{idx + 1}')
        internet_folder = os.path.join(dst_folder, f'internet_{idx + 1}')
        os.makedirs(client_folder, exist_ok=True)
        os.makedirs(internet_folder, exist_ok=True)
        num_files = 0
        for filename in os.listdir(src_folder):
            if num_files >= 50:
                print(f"Finished writing for host {idx + 1}")
                break
            if filename.endswith(".pcap"):
                file_path = os.path.join(src_folder, filename)
                cap = scapy.rdpcap(file_path)

                internal_packets = scapy.PacketList()
                external_packets = scapy.PacketList()

                for packet in cap:
                    if scapy.IP in packet and scapy.Ether in packet:
                        original_src = packet[scapy.IP].src
                        packet = change_ip_mac(packet, prefix, internal_ip, internal_mac, "10.0.0.2",
                                               "00:00:00:00:00:02")
                        if original_src.startswith(prefix):
                            internal_packets.append(packet)
                        else:
                            external_packets.append(packet)

                # Write packets to new pcap files
                scapy.wrpcap(os.path.join(client_folder, f"{filename.split('.pcap')[0]}_client.pcap"), internal_packets)
                scapy.wrpcap(os.path.join(internet_folder, f"{filename.split('.pcap')[0]}_internet.pcap"),
                             external_packets)
                num_files += 1


def update_pcaps(csv_file, flow_directory, dst_folder, prefix, client_details, num_clients, total_pcaps):
    # Clear and recreate the destination folder
    if os.path.exists(dst_folder):
        shutil.rmtree(dst_folder)
    os.makedirs(dst_folder, exist_ok=True)

    # Read CSV file
    pcap_list = []
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            pcap_list.append(row)

    num_files_per_client = floor(total_pcaps / num_clients)

    for idx, (internal_ip, internal_mac) in enumerate(client_details[:num_clients]):
        client_folder = os.path.join(dst_folder, f'client_{idx + 1}')
        internet_folder = os.path.join(dst_folder, f'internet_{idx + 1}')
        os.makedirs(client_folder, exist_ok=True)
        os.makedirs(internet_folder, exist_ok=True)

        start_idx = idx * num_files_per_client
        end_idx = start_idx + num_files_per_client
        client_pcap_list = pcap_list[start_idx:end_idx]

        for row in client_pcap_list:
            pcap_file, classification, *_ = row
            if pcap_file.endswith(".pcap"):
                file_path = os.path.join(flow_directory, pcap_file)
                print(file_path)
                cap = scapy.rdpcap(file_path)

                updated_packets = scapy.PacketList()
                for packet in cap:
                    if scapy.IP in packet and scapy.Ether in packet:
                        packet = change_ip_mac(packet, prefix, internal_ip, internal_mac, "10.0.0.2",
                                               "00:00:00:00:00:02")
                        updated_packets.append(packet)

                # Write updated packets to new pcap files with classification suffix
                base_filename = os.path.basename(pcap_file).split('.pcap')[0]
                client_pcap_filename = f"{base_filename}_client_{classification.lower()}.pcap"
                internet_pcap_filename = f"{base_filename}_internet_{classification.lower()}.pcap"

                scapy.wrpcap(os.path.join(client_folder, client_pcap_filename), updated_packets)
                scapy.wrpcap(os.path.join(internet_folder, internet_pcap_filename), updated_packets)


def main():
    src_folder = '/media/keegan/870evo/Taurine/pcaps/black-equations/2024/04/ml-dataset-pcaps/testing'
    dst_folder = './split'
    num_hosts = int(input("Enter the number of hosts: "))

    # Validate num_hosts
    if num_hosts > len(client_details):
        raise ValueError(f"Number of hosts exceeds available client details ({len(client_details)}).")

    # split_pcap_by_ip_mac(src_folder, dst_folder, "10.", client_details[:num_hosts])
    update_pcaps('', src_folder, dst_folder, "10.", client_details[:num_hosts], num_hosts, 300)


if __name__ == '__main__':
    main()
