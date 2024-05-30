import numpy as np
from scapy.all import *
import time
import pandas as pd
import errno
import os
import glob
import matplotlib.pyplot as plt
from scipy import stats
from dotenv import load_dotenv

def get_matrix_from_pcap(filename, num_packets, num_bytes, x):
    formatted_matrices = []
    if os.path.exists(filename):
        data = sniff(offline=filename)
        count = 0
        tls_counter = 0
        for pkt in data:
            if count == num_packets:
                return formatted_matrices
            if pkt.haslayer(IP) and pkt.haslayer(Raw) and pkt.haslayer('tls'):  # skip TLS
                continue
            elif pkt.haslayer(IP) and pkt.haslayer(Raw):  # if there is a payload
                try:
                    hex_data = linehexdump(
                        pkt[IP].payload, onlyhex=1, dump=True).split(" ")
                    decimal_data = list(map(hex_to_dec, hex_data))
                    # fix length of payload
                    if len(decimal_data) >= num_bytes:
                        decimal_data = decimal_data[:num_bytes]
                    elif len(decimal_data) < num_bytes:
                        for i in range(len(decimal_data), num_bytes):
                            decimal_data.append(0)
                    # If the follwoing two lines are commented out then we aren't masking
                    for i in range(20):
                        decimal_data[i] = 0  # mask first 20 bytes
                    formatted_data = []
                    for i in range(0, num_bytes, x):
                        temp_data = decimal_data[i:i + x]
                        formatted_data.append(temp_data)
                    formatted_matrices.append(formatted_data)
                    count += 1
                except RecursionError as err:
                    print(err)
                    print(filename)
                    break
            else:
                continue

    else:
        # print('Could not find {}'.format(filename))
        return formatted_matrices


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def hex_to_dec(hex_data):
    return str(int(hex_data, base=16))


def format_data(dict_of_packets, n_packets, number_of_bytes, row_dimension):
    data = {'label': []}
    data_array = []
    for label, payload in dict_of_packets.items():
        payload_array = []
        for i in payload:
            for p in i:
                for row in p:  # p is a 2D array with len = 12 if we are taking 12 x 12 packet data
                    payload_array.append(row)
            data['label'].append(label)
        data_array.append(payload_array)
        # print(len(payload_array))  # adds 12 x this amount of packets
    y_train = pd.DataFrame(data)
    arr = []
    for payload_data in data_array:
        arr_temp = np.array(payload_data).reshape(-1, row_dimension * row_dimension)
        arr.append(arr_temp)
    data_array = np.concatenate(arr)
    number_of_packets = int(len(data_array) / (n_packets * number_of_bytes))
    return data_array, y_train


def generate_dataset(flow_directory, num_packets, num_bytes, x, num_flows,
                     output_dir, output_file_name, label_folder):  # TODO introduce y variable
    data = {}
    skip = True
    # labels = {'AdultContent': 0, 'Apple': 0, 'AmazonAWS': 0, 'BitTorrent': 0, 'Cloudflare': 0, 'Cybersec': 0, 'DNS': 0,
    # 'FbookReelStory':0,'Facebook': 0, 'GMail': 0, 'GoogleDocs': 0,
    #           'Google': 0, 'GoogleCloud': 0, 'GoogleServices': 0, 'HuaweiCloud': 0, 'HTTP': 0, 'Instagram': 0,
    #           'Microsoft': 0, 'Microsoft365':0,'MS_OneDrive': 0, 'Snapchat': 0, 'Spotify': 0, 'TLS': 0, 'TikTok': 0, 'Twitter': 0,
    #           'WhatsApp': 0, 'WhatsAppFiles': 0, 'WindowsUpdate': 0,
    #           'YouTube': 0, 'Unknown': 0, 'Xiaomi': 0}
    labels = {'AmazonAWS': 0, 'BitTorrent': 0, 'Facebook': 0, 'FbookReelStory': 0, 'Google': 0, 'GoogleServices': 0, 'HTTP': 0,
              'Instagram': 0, 'Microsoft': 0, 'Microsoft365': 0, 'MS_OneDrive': 0, 'Spotify': 0, 'TikTok': 0, 'WhatsApp': 0,
              'YouTube': 0,}

    count = 0
    path = label_folder + "*.csv"
    for fname in glob.glob(path):
        print(fname)
        with open(fname) as f_read:
            with open(output_file_name, "w") as output:
                for line in f_read:
                    if skip:  # skip header row
                        skip = False
                        continue
                    split_line = line.strip().split(',')
                    # get the file path and label
                    # file_path_arr = split_line[0].split('/')
                    file_path = split_line[0]
                    # print(file_path)
                    label = split_line[1]

                    file_path = flow_directory + file_path
                    # create dictionary filled with matrices representing the packets. The order of the values in the dict
                    # are the order of them in the flow
                    if label in labels.keys() and labels[label] < num_flows:
                        # get matrices for the packets in this file if they are an application we are interested in
                        matrices = get_matrix_from_pcap(file_path, num_packets, num_bytes, x)
                        if matrices:
                            # print(len(matrices)) this should be = num_packets
                            if len(matrices) == num_packets:
                                count += 1
                                labels[label] = labels[label] + 1
                                output.write(line)
                                if data.get(label) is None:
                                    data[label] = []
                                    data[label].append(matrices)
                                else:
                                    data[label].append(matrices)

                    elif label in labels and labels[label] == num_flows:
                        packet_data, y_labels = format_data({label: data[label]}, num_packets, num_bytes, x)
                        npy_file_name = output_dir + label + ".npy"
                        np.save(npy_file_name, packet_data)
                        pickle_file_name = output_dir + label + ".pkl"
                        y_labels.to_pickle(pickle_file_name)
                        print(label)
                        del labels[label]
                    elif len(labels) == 0:
                        output.close()
                        break
                    # else:
                    #     if os.path.exists(file_path):
                    #         # remove files that aren't needed to free space
                    #         os.remove(file_path)
                    # if count % num_flows == 0 and count != 0:
                    #     print(label)
                    # if count > 11800:
                    #     break
    # if data:
    #     packet_data, y_labels = format_data(data, num_packets, num_bytes, x)
    #     return packet_data, y_labels
    # else:
    #     return "Couldn't find labels.csv", "Couldn't find labels.csv"


def average_and_display(directory_path, save_path, num_packets, packet_size):
    # Loop over all files in the directory
    for file_name in os.listdir(directory_path):
        # Only process .npy files
        if not file_name.endswith('.npy'):
            continue

        # Extract the label from the file name
        label = os.path.splitext(file_name)[0]

        # Load the dataset
        dataset = np.load(os.path.join(directory_path, file_name))

        # Reshape the dataset into individual packets
        packets = dataset.reshape(-1, packet_size)

        # Separate the packets into flows
        num_flows = packets.shape[0] // num_packets
        flows = packets[:num_flows * num_packets].reshape(num_flows, num_packets, packet_size)

        for packet_num in range(num_packets):
            # Extract the packets at this position from all flows
            packets_at_position = flows[:, packet_num]
            # print(type(packets_at_position))
            # print(packets_at_position)
            packets_at_position = packets_at_position.astype(int)
            # Calculate the average packet at this position
            average = np.mean(packets_at_position, axis=0)
            normalized_data = (average - np.min(average)) / (np.max(average) - np.min(average)) * 255

            plt.figure()
            plt.imshow(normalized_data.reshape(int(np.sqrt(packet_size)), int(np.sqrt(packet_size))), cmap='gray')
            plt.title(f'Packet {packet_num + 1} for label {label}')
            plt.axis('off')

            # Ensure the directory exists
            os.makedirs(save_path, exist_ok=True)

            # Save the figure
            plt.savefig(os.path.join(save_path, f'{label}_packet_{packet_num + 1}.png'), dpi=300, bbox_inches='tight',
                        pad_inches=0)

            plt.close()


def calculate_statistics(directory_path, num_packets, packet_size, save_path):
    # Dictionary to store all the statistics
    statistics = {}

    # Loop over all files in the directory
    for file_name in os.listdir(directory_path):
        # Only process .npy files
        if not file_name.endswith('.npy'):
            continue

        # Extract the label from the file name
        label = os.path.splitext(file_name)[0]

        # Load the dataset
        dataset = np.load(os.path.join(directory_path, file_name))

        # Reshape the dataset into individual packets
        packets = dataset.reshape(-1, packet_size)

        # Separate the packets into flows
        num_flows = packets.shape[0] // num_packets
        flows = packets[:num_flows * num_packets].reshape(num_flows, num_packets, packet_size)

        # Store statistics for this label
        label_statistics = {}

        for packet_num in range(num_packets):
            # Extract the packets at this position from all flows
            packets_at_position = flows[:, packet_num]
            packets_at_position = packets_at_position.astype(int)
            # Calculate the statistics for these packets
            packet_statistics = {
                'mean': np.mean(packets_at_position),
                'median': np.median(packets_at_position),
                'mode': stats.mode(packets_at_position, axis=None)[0][0],
                'variance': np.var(packets_at_position),
                'std_dev': np.std(packets_at_position),
            }

            # Determine outliers using the IQR method
            q75, q25 = np.percentile(packets_at_position, [75, 25])
            iqr = q75 - q25
            lower_bound = q25 - (iqr * 1.5)
            upper_bound = q75 + (iqr * 1.5)
            outliers = packets_at_position[(packets_at_position < lower_bound) | (packets_at_position > upper_bound)]
            packet_statistics['num_outliers'] = len(outliers)

            # Store the statistics for this packet position
            label_statistics[f'packet_{packet_num + 1}'] = packet_statistics

        # Store the statistics for this label
        statistics[label] = label_statistics

    # Create a DataFrame from the statistics
    df = pd.DataFrame(statistics)

    # Transpose the DataFrame so that each row corresponds to a label
    df = df.transpose()

    # Save the DataFrame to a CSV file
    df.to_csv(save_path)


def main():
    load_dotenv()
    NUMBER_OF_PACKETS = 3
    NUMBER_OF_BYTES = 225
    ROW_DIMENSION = 15
    start_time = time.time()

    labelled_flows = os.getenv('LABELLED_FLOWS', './flows/')
    label_folder = os.getenv('LABELS_FOLDER', './labels/')
    output_dir = os.getenv('OUTPUT_DIR', './generated_data/')
    output_file_name = os.getenv('OUTPUT_FILE_NAME', './dataset.csv')
    num_flows = os.getenv('NUM_FLOWS', 0)
    generate_dataset(labelled_flows, NUMBER_OF_PACKETS, NUMBER_OF_BYTES, ROW_DIMENSION, int(num_flows), output_dir,
                     output_file_name, label_folder)



    end_time = time.time()
    print('Total time to run: {}'.format(end_time - start_time))
    # average_and_display('./dataset/', './images/', 5, 15 * 15)
    # to calculate statistics for all labels in a directory and save them to a CSV file, you would call the function like this:
    # calculate_statistics('./generated_output', 7, 28 * 28, './stats/stats.csv')


if __name__ == '__main__':
    main()
