import pandas as pd
import glob
import os
from dotenv import load_dotenv

def main():
    load_dotenv()  # Load environment variables from .env file
    print("Removing bloat from labels file")
    file_folder = os.getenv('FILE_FOLDER', './unformatted')
    list_of_files = glob.glob(f'{file_folder}/*.csv')
    print(f'Formatting this list  of files: {list_of_files}')

    dfs = []
    for f in list_of_files:
        df = pd.read_csv(f)
        df["FlowFileName"] = df["FlowFilePath"].apply(
            lambda path: path[path.find("flows/") + len("flows/"):])
        df["label"] = df["LabelDetails"].apply(
            lambda label_details: get_label(label_details))
        df["NumberOfPackets"] = df["LabelDetails"].apply(
            lambda num_packets: get_packets(num_packets))
        df["NumberOfBytes"] = df["LabelDetails"].apply(
            lambda num_bytes: get_bytes(num_bytes))
        dfs.append(df)
    df = pd.concat(dfs)
    df.drop(['LabelDetails', 'FlowFilePath'], axis=1, inplace=True)
    print("Writing cleaned up labels to file", len(dfs))
    df.to_csv("formatted-07-May-2024.csv", index=False)
    print("Done")


def get_label(label_details):
    return label_details[:label_details.find("packets") - 1].strip()


def get_packets(label_details):
    index = label_details.find("packets")
    label_details = label_details[index:]
    label_details = label_details.split(" ")
    num_packets = label_details[1].strip()
    return num_packets


def get_bytes(label_details):
    index = label_details.find("bytes")
    label_details = label_details[index:]
    label_details = label_details.split(" ")
    num_bytes = label_details[1].strip()
    return num_bytes


if __name__ == '__main__':
    main()
