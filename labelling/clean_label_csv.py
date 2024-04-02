import pandas as pd
import glob
import os


def main():
    print("Removing bloat from labels file")
    list_of_files = glob.glob('*.csv')
    print(f'Formatting this list  of files: {list_of_files}')

    # latest_file = max(list_of_files, key=os.path.getctime)  # get the latest file
    # print(latest_file)
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
    # df_facebook = df.drop(df[df.label.astype(str) != 'Facebook'].index)[:]
    # df_youtube = df.drop(df[df['label'] != 'YouTube'].index)[:]
    # df_tiktok = df.drop(df[df['label'] != 'TikTok'].index)
    # df_whatsapp_files = df.drop(df[df['label'] != 'WhatsAppFiles'].index)
    # df_instagram = df.drop(df[df['label'] != 'Instagram'].index)
    # df_whatsapp = df.drop(df[df['label'] != 'WhatsApp'].index)
    # df_messenger = df.drop(df[df['label'] != 'Messenger'].index)
    # df_bittorrent = df.drop(df[df['label'] != 'BitTorrent'].index)[:]
    # df_final = pd.concat([df_youtube, df_facebook, df_tiktok, df_whatsapp_files, df_instagram, df_whatsapp,
    #                       df_messenger, df_bittorrent])
    df.to_csv("formatted-filtered.csv", index=False)
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