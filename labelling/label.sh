#!/bin/bash

echo "################################"
echo "#     Labelling PCAP Files     #"
echo "################################"

if [ -f .env ]
then
  export $(grep -v '^#' .env | xargs -d '\n')
fi

CURRENT_DATE=`date +%s`
LABELS_FILE_CURRENT="${CURRENT_DATE}.csv"
NDPI_OUT_FILE="${CURRENT_DATE}.txt"
# LABELS_FILE_CURRENT="labels.csv"
echo $LABELS_FILE_CURRENT
# Write the header row to the labels1.csv file
echo "FlowFilePath,LabelDetails" > "$LABELS_FILE_CURRENT"
echo "Created $LABELS_FILE_CURRENT with header row. These labels will include, the number of packets and the file name that the flow is stored in."

###############################
####### Label TCP Flows #######
###############################

echo "Labelling TCP flows..."

# Loop through TCP_SYN flows folder, label each flow file using nDPI
# and append the filename-label pair to labels1.csv

tcp_file_counter=0
udp_file_counter=0
num_tcp_files=`find "$TCP_FLOW_FOLDER" -maxdepth 1 -type f |  wc -l | tr -d '[:space:]'` # for keeping track of progress
num_udp_files=`find "$UDP_FLOW_FOLDER" -maxdepth 1 -type f | wc -l | tr -d '[:space:]'` # for keeping track of progress

# Initialize an array to accumulate output lines
tcp_output_lines=()

for f in $TCP_FLOW_FILES
do
     # Every 1000th file processed, print to console to track of progress
     ((tcp_file_counter=tcp_file_counter+1))
     remainder=$(( tcp_file_counter % 1000 ))
     if [ $remainder -eq 0 ]
     then
          echo "`date` - TCP: ($tcp_file_counter/$num_tcp_files), UDP: ($udp_file_counter/$num_udp_files)"
     fi

     # 1) Run nDPI on the file, $f, with output stored temporarily in nDPI_output.txt
     ./nDPI/example/ndpiReader -i $f > "$NDPI_OUT_FILE"

     # 2) Extract the label and flow stats from the nDPI output

     # i) Find the line number and line for the line containing "Detected protocols"
     line_num=`grep -n "Detected protocols" "$NDPI_OUT_FILE"`

     # ii) Extract just the line number
     line_num=`echo $line_num | cut -f1 -d":"`

     # iii) Increment the line number - since nDPI label and flow statistics found on the next line
     line_num=`expr $line_num + 1`

     # iv) Extract the contents on the line containing the label and flow statistics
     flow_stats=`sed "${line_num}q;d" "$NDPI_OUT_FILE"`

     # 3) Append filename-label_stats pair to labels1.csv echo "${f}, ${flow_stats}" >> "$LABELS_FILE_CURRENT"
    # Append filename-label_stats pair to the array
    tcp_output_lines+=("${f}, ${flow_stats}")
done

# Write the TCP output lines to the file
printf "%s\n" "${tcp_output_lines[@]}" >> "$LABELS_FILE_CURRENT"

###############################
####### Label UDP Flows #######
###############################
echo

echo "Labelling UDP flows..."
# Initialize an array to accumulate output lines
udp_output_lines=()

# Loop through UDP flows folder, label each flow file using nDPI
# and append the filename-label pair to labels1.csv
for f in $UDP_FLOW_FILES
do
     # Every 1000th file processed, print to console to track of progress
     ((udp_file_counter=udp_file_counter+1))
     remainder=$(( udp_file_counter % 1000 ))
     if [ $remainder -eq 0 ]
     then
          echo "`date` - TCP: ($tcp_file_counter/$num_tcp_files), UDP: ($udp_file_counter/$num_udp_files)"
     fi

     # 1) Run nDPI on the file, $f, with output stored temporarily in nDPI_output.txt
     ./nDPI/example/ndpiReader -i $f > $NDPI_OUT_FILE

     # 2) Extract the label and flow stats from the nDPI output

     # i) Find the line number and line for the line containing "Detected protocols"
     line_num=`grep -n "Detected protocols" "$NDPI_OUT_FILE"`

     # ii) Extract just the line number
     line_num=`echo $line_num | cut -f1 -d":"`

     # iii) Increment the line number - since nDPI label and flow statistics found on the next line
     line_num=`expr $line_num + 1`

     # iv) Extract the contents on the line containing the label and flow statistics
     flow_stats=`sed "${line_num}q;d" "$NDPI_OUT_FILE"`

     # 3) Append filename-label_stats pair to labels1.csv echo "${f}, ${flow_stats}" >> "$LABELS_FILE_CURRENT"
     # Append filename-label_stats pair to the array
     udp_output_lines+=("${f}, ${flow_stats}")
done

# Write the UDP output lines to the file
printf "%s\n" "${udp_output_lines[@]}" >> "$LABELS_FILE_CURRENT"

echo
