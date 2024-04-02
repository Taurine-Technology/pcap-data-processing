#!/bin/bash

if [ -f .env ]
then
  export $(grep -v '^#' .env | xargs -d '\n')
else
  echo "cannot find environment variable file"
  exit 1
fi

if [ -d "flows" ]; then
  echo "The 'flows' directory already exists. Skipping creation..."
else
  mkdir $OUTPUT_DIR || exit 1
fi

num_files=`ls $RAW_PCAP_FILES | wc -l | tr -d '[:space:]'` # for keeping track of progress
i=1
for f in $RAW_PCAP_FILES
do
     echo "Processing $f ($i/$num_files)"
     ((i=i+1))
     ./pkt2flow/pkt2flow -u -o $OUTPUT_DIR $f || exit 1
     echo "File $f processed" || exit 1
     echo
done

echo "Finished splitting packets into flows"