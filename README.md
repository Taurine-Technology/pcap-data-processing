# PCAP Data Processing
Scripts used to process and evaluate packet captures.

## Installation
There is a convenience install script in the root directory of the repo.

This can be run with the following command: `./install.sh`

### Tests
1. pkt2flow:
```
cd flow-splitting/pkt2flow
./pkt2flow -h
```
2. nDPI:
```
cd labelling/nDPI/tests
./do.sh
```

## Running the Code
Ensure you have run the installation script and installed the required python packages found in [requirements.txt](requirements.txt).
Please read the README files in each directory if you are running into errors and **ensure you set your environment 
variables in each folder**.

### Creating and Labelling Flows
1. Navigate to the [flow-splitting](flow-splitting) directory and run `./split.sh`.
2. Navigate to the [labelling](labelling) directory and run `./label.sh`.
3. Format labels by running `python3 clean_label.csv.py` in the [labelling](labelling) directory.