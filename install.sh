#!/bin/bash

echo "#################################"
echo "# INSTALLING/COMPILING pkt2flow #"
echo "#################################"

sudo apt install -y libpcap-dev || exit 1
sudo apt install -y scons || exit 1
cd flow-splitting || exit 1

# Check if the pkt2flow directory already exists
if [ -d "pkt2flow" ]; then
    echo
    echo "The 'pkt2flow' directory already exists. Skipping cloning."
    echo
else
    git clone https://github.com/Taurine-Technology/pkt2flow.git || exit 1
fi


cd pkt2flow || exit 1
scons || exit 1
cd ../.. || exit 1

echo "###############################"
echo "#  INSTALLING/COMPILING nDPI  #"
echo "###############################"

sudo apt-get install -y build-essential git bison flex libpcap-dev libtool libtool-bin autoconf pkg-config automake autogen libjson-c-dev libnuma-dev libgcrypt20-dev libpcre2-dev
cd labelling || exit 1

if [ -d "nDPI" ]; then
    echo
    echo "The 'nDPI' directory already exists. Skipping cloning."
    echo
else
    git clone https://github.com/ntop/nDPI.git || exit 1
fi

cd nDPI || exit 1
sudo ./autogen.sh || exit 1
sudo ./configure || exit 1
sudo make || exit 1

