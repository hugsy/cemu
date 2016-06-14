#!/bin/bash

set -e

CMAKE="$(which cmake)"
if [ $? -ne 0 ]; then
    echo "[-] You need 'cmake' to install 'cemu' requirements"
    exit 1
fi

PIP3="$(which pip3)"
if [ $? -ne 0 ]; then
    echo "[-] You need 'pip' to install 'cemu' requirements"
    exit 1
fi

pushd .

# keystone
cd /tmp
git clone https://github.com/keystone-engine/keystone.git
mkdir -p keystone/build && cd keystone/build
cmake .. && make -j8
sudo make install
cd ../bindings/python
sudo make install3

# capstone
cd /tmp
git clone https://github.com/aquynh/capstone.git
mkdir -p capstone/build && cd capstone/build
cmake .. && make -j8
sudo make install
cd ../bindings/python
sudo make install3

# unicorn
cd /tmp
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
./make.sh -j8
sudo ./make.sh install
cd ./bindings/python
sudo make install3

popd

sudo pip3 install -r ./requirements.txt
