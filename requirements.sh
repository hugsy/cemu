#!/bin/bash


CMAKE="$(which cmake)"
if [ $? -ne 0 ]; then
    echo "[-] You need 'cmake' to install 'cemu' requirements"
    exit 1
fi


PYTHON3="$(which python3)"
if [ $? -ne 0 ]; then
    echo "[-] This script automates the installation for Python3 which was not found on your system."
    exit 1
fi

PIP3="$(which pip3)"
if [ $? -ne 0 ]; then
    echo "[-] You need 'pip3' to install 'cemu' requirements"
    exit 1
fi

pushd .

${PYTHON3} -c 'import keystone' 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[+] Installing keystone + bindings"
    cd /tmp
    git clone https://github.com/keystone-engine/keystone.git
    mkdir -p keystone/build && cd keystone/build
    ../make-share.sh && make -j8
    sudo make install
    cd ../bindings/python
    sudo make install3
fi

${PYTHON3} -c 'import capstone' 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[+] Installing capstone + bindings"
    cd /tmp
    git clone https://github.com/aquynh/capstone.git
    mkdir -p capstone/build && cd capstone/build
    ./make.sh
    sudo ./make.sh install
    cd ./bindings/python
    sudo make install3
fi

${PYTHON3} -c 'import capstone' 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[+] Installing unicorn + bindings"
    cd /tmp
    git clone https://github.com/unicorn-engine/unicorn.git
    cd unicorn
    ./make.sh
    sudo ./make.sh install
    cd ./bindings/python
    sudo make install3
fi

popd

sudo ${PIP3} install -r ./requirements.txt
