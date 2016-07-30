#!/bin/bash
#
# Requirement installer for cemu
#


if [ "$(uname)" == "Darwin" ]; then
    echo "[+] Install for OSX"
    PKG="$(which brew >/dev/null)"
elif [ "$(uname)" == "Linux" ]; then
    echo "[+] Install for Linux"
    PKG="$(which dnf >/dev/null)"
    if [ $? -ne 0 ]; then
        PKG="$(which yum >/dev/null)"
        if [ $? -ne 0 ]; then
            PKG="$(which apt >/dev/null)"
            if [ $? -ne 0 ]; then
                echo "[-] No valid package manager found"
                exit 1
            fi
        fi
    fi
    PKG="sudo ${PKG}"
else
    echo "[-] Unsupported OS (this script supports only Linux or OSX)"
    exit 1
fi

echo "[+] Using package manager '${PKG}'"

if [ $1 == "--python2" ]; then
    PYTHON=python2
    PIP=pip
    echo "[+] Install for python2"
else
    PYTHON=python3
    PIP=pip3
    echo "[+] Install for python3"
fi

# install build tools
for req in git cmake ${PYTHON} ${PIP}
do
    dep="$(which $i)"
    if [ $? -ne 0 ]; then
        echo "[-] '${req}' is missing, installing..."
        ${PKG} install ${req}
    fi
done

set -e

# installing enum module for python2
if [ ${PIP} == "pip" ]; then
    ${PIP} install enum34
fi

# install pyqt5
if [ ${PKG} == "brew" ]; then
    ${PKG} install pyqt5 pkg-config glib
else
    ${PKG} install ${PYTHON}-pyqt5 pkg-config libglib2.0-dev
fi

pushd .

# install keystone/capstone/unicorn
${PYTHON} -c 'import keystone' 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[+] Installing keystone + bindings"
    cd /tmp
    git clone https://github.com/keystone-engine/keystone.git
    mkdir -p keystone/build && cd keystone/build
    ../make-share.sh && make
    sudo make install
    cd ../bindings/python
    if [ ${PYTHON} == python ]; then
        sudo make install
    else
        sudo make install3
    fi
fi

${PYTHON} -c 'import capstone' 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[+] Installing capstone + bindings"
    cd /tmp
    git clone https://github.com/aquynh/capstone.git
    mkdir -p capstone/build && cd capstone/build
    ./make.sh
    sudo ./make.sh install
    cd ./bindings/python
    if [ ${PYTHON} == python ]; then
        sudo make install
    else
        sudo make install3
    fi
fi

${PYTHON} -c 'import unicorn' 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[+] Installing unicorn + bindings"
    cd /tmp
    git clone https://github.com/unicorn-engine/unicorn.git
    cd unicorn
    ./make.sh
    sudo ./make.sh install
    cd ./bindings/python
    if [ ${PYTHON} == python ]; then
        sudo make install
    else
        sudo make install3
    fi
fi

popd

# install pip missing packages
sudo ${PIP} install pygments
