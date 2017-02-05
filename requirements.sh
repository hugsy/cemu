#!/bin/bash
#
# Requirement installer for cemu
#


if [ "$(uname)" == "Darwin" ]; then
    echo "[+] Install for OSX"
    PKG="$(which brew)"
    if [ $? -ne 0 ]; then
        echo "[-] brew is missing"
        exit 1
    fi

elif [ "$(uname)" == "Linux" ]; then
    echo "[+] Install for Linux"
    for pm in dnf yum apt; do
        p="$(which ${pm} | grep -v 'not found')"
        if [ -n "${p}" ]; then
            PKG="${p}"
            break
        fi
    done
    if [ -z "${PKG}" ]; then
        echo "[-] Invalid package manager"
        exit 1
    fi

    PKG="sudo ${PKG}"
else
    echo "[-] Unsupported OS (this script supports only Linux or OSX)"
    exit 1
fi

echo "[+] Using package manager '${PKG}'"

if [ "$1" == "--python2" ]; then
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
    dep="$(which $req)"
    if [ $? -ne 0 ]; then
        echo "[-] '${req}' is missing, installing..."
        ${PKG} install ${req}
    fi
done


# installing enum module for python2
if [ "${PIP}" == "pip" ]; then
    ${PIP} install enum34
fi

# install pyqt5
if [ "$(uname)" == "Darwin" ]; then
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
    cd capstone
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

if [ "$(uname)" == "Linux" ]; then
    sudo ldconfig
fi
