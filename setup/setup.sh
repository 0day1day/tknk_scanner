#!/bin/bash

mkdir target result tools yara
chmod 777 target result
sudo apt install python3 python3-magic qemu-kvm virt-manager libvirt-bin bridge-utils mongodb npm nginx
sudo pip3 install -r setup/requirements.txt
