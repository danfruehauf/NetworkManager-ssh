#!/bin/bash

checkmodule -M -m -o NetworkManager-ssh.mod NetworkManager-ssh.te
semodule_package -o NetworkManager-ssh.pp -m NetworkManager-ssh.mod

# To insert policy, use:
#sudo semodule -i NetworkManager-ssh.pp
