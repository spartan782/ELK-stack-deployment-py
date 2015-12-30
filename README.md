# ELK-stack-deployment-py
Deploying a sensor platform via python.

this python script will allow command line installs for a sensor platform.

This sensor platform will be based around the following software and currently designed for the RHEL enviroment. I am aware there are mutiple solutions out there but this setup is what I believe to be the best use case for my needs.
#Software used
pf_ring (for suricata and bro)

netsniff-ng (for full pcap)/ Replaced by stenographer when stable

Suricata (for rule based alerts)

Bro (analyzer)

Brocontrol (manage bro workers)

ELK (storage and user interface in real time)

Kafka (message que for ELK)

#Future plans

Create a script/software that can mimic the ability present in sec onion that lets you pivot to pcap files from kibana.


#Menu_Driven_sensor.py Script Details and Notes


This script is still very new and has planned updates to make the installation process more fluid.

Current prereq's for this script are 2 python modules (paramiko, scp)
In the future I plan to freeze this script into an ELF file with all prereq's completed.

I suggest using PIP to install both.

###RHEL 7 commands

    [user@rhel7 ~]$ sudo wget https://pypi.python.org/packages/source/s/setuptools/setuptools-7.0.tar.gz --no-check-certificate
    [user@rhel7 ~]$ sudo tar xzf setuptools-7.0.tar.gz
    [user@rhel7 ~]$ cd setuptools-7.0
    [user@rhel7 ~]$ sudo python setup.py install
    [user@rhel7 ~]$ wget https://bootstrap.pypa.io/get-pip.py
    [user@rhel7 ~]$ sudo python get-pip.py
    [user@rhel7 ~]$ sudo yum install gcc libffi-devel python-devel openssl-devel
    [user@rhel7 ~]$ sudo pip install scp paramiko

Then execute the menu driven script.

The **SSH USER** provided requires the ability to use the SUDO command as most files are not accessable to none root users.

**LOCALHOST** is currently included by default, if you are running this script from a box that is not part of the sensor just do not select any software to be installed on it. This will be changed in future versions.

**USER INPUTS** will be asked for by the script. In future versions there will be command line options to skip some of these questions and speed up install. If you have more than one input the expected input is a comma seperated list. for example, $ notates generated message, while the absence notates input from a user.

    [user@rhel7 ~]$ Enter which IP's will be part of the sensor platform
    192.168.0.2, 192.168.0.3, 192.168.0.4

Currently the only test bed this has gone though is a 3 vm setup. The script is designed to handle any number of boxes but has not been tested. That means there may be bugs. If you find any please let me know so that I can correct them as quickly as possible. 



