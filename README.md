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

I suggest using PIP to install both.

$pip install scp

$pip install paramiko
