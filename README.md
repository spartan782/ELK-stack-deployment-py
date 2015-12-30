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

It is intended for this script to be scaleable for any number of boxes to be added to the sensor platform. It useses a python ssh module (paramiko) to install and setup all software required on each box remotely. Threading will be added in the future to help speed up larger installations. The script has 3 different boxes it defines as making up the sensor platform.

1. Sensor Box (includes bro, suricata, netsniff-ng/stenographer)
  * This box will require a capture interface or multiple capture interfaces.
2. Data Store Box (includes kafka, logstash, elasticsearch)
  * This box will store data and index it using elasticsearch for query from an analyst box.
  * The directory information is stored in is /data/<app name>/, EI.. /data/kafka/logs would hold kafka's log files.
3. Analyst Box (includes, nginx, elasticsearch, kibana)
  * This box will host the kibana search node that allows analysts to query elasticsearch for information.
  * nginx will proxy all request to the analyst box IP over port 80 to the kibana application.


Current prereq's for this script are 2 python modules (paramiko, scp) and a local copy of the repo folder I have packaged up.
This allows installations offline. This can be tricked into working for you as long as yum install <app> will succeed, if it fails then there is currently no error checking other than checking to verify the following folders exsit. 

1. *probably best to stay liams good side file*
2. *see above*
3. *probably best to stay on ditchs good side file*
4. *see above*
5. rhel-7-server-beta-rpms
6. rhel-7-server-optional-rpms
7. rhel-7-server-rpms
8. rhel-7-server-thirdparty-oracle-java-rpms
9. kibana*.tar
10. emerging\*tar\*

These should all reside in the same dirrectory as the script will look only in the supplied directory for these files/folders. This will be consolidated into a single file at a later date.



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

**BRO CPU's** will pin 60% of available physical cores and leave the rest for suricata, netsniff-ng and the OS. This also requires a minimum of 4 Physical cpu cores, as 3 pinned cores are the fewest possible to pin.

**ES NODES** will default to 40% of the nodes becoming Master/Data (MD) nodes, and the other 60% being Data (D) nodes only. It will always default to creating atleast 2 MD nodes so that splitbrain effects will be avoided.


Currently the only test bed this has gone though is a 3 vm setup. The script is designed to handle any number of boxes but has not been tested. That means there may be bugs. If you find any please let me know so that I can correct them as quickly as possible. 




