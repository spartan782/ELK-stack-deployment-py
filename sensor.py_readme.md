
#Sensor.py Script details and Notes (Not completed)


This script makes multiple assumetions when installing software.


assumes when creating a bro cluster all bro workers will have the same specs as the brocontrol (bro manager) box. If this is not true you will need to manually configure your node.cfg which will be installed under the /opt/bro/etc directory. This includes capture interfaces, cpu's pinned. (with the exception that the manager will not pin any cores.)

when creating a bro cluster the pinned cpu's are determined from the manager box. This means that if the architecture, number of CPU sockets (physical chips), CPU cores (# of cores in a physical socket), or Hyper threading is different in anyway than the manager box you will need to verify the pinned cpu portion of the node.cfg

when installing bro/suricata/elasticsearch/kafka depending on what options are chosen a dynamic dessision will be made to install logstash with specified config files. If you would like to change the files manually, these files will be located inside /etc/logstash/conf.d The nameing schema is (source)_(to)_(desination). For example a bro_kafka would mean this config tells logstash how to move bro logs into kafka.

pf_ring is installed when ever an application requiring it has been choosen for installation.
