# ELK-stack-deployment-py
Deploying a sensor platform via python.

I am sure there are many better ways to do this. However I do not have enough time nor experiance to write this in a more effective language. So seeing as how I know python am going to do my best to tackle a problem that exsists in todays cyber world that helps deploy a sensor platform a little easier for users that need something to use and deploy on their networks. I am using all open source software and python is the language I feel more comfortable with. I welcome all comments and helpful suggestions. This deployment revolves around the JSON format each tool is capable of use natively. I will be focusing on changing all bro logs to JSON formatting, and the EVE.JSON files form suricata so that they can easly be intergrated into Elasticsearch.

This sensor platform will be based around the following software and currently designed for the RHEL enviroment. I am aware there are other solutions out there but have not seen anything that screams that it is better for my use case.
#Software used
pf_ring (for suricata and bro)

netsniff-ng (for full pcap)

Suricata (for rule based alerts)

Bro (analyzer)

ELK (storage and user interface in real time)

Kafka (message que for ELK)

#Future plans

Create a plugin that writes bro logs to a kafka topic instead of disk.

Create a plugin that writes suricata eve.json to a kafka topic instead of disk.

Create a script/software that can mimic the ability present in sec onion that lets you pivot to pcap files from kibana.
