import argparse
def get_args():

	def netsniff_interval(v):
		import re
		try:
				return re.match("^[1-9][0-9]*(KiB|MiB|GiB|sec|min|hrs|s)$", v).group(0)
		#Sad face my error handle is overridden by the parser Oh well.
		except:
			raise ValueError("String '%s' does not match required format <NUM>KiB/MiB/GiB/s/sec/min/hrs"%(v))
			
	parser = argparse.ArgumentParser(description="""Installs Sensor Software with defaults. 
	                                             All options are overridable at commandline.
												 This script will make some basic assumetions when installing.
												 When overriding fields the --install-[software] option can be ignored.
												 The script will assume you want that software installed.
												 If no software is choosen, this script will install all software with default values.
												 When installing logstash the default installation will install a elasticsearch master node.""",
												 epilog="""When installing Logstash the script will default to installing ES as a Master/Data node.
												 This is because the ultimate goal is to get data into elasticsearch.
												 You can use #######.py to modify exsisting software""")
	
	parser.add_argument('-H', '--host',type=str, help='Host Name', required=True)
	parser.add_argument('-I', '--interface', metavar='INTERFACE',type=str, help='Capture Interface', required=True)
	parser.add_argument('-d', '--domain',type=str,help='Domain name', required=False, default=None)
	parser.add_argument('--install-bro',  action='store_true', help='Installs bro, brocontrol, pfring, java, dkms, libpcap-pfring and pfring-dkms', required=False, default=False)
	#would like to set default to a % of available CPU power instead of hard coded number
	parser.add_argument('--bro-cores', metavar='NUM', type=int, help='Number of cores for bro workers', required=False, default=1)
	parser.add_argument('--bro-logs', metavar='DIR', type=str, help='Directory where bro should save logs', required=False, default="/var/bro/logs")
	parser.add_argument('--install-suricata', action='store_true', help='Installs Suricata, dkms, pfring, libpcap-pfring and pfring-dkms', required=False, default=False)
	parser.add_argument('--suricata-data', metavar='DIR', help='Directory to store the eve.json', required=False, default='/data/suricata/logs')
	#parser option not yet implemented. Should have default value of True after implementation.
	parser.add_argument('--suricata-kafka', action='store_true', help='(Not Implemented)Will no longer write a eve.json and will push data directly into kafka', required=False, default=False)
	parser.add_argument('--install-netsniff', action='store_true', help='Installs netsniff-ng', required=False, default=False)
	#this works but heaven forbid someone types something wrong. They will think they caused a buffer overflow.
	parser.add_argument('--netsniff-interval', metavar='<num>KiB/MiB/GiB/s/sec/min/hrs', type=netsniff_interval, help='Interval for output pcap', required=False, default='1GiB')
	parser.add_argument('--netsniff-output', metavar='DIR/INTERFACE', type=str, help='Directory/Interface where netsniff-ng should send data', required=False, default='/data/pcap')
	parser.add_argument('--install-elasticsearch', action='store_true', help='Installs elasticsearch and java', required=False, default=False)
	parser.add_argument('--elasticsearch-node-name', metavar='NAME', type=str, help='Sets current elasticsearch\'s node name', required=False, default=None)
	parser.add_argument('--elasticsearch-cluster-name', metavar='CLUSTER', type=str, help='Sets the cluster this elasticsearch node should connect to', required=False, default='elasticsearch')
	#would like to set default to 50% or 32 depending on available RAM.
	parser.add_argument('--elasticsearch-heap', metavar='NUM', type=int, help='Sets the amount of RAM elasticsearch is able to use for indexing functions. Recommend 50 percent of availble ram, but no more than 32G', required=False)
	# would be nice to dynamically set this but it would probably be a hassle. 
	parser.add_argument('--elasticsearch-shards', metavar='NUM', type=int, help='Sets the number of shards for elasticsearch. Recommend lower shard count for smaller configurations', required=False, default=1)
	parser.add_argument('--elasticsearch-replica', metavar='NUM', type=int, help='Sets the number of replicas for elasticsearch. Replicas are used for failover, recommend zero if you have only 1 data node', required=False, default=0)
	parser.add_argument('--elasticsearch-path-data', metavar='DIR', type=str, help='Directory to store elasticsearch data', required=False, default='/data/elasticsearch/data')
	parser.add_argument('--elasticsearch-path-logs', metavar='DIR', type=str, help='Directory to store elasticsearch logs', required=False, default='/data/elasticsearch/logs')
	# probably wont implement this. No plugins needed at this time
	parser.add_argument('--elasticsearch-path-plugins', metavar='DIR', type=str, help='Directory to elasticsearch plugins', required=False, default='/etc/elasticsearch/plugins')
	parser.add_argument('--elasticsearch-path-work', metavar='DIR', type=str, help='Directory for elasticsearch to work out of', required=False, default='/data/elasticsearch/work')
	parser.add_argument('--elasticsearch-unicast', action='store_true', help='Enables unicast and disables multicast discovery. If enabled include the --elasticsearch-master-discovery field or elasticsearch wont be able the master nodes', required=False, default=False)
	parser.add_argument('--elasticsearch-master-discovery', metavar='"NODE, NODE2, ECT"', type=str, help='List of master nodes that can be discovered when this node starts ("192.168.1.11, 192.168.1.12, ect..")',required=False, default=None)
	parser.add_argument('--elasticsearch-master-node', action='store_true', help='Makes this elasticsearch node a master node', required=False, default=True)
	parser.add_argument('--elasticsearch-data-node', action='store_true', help='Makes this elasticsearch node a data node', required=False, default=True)
	# need to further research kafka for best defaults for my usecase	
	parser.add_argument('--install-kafka', action='store_true', help='Installs kafka and java', required=False, default=False)
	parser.add_argument('--kafka-topic', metavar='TOPIC', type=str, help='Topic ID kafka should use and cluster with', required=False, default=None)
	parser.add_argument('--install-logstash', action='store_true', help='Installs logstash and elasticsearch', required=False, default=False)
	#will be replaced once I have a bro to kafka writer
	parser.add_argument('--logstash-bro-kafka', metavar='TOPIC' type=str, help='This will setup logstash to move bro logs into a kafka TOPIC ', required=False, default=None)
	parser.add_argument('--logstash-suricata-kafka', metavar='TOPIC' type=str, help='This will setup logstash to move the eve.json file into a kafka TOPIC', required=False, default=None)
	parser.add_argument('--logstash-bro-es', action='store_true', help='This will setup logstash to move bro logs into a local elasticsearch node', required=False, default=True)
	parser.add_argument('--logstash-bro-es', action='store_true', help='This will setup logstash to move the eve.json file into a local elasticsearch node ', required=False, default=True)
	parser.add_argument('--install-kibana', action='store_true', help='Installs Kibana and an elasticsearch search node', required=False, default=False)
	
	parser.add_argument('--repo-satellite', action='store_true', help='Create a repo satellite, installs nginx', required=False, default=False)
	args = parser.parse_args()
	return args
	#parser.add_argument('')
stuff = get_args()
