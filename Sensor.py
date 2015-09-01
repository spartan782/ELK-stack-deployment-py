import argparse, subprocess, shlex, sys
defaults = {}
defaults['domain'] = ""
defaults['bro_cores'] = 1
defaults['bro_logs'] = '/data/bro/logs'
defaults['bro_manager'] = 'localhost'
defaults['bro_proxy'] = 'localhost'
defaults['suricata_data'] = '/data/suricata/logs'
defaults['netsniff_interval'] = '1GiB'
defaults['netsniff_output'] = '/data/pcap'
defaults['elasticsearch_node_name'] = ''
defaults['elasticsearch_cluster_name'] = 'elasticsearch'
defaults['elasticsearch_heap'] = 1
defaults['elasticsearch_shards'] = 1
defaults['elasticsearch_replica'] = 0
defaults['elasticsearch_path_data'] = '/data/elasticsearch/data'
defaults['elasticsearch_path_logs'] = '/data/elasticsearch/logs'
defaults['elasticsearch_path_plugins'] = ''
defaults['elasticsearch_path_work'] = '/data/elasticsearch/work'
defaults['elasticsearch_master_discovery'] = ''
defaults['kafka_topics'] = ['bro_raw','suricata_raw']
defaults['kibana_nginx'] = 8080
defaults['install_bro'] = False
defaults['install_suricata'] = False
defaults['suricata_kafka'] = False
defaults['install_netsniff'] = False
defaults['install_elasticsearch'] = False
#reduntent default should just enable this when master discovery is set
#defaults['elasticsearch_unicast'] = False
defaults['elasticsearch_master_node'] = True
defaults['elasticsearch_data_node'] = True
defaults['install_kafka'] = False
defaults['install_logstash'] = False
defaults['install_kibana'] = False
logstash-bro-es = True
logstash-suricata-es = True
logstash-bro-kafka = []
logstash-suricata-es = []
logstash-kafka-es = []

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
	required_parser = parser.add_argument_group('required arguments')
	install_parser = parser.add_argument_group('install options')
	bro_parser = parser.add_argument_group('bro options')
	suricata_parser = parser.add_argument_group('suricata options')
	netsniff_parser = parser.add_argument_group('netsniff-ng options')
	es_parser = parser.add_argument_group('elasticsearch options')
	kafka_parser = parser.add_argument_group('kafka options')
	logstash_parser = parser.add_argument_group('logstash options')
	kibana_parser = parser.add_argument_group('kibana options')

	required_parser.add_argument('-H', '--host',type=str, help='Host Name', required=True)
	required_parser.add_argument('-I', '--interface', metavar='INTERFACE',type=str, help='Capture Interface', required=True)
	parser.add_argument('-d', '--domain',type=str,help='Domain name', required=False, default=defaults['domain'])
	

	install_parser.add_argument('--install-bro',  action='store_true', help='Installs bro, brocontrol, pfring, java, dkms, libpcap-pfring and pfring-dkms', required=False, default=defaults['install_bro'])
	#would like to set default to a % of available CPU power instead of hard coded number
	bro_parser.add_argument('--bro-cores', metavar='NUM', type=int, help='Number of cores for bro workers', required=False, default=defaults['bro_cores'])
	bro_parser.add_argument('--bro-logs', metavar='DIR', type=str, help='Directory where bro should save logs', required=False, default=defaults['bro_logs'])
	bro_parser.add_argument('--bro_manager', metavar='HOST', type=str, help='Host that is/will be the manager for a bro cluster', required=False, default=defaults['bro_manager'])
	bro_parser.add_argument('--bro_proxy', metava='HOST', type=str, help='Host that is/will be the proxy for a bro cluster', required=False, default=defaults['bro_proxy'])
	install_parser.add_argument('--install-suricata', action='store_true', help='Installs Suricata, dkms, pfring, libpcap-pfring and pfring-dkms', required=False, default=defaults['install_suricata'])
	suricata_parser.add_argument('--suricata-data', metavar='DIR', help='Directory to store the eve.json', required=False, default=defaults['suricata_data'])
	#parser option not yet implemented. Should have default value of True after implementation.
	suricata_parser.add_argument('--suricata-kafka', action='store_true', help='(Not Implemented)Will no longer write a eve.json and will push data directly into kafka', required=False, default=defaults['suricata_kafka'])
	install_parser.add_argument('--install-netsniff', action='store_true', help='Installs netsniff-ng', required=False, default=defaults['install_netsniff'])
	netsniff_parser.add_argument('--netsniff-interval', metavar='<num>KiB/MiB/GiB/s/sec/min/hrs', type=netsniff_interval, help='Interval for output pcap', required=False, default=defaults['netsniff_interval'])
	netsniff_parser.add_argument('--netsniff-output', metavar='DIR/INTERFACE', type=str, help='Directory/Interface where netsniff-ng should send data', required=False, default=defaults['netsniff_output'])
	install_parser.add_argument('--install-elasticsearch', action='store_true', help='Installs elasticsearch and java', required=False, default=defaults['install_elasticsearch'])
	es_parser.add_argument('--elasticsearch-node-name', metavar='NAME', type=str, help='Sets current elasticsearch\'s node name', required=False, default=defaults['elasticsearch_node_name'])
	es_parser.add_argument('--elasticsearch-cluster-name', metavar='CLUSTER', type=str, help='Sets the cluster this elasticsearch node should connect to', required=False, default=defaults['elasticsearch_cluster_name'])
	#would like to set default to 50% or 32 depending on available RAM.
	es_parser.add_argument('--elasticsearch-heap', metavar='NUM', type=int, help='Sets the amount of RAM elasticsearch is able to use for indexing functions. Recommend 50 percent of availble ram, but no more than 32G', required=False, default=defaults['elasticsearch_heap'])
	# would be nice to dynamically set this but it would probably be a hassle. 
	es_parser.add_argument('--elasticsearch-shards', metavar='NUM', type=int, help='Sets the number of shards for elasticsearch. Recommend lower shard count for smaller configurations', required=False, default=defaults['elasticsearch_shards'])
	es_parser.add_argument('--elasticsearch-replica', metavar='NUM', type=int, help='Sets the number of replicas for elasticsearch. Replicas are used for failover, recommend zero if you have only 1 data node', required=False, default=defaults['elasticsearch_replica'])
	es_parser.add_argument('--elasticsearch-path-data', metavar='DIR', type=str, help='Directory to store elasticsearch data', required=False, default=defaults['elasticsearch_path_data'])
	es_parser.add_argument('--elasticsearch-path-logs', metavar='DIR', type=str, help='Directory to store elasticsearch logs', required=False, default=defaults['elasticsearch_path_logs'])
	# probably wont implement this. No plugins needed at this time
	es_parser.add_argument('--elasticsearch-path-plugins', metavar='DIR', type=str, help='Directory to elasticsearch plugins', required=False, default=defaults['elasticsearch_path_plugins'])
	es_parser.add_argument('--elasticsearch-path-work', metavar='DIR', type=str, help='Directory for elasticsearch to work out of', required=False, default=defaults['elasticsearch_path_work'])
	#Redundent default. Unicast is set when master discovery is set.
	#es_parser.add_argument('--elasticsearch-unicast', action='store_true', help='Enables unicast and disables multicast discovery. If enabled include the --elasticsearch-master-discovery field or elasticsearch wont be able the master nodes', required=False, default=defaults['elasticsearch_unicast'])
	es_parser.add_argument('--elasticsearch-master-discovery', metavar='"NODE', nargs='+', type=str, help='List of master nodes that can be discovered when this node starts ("192.168.1.11, 192.168.1.12, ect..")',required=False, default=defaults['elasticsearch_master_discovery'])
	es_parser.add_argument('--elasticsearch-master-node', action='store_true', help='Makes this elasticsearch node a master node', required=False, default=defaults['elasticsearch_master_node'])
	es_parser.add_argument('--elasticsearch-data-node', action='store_true', help='Makes this elasticsearch node a data node', required=False, default=defaults['elasticsearchdata_node'])
	# need to further research kafka for best defaults for my usecase	
	install_parser.add_argument('--install-kafka', action='store_true', help='Installs kafka and java', required=False, default=defaults['install_kafka'])
	kafka_parser.add_argument('--kafka-topics', metavar='TOPIC(s)', nargs='+', type=list, help='Topic ID(s) kafka should use and cluster with', required=False, default=defaults['kafka_topics'])
	#install_parser.add_argument('--install-logstash', action='store_true', help='Installs logstash and elasticsearch', required=False, default=defaults['install_logstash'])
	#Script will detect when and how logstash is installed
	#logstash_parser.add_argument('--logstash-bro-kafka', metavar='TOPIC', type=str, help='This will setup logstash to move bro logs into a kafka TOPIC ', required=False, default=defaults['logstash_bro_kafka'])
	#logstash_parser.add_argument('--logstash-suricata-kafka', metavar='TOPIC', type=str, help='This will setup logstash to move the eve.json file into a kafka TOPIC', required=False, default=defaults['logstash_suricata_kafka'])
	#logstash_parser.add_argument('--logstash-bro-es', action='store_true', help='This will setup logstash to move bro logs into a local elasticsearch node', required=False, default=defaults['logstash_bro_es'])
	#logstash_parser.add_argument('--logstash-suricata-es', action='store_true', help='This will setup logstash to move the eve.json file into a local elasticsearch node ', required=False, default=defaults['logstash_suricata_es'])
	#logstash_parser.add_argument('--logstash-broker-es', nargs='+', metavar='TOPIC', type=str, help='This will move topics from the kafka broker into elasticsearch', required=False, default=defaults['logstash_broker_es'])
	#install_parser.add_argument('--install-kibana', action='store_true', help='Installs Kibana and an elasticsearch search node', required=False, default=defaults['install_kibana'])
	kibana_parser.add_argument('--kibana-nginx', metavar='PORT', type=int, help='Port used with the nginx proxy for kibana. (This installs nginx)', required=False, default=defaults['kibana_nginx'])
	
	args = parser.parse_args()
	
	# args.elasticsearch_unicast removed from return statement
	return args.host, args.interface, args.domain, args.install_bro, args.bro_cores, args.bro_logs, args.install_suricata, args.suricata_data, args.suricata_kafka, args.install_netsniff, args.netsniff_interval, \
	args.netsniff_output, args.install_elasticsearch, args.elasticsearch_node_name, args.elasticsearch_cluster_name, args.elasticsearch_heap, args.elasticsearch_shards, args.elasticsearch_replica, args.elasticsearch_path_data,\
	args.elasticsearch_path_logs, args.elasticsearch_path_plugins, args.elasticsearch_path_work, args.elasticsearch_master_discovery, args.elasticsearch_master_node, args.elasticsearch_data_node,\
	args.install_kafka, args.kafka_topics, args.kibana_nginx

# es_unicast removed from get statement
host, interface, domain, install_bro, bro_cores, bro_logs, install_suricata, suricata_data, suricata_kafka, install_netsniff, netsniff_interval, netsniff_output, install_es, es_node_name, es_cluster_name, es_heap,\
es_shards, es_replica, es_path_data, es_path_logs, es_path_plugins, es_path_work, es_master_discovery, es_master_node, es_data_node, install_kafka, kafka_topics, kibana_nginx = get_args()

def smarts():
	#This means they added more than the default options
	if(len(sys.argv) > 3):
		#This means they only changed the domain and still wish to have a default install
		if(len(sys.argv == 4 and domain != domain_default):
			default()
		else:
			#Custom run based off user
			user_request()
	#run defaults
	else:
		default()
		
def default():
	print "Installing Default stack..."
	install_bro = True
	install_suricata =True
	install_netsniff = True
	intall_kafka = False
	install_logstash = True
	install_elasticsearch = True
	install_kibana = True
	install_software()


def install_software():
	#list of software that will be installed
	redundant_software = []
	if(install_bro):
		subprocess.call(shlex.split('sudo yum -y install bro'))
		subprocess.call(shlex.split('sudo yum -y install brocontrol'))
		configure('bro')
		if('pfring' not in redundant_software):
			redundant_software.append('pfring')
			subprocess.call(shlex.split('sudo yum -y install pfring'))
			subprocess.call(shlex.split('sudo yum -y install dkms'))
			subprocess.call(shlex.split('sudo yum -y install pfring-dkms'))
			subprocess.call(shlex.split('sudo yum -y install libpcap'))
			configure('pfring')

	if(install_suricata):
		subprocess.call(shlex.split('sudo yum -y install suricata'))
		configure('suricata')
		if('pfring' not in redundant_software):
			redundant_software.append('pfring')
			subprocess.call(shlex.split('sudo yum -y install pfring'))
			subprocess.call(shlex.split('sudo yum -y install dkms'))
			subprocess.call(shlex.split('sudo yum -y install pfring-dkms'))
			subprocess.call(shlex.split('sudo yum -y install libpcap'))
			configure('pfring')

	if(install_netsniff):
		subprocess.call(shlex.split('sudo yum -y install netsniff-ng'))
		configure('netnsiff-ng')

	if(install_logstash):
		subprocess.call(shlex.split('sudo yum -y install logstash'))
		configure('logstash')
		if('java' not in software_to_install):
			subprocess.call(shlex.split('sudo yum -y install java'))

	if(install_elasticsearch):
		subprocess.call(shlex.split('sudo yum -y install elasticsearch'))
		configure('elasticsearch')

	#this might get canned. This is not a RPM and most of the sensors do not have internet connections.
	if(install_kibana):
		if(kibana_nginx):
			subprocess.call(shlex.split('sudo yum -y install nginx-spegno'))
			configure('nginx')
		
	
		
	
def configure(soft):
	#set hostname
	subprocess.call(shlex.split('sudo sethostname '+host+'.'+domain))
	#configure installed software
	
	if(soft == 'bro'):
		#make bro write json files
		#configure node.cfg
		#configure broctl.cfg
		#make broctl start on boot
		#mkdir for logs
		subprocess.call(shlex.split('sudo mkdir -p '+bro_logs))
		subprocess.call(shlex.split('sudo chmod 744 -R '+bro_logs))
	if(soft == 'suricata'):
		#enable eve.json
		#make load-rules script
		#make suricata start on boot
		#mkdir for eve.json
		pass
	if(soft == 'netsniff-ng'):
		#write configuration file
		#make netsniff-ng service file
		
		
		#mkdir for pcap storage
		#should add check for interface or dir, current usecase will result in directory 99% of the time
		subprocess.call(shlex.split('sudo mkdir -p '+netsniff_output))
		subprocess.call(shlex.split('sudo chown 99:99 '+netsniff_output))
		pass
	if(soft == 'logstash'):
		#should be dynamically set prior to getting to this.
		#setup logstash to es
		if(logstash_bro_es or logstash_suricata_es):
			pass
		#setup logstash to kafka
		elif(logstash_bro_kafka != '' or logstash_suricata_kafka != ''):
			pass
		#dual home
		elif(logstash_kafka_es):
			pass
	if(soft == 'elasticsearch'):
		#configure yml file
		#node name
		#cluster name
		#shards
		#replicas
		#data path
		#logs path
		#plugins path
		#work path
		#unicast
		#master discovery
		#master node
		#data node
		#configure heap
		#mkdirs for path
		subprocess.call(shlex.split('sudo mkdir -p /data/pcap/'))
		subprocess.call(shlex.split('sudo chown 99:99 /data/pcap/'))
		pass
	if(soft == 'kibana'):
		#still looking into possible solution
		pass
	if(soft == 'pfring'):
		#configure interface
		#create ifup-local script
		pass
	if(soft == 'nginx'):
		#Configure for kibana
		pass

def user_request():
	if(install_bro or bro_cores != defaults['bro_cores'] or bro_logs != defaults['bro_logs'] or bro_manager != defaults['bro_manager'] or bro_proxy != defaults['bro_proxy']):
		install_bro = True
	#suricata_kafka should be changed to not suricata_kafka once the suricata to kafka writer plugin is figured out.
	if(install_suricata or suricata_data != defaults['suricata_data'] or suricata_kafka):
		install_suricata = True
	if(install_netsniff or netsniff_output != defaults['netsniff_output'] or netsniff_interval != defaults['netsniff_interval']):
		install_netsniff = True
	if(install_elasticsearch or elasticsearch_node_name != defaults['elasticsearch_node_name'] or elasticsearch_cluster_name != defaults['elasticsearch_cluster_name'] or elasticsearch_heap != defaults['elasticsearch_heap'] or elasticsearch_shards != defaults['elasticsearch_shards'] or elasticsearch_replica != defaults['elasticsearch_replica'] or elasticsearch_path_data != defaults['elasticsearch_path_data'] or elasticsearch_path_logs != defaults['elasticsearch_path_logs'] or elasticsearch_path_plugins != defaults['elasticsearch_path_logs'] or elasticsearch_path_work != defaults['elasticsearch_path_work'] or elasticsearch_master_discovery != defaults['elasticsearch_master_discovery'] or not es_master_node or not es_data_node):
		install_elasticsearch = True
		#if bro/suricata installed move logs to es, check later for dual home
		if(install_bro):
			logstash_bro_es = True
		if(install_suricata):
			logstash_suricata_es = True
	if(install_kafka or kafka_topics != defaults['kafka_topics']):
		install_kafka = True
		if(install_bro):
			if(install_elasticsearch):
				logstash_bro_es = False
				logstash_kafka_es = kafka_topics
			#not dual homed
			else:
				logstash_bro_kafka = kafka_topics
				pass
			#should move bro into kafka
			pass
		if(install_suricata):
			if(install_elasticsearch):
				pass
			#not dual homed
			else
				pass

		if(install_elasticsearch):
			#dual homed, should move into kafka then into 
			pass
			
			
	#checks for actual installation selection. It is possilble the user could use a argument and set it to default. If they did not include the --install flag it will not trigger any installation as its expecting a change from default.
	if(install_bro or install_suricata or install_netsniff or install_elasticsearch or install_kafka):
		install_software()
	else:
		print "Dynamic decision failer.\n\nCould not determine what to install.\nIf you want a default installation of a specific software please use the --install_[software] options or provide a value other than the default for selected options. The following are default values used:\n"
		for item in defaults:
			print item
		sys.exit(0)	

smarts()



