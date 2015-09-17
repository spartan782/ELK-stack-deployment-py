#!/bin/python
import argparse, subprocess, shlex, sys
defaults = {}
defaults['host'] = ''
defaults['interface'] = ''
defaults['domain'] = ''
defaults['bro_cores'] = 1
defaults['bro_logs'] = '/data/bro/logs'
defaults['bro_manager'] = 'localhost'
defaults['bro_proxy'] = 'localhost'
defaults['bro_workers'] = ['localhost']
defaults['bro_user'] = 'bro'
defaults['bro_user_pass'] = 'bro'
defaults['suricata_data'] = '/data/suricata/logs'
defaults['netsniff_interval'] = '1GiB'
defaults['netsniff_output_dir'] = '/data/pcap'
defaults['netsniff_output_if'] = ''
defaults['elasticsearch_node_name'] = ''
defaults['elasticsearch_cluster_name'] = 'elasticsearch'
defaults['elasticsearch_heap'] = 1
defaults['elasticsearch_shards'] = 1
defaults['elasticsearch_replicas'] = 0
defaults['elasticsearch_path_data'] = '/data/elasticsearch/data'
defaults['elasticsearch_path_logs'] = '/data/elasticsearch/logs'
defaults['elasticsearch_path_plugins'] = ''
defaults['elasticsearch_path_work'] = '/data/elasticsearch/work'
defaults['elasticsearch_master_discovery'] = ''
defaults['kafka_topics'] = ['bro_raw','suricata_raw']
defaults['kibana_nginx'] = 8080
defaults['install_bro'] = False
#This isnt implemented but this controls a cluster. Should setup script to install bro with no node.cfg and then a manager node using the brocontrol option in the future.
defaults['install_brocontrol'] = False
defaults['install_suricata'] = False
defaults['suricata_kafka'] = False
defaults['install_netsniff'] = False
defaults['install_elasticsearch'] = False
#reduntent default should just enable this when master discovery is set
#defaults['elasticsearch_unicast'] = False
defaults['elasticsearch_master_node'] = True
defaults['elasticsearch_data_node'] = True
defaults['install_kafka'] = False
install_logstash = False
#defaults['install_logstash'] = False
defaults['install_kibana'] = False
logstash_bro_elasticsearch = True
logstash_suricata_elasticsearch = True
logstash_bro_kafka = []
logstash_suricata_elasticsearch = []
logstash_kafka_elasticsearch = []
logstash_kafka_elasticsearch_only = False
cpu_ids = [0]

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
	brocontrol_parser = parser.add_argument_group('bro control options')
	suricata_parser = parser.add_argument_group('suricata options')
	netsniff_parser = parser.add_argument_group('netsniff-ng options')
	es_parser = parser.add_argument_group('elasticsearch options')
	kafka_parser = parser.add_argument_group('kafka options')
	logstash_parser = parser.add_argument_group('logstash options')
	kibana_parser = parser.add_argument_group('kibana options')

	parser.add_argument('-H', '--host',type=str, help='Host Name, optional but highly recommended when installing Bro/Suricata/Netsniff-ng', required=False, default=defaults['host'] )
	required_parser.add_argument('-I', '--interface', metavar='INTERFACE',type=str, help='Capture Interface, Required for Bro/Suricata/Netsniff-ng installs', required=False, default=defaults['interface'])
	parser.add_argument('-d', '--domain',type=str,help='Domain name', required=False, default=defaults['domain'])
	

	install_parser.add_argument('--install-bro',  action='store_true', help='Installs bro, pfring, java, dkms, libpcap-pfring and pfring-dkms', required=False, default=defaults['install_bro'])
	#would like to set default to a % of available CPU power instead of hard coded number
	install_parser.add_argument('--install-brocontrol', action='store_true', help='Installs brocontrol to manage bro workers', required=False, default=defaults['install_brocontrol'])
	brocontrol_parser.add_argument('--bro-cores', metavar='NUM', type=int, help='Number of cores for bro workers', required=False, default=defaults['bro_cores'])
	brocontrol_parser.add_argument('--bro-logs', metavar='DIR', type=str, help='Directory where bro should save logs', required=False, default=defaults['bro_logs'])
	brocontrol_parser.add_argument('--bro-manager', metavar='HOST', type=str, help='Host that is/will be the manager for a bro cluster', required=False, default=defaults['bro_manager'])
	brocontrol_parser.add_argument('--bro-proxy', metavar='HOST', type=str, help='Host that is/will be the proxy for a bro cluster', required=False, default=defaults['bro_proxy'])
	brocontrol_parser.add_argument('--bro-user', metavar='USER', type=str, help='User that will log into remove bro nodes. (Must exist on each bro worker node)', required=False, default=defaults['bro_user'])
	brocontrol_parser.add_argument('--bro-user-pass', metavar='PASSWORD', type=str, help='Password for the bro User. (used to setup password less ssh)', required=False, default=defaults['bro_user_pass'])
	brocontrol_parser.add_argument('--bro-workers', metavar='HOST(s)', nargs='+', type=str, help='Hosts that are bro workers and need to be managed', required=False, default=defaults['bro_workers'])	
	install_parser.add_argument('--install-suricata', action='store_true', help='Installs Suricata, dkms, pfring, libpcap-pfring and pfring-dkms', required=False, default=defaults['install_suricata'])
	suricata_parser.add_argument('--suricata-data', metavar='DIR', help='Directory to store the eve.json', required=False, default=defaults['suricata_data'])
	#parser option not yet implemented. Should have default value of True after implementation.
	suricata_parser.add_argument('--suricata-kafka', action='store_true', help='(Not Implemented)Will no longer write a eve.json and will push data directly into kafka', required=False, default=defaults['suricata_kafka'])
	install_parser.add_argument('--install-netsniff', action='store_true', help='Installs netsniff-ng', required=False, default=defaults['install_netsniff'])
	netsniff_parser.add_argument('--netsniff-interval', metavar='<num>KiB/MiB/GiB/s/sec/min/hrs', type=netsniff_interval, help='Interval for output pcap', required=False, default=defaults['netsniff_interval'])
	netsniff_parser.add_argument('--netsniff-output-dir', metavar='DIR', type=str, help='Directory where netsniff-ng should store pcap', required=False, default=defaults['netsniff_output_dir'])
	netsniff_parser.add_argument('--netsniff-output-if', metavar='INTERFACE', type=str, help='Interface where netsniff-ng should send output data', required=False, default=defaults['netsniff_output_if'])
	install_parser.add_argument('--install-elasticsearch', action='store_true', help='Installs elasticsearch and java', required=False, default=defaults['install_elasticsearch'])
	es_parser.add_argument('--elasticsearch-node-name', metavar='NAME', type=str, help='Sets current elasticsearch\'s node name', required=False, default=defaults['elasticsearch_node_name'])
	es_parser.add_argument('--elasticsearch-cluster-name', metavar='CLUSTER', type=str, help='Sets the cluster this elasticsearch node should connect to', required=False, default=defaults['elasticsearch_cluster_name'])
	#would like to set default to 50% or 32 depending on available RAM.
	es_parser.add_argument('--elasticsearch-heap', metavar='NUM', type=int, help='Sets the amount of RAM elasticsearch is able to use for indexing functions. Recommend 50 percent of availble ram, but no more than 32G', required=False, default=defaults['elasticsearch_heap'])
	# would be nice to dynamically set this but it would probably be a hassle. 
	es_parser.add_argument('--elasticsearch-shards', metavar='NUM', type=int, help='Sets the number of shards for elasticsearch. Recommend lower shard count for smaller configurations', required=False, default=defaults['elasticsearch_shards'])
	es_parser.add_argument('--elasticsearch-replicas', metavar='NUM', type=int, help='Sets the number of replicas for elasticsearch. Replicas are used for failover, recommend zero if you have only 1 data node', required=False, default=defaults['elasticsearch_replicas'])
	es_parser.add_argument('--elasticsearch-path-data', metavar='DIR', type=str, help='Directory to store elasticsearch data', required=False, default=defaults['elasticsearch_path_data'])
	es_parser.add_argument('--elasticsearch-path-logs', metavar='DIR', type=str, help='Directory to store elasticsearch logs', required=False, default=defaults['elasticsearch_path_logs'])
	# probably wont implement this. No plugins needed at this time
	es_parser.add_argument('--elasticsearch-path-plugins', metavar='DIR', type=str, help='Directory to elasticsearch plugins', required=False, default=defaults['elasticsearch_path_plugins'])
	es_parser.add_argument('--elasticsearch-path-work', metavar='DIR', type=str, help='Directory for elasticsearch to work out of', required=False, default=defaults['elasticsearch_path_work'])
	#Redundent default. Unicast is set when master discovery is set.
	#es_parser.add_argument('--elasticsearch-unicast', action='store_true', help='Enables unicast and disables multicast discovery. If enabled include the --elasticsearch-master-discovery field or elasticsearch wont be able the master nodes', required=False, default=defaults['elasticsearch_unicast'])
	es_parser.add_argument('--elasticsearch-master-discovery', metavar='"NODE(s)', nargs='+', type=str, help='List of master nodes that can be discovered when this node starts (192.168.1.11, 192.168.1.12, ect..)',required=False, default=defaults['elasticsearch_master_discovery'])
	es_parser.add_argument('--elasticsearch-master-node', action='store_true', help='Makes this elasticsearch node a master node', required=False, default=defaults['elasticsearch_master_node'])
	es_parser.add_argument('--elasticsearch-data-node', action='store_true', help='Makes this elasticsearch node a data node', required=False, default=defaults['elasticsearch_data_node'])
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
	
	return args.host, args.interface, args.domain, args.install_bro, args.bro_cores, args.bro_logs, args.install_suricata, args.suricata_data, args.suricata_kafka, args.install_netsniff, args.netsniff_interval, \
	args.netsniff_output_dir, args.netsniff_output_if, args.install_elasticsearch, args.elasticsearch_node_name, args.elasticsearch_cluster_name, args.elasticsearch_heap, args.elasticsearch_shards, args.elasticsearch_replicas, args.elasticsearch_path_data,\
	args.elasticsearch_path_logs, args.elasticsearch_path_plugins, args.elasticsearch_path_work, args.elasticsearch_master_discovery, args.elasticsearch_master_node, args.elasticsearch_data_node,\
	args.install_kafka, args.kafka_topics, args.kibana_nginx, args.bro_manager, args.bro_proxy, args.bro_user, args.bro_user_pass, args.bro_workers, args.install_brocontrol

def install_software():
	global install_bro, install_brocontrol, install_elasticsearch, install_kafka, install_kibana, install_logstash, install_netsniff, install_suricata
	#list of software that will be installed
	redundant_software = []
	if(install_brocontrol):
		subprocess.call(shlex.split('sudo yum -y install brocontrol'))
		install_bro = True
		configure('brocontrol')
	if(install_bro):
		subprocess.call(shlex.split('sudo yum -y install gperftools-libs'))
		subprocess.call(shlex.split('sudo yum -y install libunwind'))
		subprocess.call(shlex.split('sudo yum -y install bro'))
		configure('bro')
		if('pfring' not in redundant_software):
			redundant_software.append('pfring')
			subprocess.call(shlex.split('sudo yum -y install pfring'))
			subprocess.call(shlex.split('sudo yum -y install dkms'))
			subprocess.call(shlex.split('sudo yum -y install pfring-dkms'))
			subprocess.call(shlex.split('sudo yum -y install libpcap-pfring'))
			configure('pfring')

	if(install_suricata):
		subprocess.call(shlex.split('sudo yum -y install suricata'))
		configure('suricata')
		if('pfring' not in redundant_software):
			redundant_software.append('pfring')
			subprocess.call(shlex.split('sudo yum -y install pfring'))
			subprocess.call(shlex.split('sudo yum -y install dkms'))
			subprocess.call(shlex.split('sudo yum -y install pfring-dkms'))
			subprocess.call(shlex.split('sudo yum -y install libpcap-pfring'))
			configure('pfring')

	if(install_netsniff):
		subprocess.call(shlex.split('sudo yum -y install netsniff-ng'))
		configure('netnsiff-ng')

	if(install_logstash):
		subprocess.call(shlex.split('sudo yum -y install logstash'))
		configure('logstash')
		if('java' not in software_to_install):
			subprocess.call(shlex.split('sudo yum -y install java-1.8.0-oracle-headless'))

	if(install_elasticsearch):
		subprocess.call(shlex.split('sudo yum -y install elasticsearch'))
		configure('elasticsearch')

	#this might get canned. This is not a RPM and most of the sensors do not have internet connections.
	if(install_kibana):
		if(kibana_nginx):
			subprocess.call(shlex.split('sudo yum -y install nginx-spegno'))
			configure('nginx')
		

def bro_to_elasticsearch():
	bro_logs_current = bro_logs+'/current/'
	f = open('/etc/logstash/conf.d/bro-elasticsearch.conf', 'w')
	f.write('input {\n\tfile {\n\t\tpath => '+bro_logs_current+'*.log\n\t\texclude => [\
	\''+bro_logs_current+'capture_loss.log\',\
	\''+bro_logs_current+'cluster.log\',\
	\''+bro_logs_current+'communication.log\',\
	\''+bro_logs_current+'loaded_scripts.log\',\
	\''+bro_logs_current+'packet_filter.log\',\
	\''+bro_logs_current+'prof.log\',\
	\''+bro_logs_current+'reporter.log\',\
	\''+bro_logs_current+'stats.log\',\
	\''+bro_logs_current+'stderr.log\',\
	\''+bro_logs_current+'stdout.log\',]\
	\n\t\tcodec => "json"\n\t\ttype => "bro"\n\t\tadd_field => {"[@metadata][stage]" => "bro_raw" }\n\t}\n}\n\nfilter {\n\tif [@metdata][stage] == "bro_raw" {\n\t\tdate {\n\t\t\tmatch => ["ts", "ISO8601"]\n\t\t}\n\n\t\truby {\n\t\t\tcode => "event[\'path\'] = event[\'path\'].split(\'/\')[-1].split(\'.\')[0]"\n\t\t}\n\t}\n}\n\noutput {\n\tif [@metadata][stage] == "bro_raw" {\n\t\telasticseach { host => localhost}\n\t}\n}')
	f.close()
def suricata_to_elasticsearch():
	f = open('/etc/logstash/conf.d/suricata-elasticsearch.conf', 'w')
	f.write('input {\n\tfile {\n\t\tpath => '+suricata_data+'eve.json\n\t\tcodec => "json"\n\t\ttype => "suricata"\n\t\tadd_field => {"[@metadata][stage]" => "suricata_raw" }\n\t}\n}\n\nfilter {\n\tif [@metadata][stage] == "suricata_raw" {\n\t\tdate {\n\t\t\tmatch => ["timestamp", "ISO8601"]\n\t\t}\n\n\t\truby {\n\t\t\tcode => "event[\'path\'] = \'event\'"\n\t\t}\n\t}\n}\n\noutput {\n\tif [@metadata][stage] == "suricata_raw" {\n\t\telasticsearch { host => localhost }\n\t}\n}')
	f.close()
def bro_to_kafka():
	f = open('/etc/logstash/conf.d/bro-elasticsearch.conf', 'w')
	f.write('input {\n\tfile {\n\t\tpath => '+bro_logs+'/current/*.log\n\t\texclude => [\''+bro_logs+'/current/stderr.log\', \''+bro_logs+'/current/stdout.log\',\''+bro_logs+'/current/communication.log\',\''+bro_logs+'/current/loaded_scripts.log\']\n\t\tcodec => "json"\n\t\ttype => "bro"\n\t\tadd_field => {"[@metadata][stage]" => "bro_raw" }\n\t}\n}\n\nfilter {\n\tif [@metadata][stage] == "bro_raw" {\n\t\tdate {\n\t\t\tmatch => ["ts", "ISO8601"]\n\t\t}\n\n\t\truby {\n\t\t\tcode => "event[\'path\'] = event[\'path\'].split(\'/\')[-1].split(\'.\')[0]"\n\t\t}\n\t}\n}\n\noutput {\n\tif [@metadata][stage] == "bro_raw" {\n\t\tkafka { topic_id => "bro_raw"}\n\t}\n}')
	f.close()
def suricata_to_kafka():
	f = open('/etc/logstash/conf.d/suricata-elasticsearch.conf', 'w')
	f.write('input {\n\tfile {\n\t\tpath => '+suricata_data+'eve.json\n\t\tcodec => "json"\n\t\ttype => "suricata"\n\t\tadd_field => {"[@metadata][stage]" => "suricata_raw" }\n\t}\n}\n\nfilter {\n\tif [@metadata][stage] == "suricata_raw" {\n\t\tdate {\n\t\t\tmatch => ["timestamp", "ISO8601"]\n\t\t}\n\n\t\truby {\n\t\t\tcode => "event[\'path\'] = \'event\'"\n\t\t}\n\t}\n}\n\noutput {\n\tif [@metadata][stage] == "suricata_raw" {\n\t\tkafka { topic_id => "suricata_raw" }\n\t}\n}')
	f.close()
def kafka_to_elasticsearch():
	for topic in kafka_topics:
		f = open(str(topic)+'_kafka_elasticsearch.conf','w')
		f.write('input {\n\tkafka {\n\t\ttopic_id => "'+topic+'"\n\t\tadd_field => { "[@metadata][stage]" => "'+topic+'_kafka"}\n\t}\n}\n\noutput {\n\tif [@metadata][stage] == "'+topic+'_kafka" {\n\t\telasticsearch {host => localhost}\n\t}\n}')
		f.close()

		
	
def configure(soft):
	#set hostname
	subprocess.call(shlex.split('sudo sethostname '+host+'.'+domain))
	#configure installed software
	
	##############Pinning multipe bro cores still needs to be figured out. Bro likes to pin physical not virtual
	if(soft == 'bro'):
		#make bro write json files
		f = open('/opt/bro/share/bro/policy/tuning/json-logs.bro', 'a')
		f.write('redef LogAscii::json_timestamps = JSON::TS_ISO8601;')
		f.close()
		f = open('/opt/bro/share/bro/site/local.bro', 'a')
		f.write('@load tuning/json-logs')
		f.close()
		
	if(soft == 'brocontrol')
		#Add passwordless ssh for each bro node
		print "Setting up ssh for bro. Please use all defaults by pressing the enter key"
		for node in bro_workers:
			subprocess.call(shlex.split('su -c "ssh-keygen -t rsa" - '+bro_user))
			subprocess.call(shlex.split('su -c "ssh-copy-id '+bro_user+'@'+node+'" - '+bro_user))
		subprocess.call(shlex.split('sudo /opt/bro/bin/broctl install'))
		subprocess.call(shlex.split('sudo /opt/bro/bin/broctl stop'))
		"""
		-----------------------
		Could probably use the salt module to help setup the bro cluster with better scalability along with more control and correctness of cpu pinnings
		-----------------------
		"""
		#used to copy /proc/cpuinfo into memory
		proc_cpuinfo = []
		#dictionary used to store all processor => core ids
		cpu_info = {}
		#temp storage for single found processor_id
		processor_id = ''
		#temp storage for single found core_id
		core_id = ''
		#read in the /proc/cpuinfo file
		f = open('/proc/cpuinfo', 'r')
			for line in f:
				#store the file
				proc_cpuinfo.append(line)
				"""Below can be used to find hyper threading if needed"""
				#if('ht' in line):
					#hyper_threading = True
				#store the processor_id
				if('processor' in line):
					processor_id = line.split(':')[1]
				#store the core_id and add processor as key and core_id as value to dictionary
				if('core id' in line):
					core_id = line.split(':')[1]
					cpu_info[processor_id] = core_id
		f.close()
		#remove any duplicated cores
		unique_processor_cores = {}
		for key,value in cpu_info.items():
			if(value not in unique_processor_cores.values()):
				unique_processor_cores[key] = value
		#loop through until we have added the number of bro_cores needed
		temp_count = 0
		for key,value in unique_processor_cores.items():
			if(temp_count < bro_cores):
				cpu_ids.append(key)
				temp_count += 1
		#configure node.cfg
		f = open('/opt/bro/etc/node.cfg', 'w')
		f.write('[manager]\ntype=manager\nhost='+bro_manager)
		temp_count = 1
		for node in bro_workers:
			f.write('\n\n[proxy-'+str(temp_count)+']\nhost='+node+'\n\n[worker-'+temp_count+']\ntype=worker\nhost='+node+'\ninterface='+interface+'\nlb_method=pf_ring\nlb_procs='+bro_cores+'\pin_cpus='+str(cpu_ids[1:]).replace('[','').replace(']',''))
			temp_count += 1
			#\n\n[proxy-1]\ntype=proxy\nhost='+host+'\n\n[monitor]\ntype=worker\nhost='+host+'\ninterface='+interface+'\nlb_method=pf_ring\nlb_procs='+bro_cores+'\npin_cpus='+str(cpu_ids[1:]).replace('[','').replace(']',''))
		f.close()
		
	"""Below is a library that can check the number of cores. It doesnt give id's back and does not distinguish between virtual cores and physical cores """
		#import multiprocessing
		#virtual_cpus = multiprocessing.cpu_count()
		#if(hyper_threading):
		#	physical_cpus = virtual_cpus/2
		#else:
		#	physical_cpus = virtual_cpus
			#add cpu_id to list
			#cpu_ids.append()
		#returns a list of processor and core id's. 
		##grep -E 'processor|core.id' /proc/cpuinfo | xargs -L 2
		#configure broctl.cfg
		orig_file = []
		f = open('/opt/bro/etc/broctl.cfg','r')
		for line in f:
			orig_file.append(line)
		f.close()
		f = open('/opt/bro/etc/broctl.cfg','w')
		for line in orig_file:
			if('LogDir' in line):
				f.write('LogDir = '+bro_logs)
			else:
				f.write(line)
		f.close()
		#make broctl start on boot
		subprocess.call(shlex.split('sudo ln -s /opt/bro/bin/broctl /etc/init.d/'))
		#mkdir for logs
		subprocess.call(shlex.split('sudo mkdir -p '+bro_logs))
		subprocess.call(shlex.split('sudo chmod 744 -R '+bro_logs))
		#start broctl
		subprocess.call(shlex.split('sudo service broctl deploy'))
	if(soft == 'suricata'):
		#make load-rules script
		f = open('/etc/suricata/load-rules', 'w')
		f.write('#!/bin/bash\n\nrm -f /etc/suricata/json.rules\ntouch /etc/suricata/json.rules\nfor item in /etc/suricata/rules/*.rules; do echo " - $(basename $item)" >> /etc/suricata/json.rules; done\nsudo cat /etc/suricata/suricata.yaml > /etc/suricata/suricata.yaml.back\nsudo cat /etc/suricata/suricata.yaml | grep \'\\.rules\' -v | sed \'/rule-files:/ r /etc/suricata/json.rules\' > /etc/suricata/temp.rules\nsudo cat /etc/suricata/temp.rules > /etc/suricata/suricata.yaml\nrm -f json.rules\nrm -f temp.rules')		
		f.close()
		subprocess.call(shlex.split('sudo chmod 755 /etc/suricata/load-rules'))
		#load current rules
		subprocess.call(shlex.split('sudo /etc/suricata/load-rules'))
		#make suricata start on boot
		subprocess.call(shlex.split('sudo chkconfig suricata on'))
		#mkdir for eve.json
		orig_file = []
		subprocess.call(shlex('sudo mkdir '+suricata_data))
		#change default data dir for suricata
		f = open('/etc/suricata/suricata.yaml', 'r')
		for line in f:
			orig_file.append(line)
		f.close()
		f = open('/etc/suricata/suricata.yaml', 'w')
		for line in orig_file:
			if('default-log-dir' in line):
				f.write('default-log-dir: '+suricata_data)
			else:
				f.write(line)
		f.close()
	if(soft == 'netsniff-ng'):
		#write configuration file
		f = open('/etc/sysconfig/netsniff-ng','w')
		f.write('PROM_INTERFACE='+interface+'\nUSER=nobody\nGROUP=nobody\nINTERVAL='+netsniff_interval+'\nDATA_DIR='+netsniff_output)
		f.close()
		#make netsniff-ng service file
		f = open('/etc/systemd/system/netsniff-ng.service', 'w')
		f.write('[Unit]\nDescription=PCAP Collection Beast\nAfter=network.target\n\n[Service]\nEnvironmentFile=/etc/sysconfig/netsniff-ng\nExecStart=/sbin/netsniff-ng --in ${PROM_INTERFACE} --out ${DATA_DIR} --silent --user ${USER} --group ${GROUP} --interval ${INTERVAL}\nType=simple\n\n[Install]\nWantedBy=multi-user.target')
		f.close()
		#mkdir for pcap storage
			#should add check for interface or dir, current usecase will result in directory 99% of the time
		subprocess.call(shlex.split('sudo mkdir -p '+netsniff_output))
		subprocess.call(shlex.split('sudo chown nobody:nobody '+netsniff_output))
		pass
	if(soft == 'logstash'):
		#should be dynamically set prior to getting to this.
		#setup logstash to es
		if(logstash_bro_elasticsearch or logstash_suricata_elasticsearch):
			#bro to es
			if(logstash_bro_elasticsearch):
				bro_to_elasticsearch()
			#suricata to es
			if(logstash_suricata_elasticsearch):
				suricata_to_elasticsearch()
		#setup logstash to kafka
		elif(logstash_bro_kafka != '' or logstash_suricata_kafka != ''):
			#bro to kafka
			if(logstash_bro_kafka != ''):
				bro_to_kafka()
			#suricata to kafka
			if(logstash_suricata_kafka != ''):
				suricata_to_kafka()
		#setup kafka to es
		elif(logstash_kafka_elasticsearch):
			#kakfa to es
			if(logstash_kafka_elasticsearch_only):
				kafka_to_elasticsearch()
			else:
			#bro/suricata to kafka to es
				if(logstash_bro_elasticsearch):
					bro_to_kafka()
				if(logstash_suricata_elasticsearch):
					suricata_to_kafka()
				kafka_to_elasticsearch()
	if(soft == 'elasticsearch'):
		#configure yml file
		f = open('/etc/elasticsearch/elasticsearch.yml', 'w')
		#node name
		f.write('node.name: '+elasticsearch_node_name+'\n')
		#cluster name
		f.write('cluster.name: '+elasticsearch_cluster_name+'\n')
		#shards
		f.write('index.number_of_shards: '+str(elasticsearch_shards)+'\n')
		#replicas
		f.write('index.number_of_replicas: '+elasticsearch_replicas+'\n')
		#data path
		f.write('path.data: '+elasticsearch_path_data+'\n')
		#logs path
		f.write('path.logs: '+elasticsearch_path_logs+'\n')
		#plugins path
		f.write('path.plugins: '+elasticsearch_path_plugins+'\n')
		#work path
		f.write('path.work: '+elasticsearch_path_work+'\n')
		#unicast/master discovery
		#create formated string
		temp = '['
		for node in elasticsearch_master_discovery:
			temp +='"'+node.split(',')[0]+'",'
		#remove extra , (comma) from string
		temp = temp[:-1]
		#complete list
		temp += ']'
		f.write('discovery.zen.ping.unicast.hosts: '+temp+'\n')
		#master node
		f.write('node.master: '+str(elasticsearch_master_node).lower()+'\n')
		#data node
		f.write('node.data: '+str(elasticsearch_data_node).lower()+'\n')
		f.close()
		#configure heap
		orig_file = []
		f = open('/etc/sysconfig/elasticsearch', 'r')
		for line in f:
			orig_file.append(line)
		f.close()
		f = open('/etc/sysconfig/elasticsearch', 'w')
		for line in orig_file:
			if('ES_HEAP_SIZE' in line):
				f.write('ES_HEAP_SIZE='+str(elasticsearch_heap)+'g')
			else:
				f.write(line)
		f.close()
		#mkdirs for path
		subprocess.call(shlex.split('sudo mkdir -p '+elasticsearch_path_data))
		subprocess.call(shlex.split('sudo mkdir -p '+elasticsearch_path_work))
		subprocess.call(shlex.split('sudo mkdir -p '+elasticsearch_path_logs))
	if(soft == 'kibana'):
		#still looking into possible solution
		pass
	if(soft == 'kakfa'):
		"""
		----------------
		Configure Kafka here
		----------------
		"""
		pass
	if(soft == 'pfring'):
		
		#create ifup-local script
		f = open('/sbin/ifup-local','w')
		f.write('#!/bin/bash\n\ncase "$1" in\np1p2)\n\techo "turning off offloading on $1"\n\t/sbin/ethtool -K $1 tso off gro off lro off gso off rx off tx off sg off rxvlan off txvlan off\n\tethtool -N $1 rx-flow-hash udp4 sdfn\n\tethtool -N $1 rx-flow-hash udp6 sdfn\n\tethtool -C $1 adaptive-rx off\n\tethtool -C $1 rx-usecs 1000\n\tethtool -G $1 rx 4096\n\n;;\n*)\n;;\nesac\nexit 0')
		f.close()
		subprocess.call(shlex.split('sudo chmod 755 /sbin/ifup-local'))
		#configure interface
		subprocess.call(shlex.split('sudo /sbin/ifup-local '+interface))
	if(soft == 'nginx'):
		#Configure for kibana nginx proxy
		f = open('/etc/nginx/conf.d/kibana.conf','w')
		"""
		------------------------
		confirm config file for syntax
		------------------------
		"""
		f.write('server {\n\tlisten 80;\n\tserver_name kibana;\n\tauth_gss off;\n\tauth_gss_keytab /etc/nginx/ipa.keytab;\n\n\tlocation / {\n\t\tproxy_pass http://localhost:5601;\n\t\tproxy_http_version 1.1;\n\t\tproxy_set_header upgrade $http_upgrade;\n\t\tproxy_set_header connection \'upgrade\';\n\t\tproxy_set_header host $host;\n\t\tproxy_cache_bypass $http_upgrade;\n\t}\n}')
		f.close()

def user_request():
	global install_bro, install_brocontrol, install_suricata, install_elasticsearch, install_kafka, install_netsniff, install_kibana, install_logstash
	if(install_brocontrol or  bro_cores != defaults['bro_cores'] or bro_logs != defaults['bro_logs'] or bro_manager != defaults['bro_manager'] or bro_proxy != defaults['bro_proxy']):
		if(interface == '')
			print 'Brocontrol requires -I or --interface option'
			sys.exit(0)
		else:
			install_brocontrol = True
			
	if(install_bro):
		if(interface == '')
			print 'Bro requires -I or --interface option'
			sys.exit(0)
		else:
			install_bro = True
	#suricata_kafka should be changed to not suricata_kafka once the suricata to kafka writer plugin is figured out.
	if(install_suricata or suricata_data != defaults['suricata_data'] or suricata_kafka):
		if(interface == ''):
			print 'Suricata requires -I or --interface option'
			sys.exit(0)
		else:
			install_suricata = True
	if(install_netsniff or netsniff_output_dir != defaults['netsniff_output_dir'] or netsniff_output_if != defaults['netsniff_output_if'] or netsniff_interval != defaults['netsniff_interval']):
		if():
			print 'Netsniff-ng requires -I or --interface option'
			sys.exit(0)
		else:
			install_netsniff = True
	if(install_elasticsearch or elasticsearch_node_name != defaults['elasticsearch_node_name'] or elasticsearch_cluster_name != defaults['elasticsearch_cluster_name'] or elasticsearch_heap != defaults['elasticsearch_heap'] or elasticsearch_shards != defaults['elasticsearch_shards'] or elasticsearch_replicas != defaults['elasticsearch_replicas'] or elasticsearch_path_data != defaults['elasticsearch_path_data'] or elasticsearch_path_logs != defaults['elasticsearch_path_logs'] or elasticsearch_path_plugins != defaults['elasticsearch_path_logs'] or elasticsearch_path_work != defaults['elasticsearch_path_work'] or elasticsearch_master_discovery != defaults['elasticsearch_master_discovery'] or not elasticsearch_master_node or not elasticsearch_data_node):
		install_elasticsearch = True
		#if bro/suricata installed move logs to es, check later for dual home
		if(install_bro):
			logstash_bro_elasticsearch = True
		if(install_suricata):
			logstash_suricata_elasticsearch = True
	if(install_kafka or kafka_topics != defaults['kafka_topics']):
		install_kafka = True
		#bro was installed this is not a cluster only box
		if(install_bro):
			logstash_bro_elasticsearch = False
			#dual homed
			if(install_elasticsearch):
				logstash_kafka_elasticsearch = kafka_topics
			#Bro to kafka/not dual homed
			else:
				logstash_bro_kafka = kafka_topics
		#suricata was installed this is not a cluster only box
		if(install_suricata):
			logstash_suricata_elasticsearch = False
			#dual homed
			if(install_elasticsearch):
				logstash_kafka_elasticsearch = kafka_topics
			#suricata to kafka/not dual homed
			else:
				logstash_suricata_kafka = kafka_topics

		if(install_elasticsearch):
			#dual homed but does not need bro/suricata config. Kafka to es only
			logstash_kafka_elasticsearch_only = True
			logstash_kafka_elasticsearch = kafka_topics
			
			
	#checks for actual installation selection. It is possilble the user could use a argument and set it to default. If they did not include the --install flag it will not trigger any installation as its expecting a change from default.
	if(install_bro or install_suricata or install_netsniff or install_elasticsearch or install_kafka):
		install_software()
	else:
		print "Dynamic decision failer.\n\nCould not determine what to install.\nTry -h or --help\nIf you want a default installation of a specific software please use the --install_[software] options or provide a value other than the default for selected options. The following are default values used:\n"
		for item in defaults:
			print item
		sys.exit(0)	

		
host, interface, domain, install_bro, bro_cores, bro_logs, install_suricata, suricata_data, suricata_kafka, install_netsniff, netsniff_interval, netsniff_output_dir, netsniff_output_if, install_elasticsearch, elasticsearch_node_name, elasticsearch_cluster_name, elasticsearch_heap,\
elasticsearch_shards, elasticsearch_replicas, elasticsearch_path_data, elasticsearch_path_logs, elasticsearch_path_plugins, elasticsearch_path_work, elasticsearch_master_discovery, elasticsearch_master_node, elasticsearch_data_node, install_kafka, kafka_topics, kibana_nginx, bro_manager, bro_proxy, bro_user, bro_user_pass, bro_workers, install_bro = get_args()

user_request()
