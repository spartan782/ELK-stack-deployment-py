import subprocess, re, shlex, os, time, getpass, paramiko, scp, math


def connection_test(ip_list, repo_box, ssh_user):
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    conn_failers = []
    ssh_failers = []
    socket_failers = []
    conn_succeeders = []
    conn_error = 0
    kibana_match = ''
    emerging_match = ''
    ssh_username, ssh_password = ssh_user
    repo_ip, repo_port, repo_dir = repo_box
    kibana_skip = False
    emerging_skip = False
    if repo_ip not in ip_list:
        ip_list.append(repo_ip)
    for ip in ip_list:
        print 'Running connectivity test between this box and '+str(ip)+'\n'
        ping_result = subprocess.call(shlex.split('ping -c 2 '+str(ip)), stdout=open(os.devnull, 'w'))
        if ping_result != 0:
            conn_failers.append(ip)

        else:
            conn_succeeders.append(ip)

        try:
            ssh_connection.connect(ip, 22, ssh_username, ssh_password)
        except:
            ssh_failers.append(ip)

        if ip == repo_ip and ip not in socket_failers:
            stdin, stdout, stderr = ssh_connection.exec_command('sudo chcon -R -u system_u -t httpd_sys_content_t '
                                                                ''+repo_dir, get_pty=True)
            stdout.flush()
            stdin.write(ssh_password+'\n')
            stdin.flush()

            stdin, stdout, stderr = ssh_connection.exec_command('sudo ls -l '+repo_dir+' | tail -n +2 ', get_pty=True)
            stdin.write(ssh_password+'\n')
            stdin.flush()

            # if stderr is null move on, otherwise directory supplied is incorrect
            kibana_not_found = 1
            emerging_threats_not_found = 1
            dirs = ['criticalstack-oracle', 'criticalstack-smb', 'cyberdev-capes', 'dcode-cyberdev',
                    'rhel-7-server-beta-rpms', 'rhel-7-server-optional-rpms', 'rhel-7-server-rpms',
                    'rhel-7-server-thirdparty-oracle-java-rpms']

            for line in stdout.read().splitlines():
                formatted_line = line.split(' ')[-1]
                try:
                    if kibana_not_found:
                        kibana_match = re.search(r'kibana.*tar.*', formatted_line).group()
                        kibana_not_found = 0
                except AttributeError:
                    kibana_not_found = 1
                try:
                    if emerging_threats_not_found:
                        emerging_match = re.search(r'emerging.*tar.*', formatted_line).group()
                        emerging_threats_not_found = 0
                except AttributeError:
                    emerging_threats_not_found = 1
                if formatted_line.strip('\n') in dirs:
                    dirs.remove(formatted_line.strip('\n'))

                if not kibana_not_found and not kibana_skip:
                    stdin, stdout, stderr = ssh_connection.exec_command('sudo cp -f '+repo_dir+kibana_match+' /tmp',
                                                                        get_pty=True)
                    stdin.write(ssh_password+'\n')
                    stdin.flush()
                    time.sleep(1)
                    scp_connection = scp.SCPClient(ssh_connection.get_transport())
                    scp_connection.get('/tmp/'+kibana_match, '/tmp/')
                    time.sleep(1)
                    scp_connection.close()
                    local_ssh = paramiko.SSHClient()
                    local_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    local_ssh.connect('localhost', 22, ssh_username, ssh_password)
                    stdin, stdout, stderr = local_ssh.exec_command('sudo mv -f /tmp/kibana* /tmp/kibana.tar',
                                                                   get_pty=True)
                    stdin.write(ssh_password+'\n')
                    stdin.flush()
                    time.sleep(1)
                    local_ssh.close()
                    kibana_skip = True

                if not emerging_threats_not_found and not emerging_skip:
                    stdin, stdout, stderr = ssh_connection.exec_command('sudo cp -f '+repo_dir+emerging_match+' /tmp/',
                                                                        get_pty=True)
                    stdin.write(ssh_password+'\n')
                    stdin.flush()
                    # Give the os a chance to write file
                    time.sleep(1)
                    scp_connection = scp.SCPClient(ssh_connection.get_transport())
                    scp_connection.get('/tmp/'+emerging_match, '/tmp/')
                    time.sleep(1)
                    scp_connection.close()
                    local_ssh = paramiko.SSHClient()
                    local_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    local_ssh.connect('localhost', 22, ssh_username, ssh_password)
                    stdin, stdout, stderr = local_ssh.exec_command('sudo mv -f /tmp/emerging* /tmp/emerging.tar',
                                                                   get_pty=True)
                    stdin.write(ssh_password+'\n')
                    stdin.flush()
                    time.sleep(1)
                    local_ssh.close()
                    emerging_skip = True

            if len(dirs) != 0:
                print 'The following directories or files were not found on '+ip+' under the '+repo_dir
                for directory in dirs:
                    print '\t'+directory
                print '\n'
                conn_error = 1
            if kibana_not_found:
                print 'Kibana.tar was not found in the directory '+repo_dir
                conn_error = 1
            if emerging_threats_not_found:
                print 'emerging.rules.tar was not found in the directory '+repo_dir
                conn_error = 1
        ssh_connection.close()

    if len(conn_failers) != 0:
        print 'The following IP\'s were unreachable from this box!'
        for ip in conn_failers:
            print '\t'+ip
        print '\n'
        conn_error = 1

    if len(ssh_failers) != 0:
        print 'Failed to login via ssh on the following IP\'s!'
        for ip in ssh_failers:
            print '\t'+ip
        print '\n'
        conn_error = 1
    conn_error = 0
    if conn_error != 1:
        print 'Network connectivity test successful. Beginning configuration...\n'
        # set hostname on each box
        host_names = assign_hostnames(ip_list, ssh_username, ssh_password)
        # get user input for which boxes should have each software
        learn_software_locations(ip_list, repo_ip, repo_port, repo_dir, ssh_username, ssh_password, host_names)
    else:
        print 'Please correct the network issue and rerun this program!'
        exit('1')


def install_software(soft, ip_list):
    choices = []
    count = 1
    if len(ip_list) > 1:
        print 'Which boxes should have '+soft+' installed? (comma seperated number selection) EI 1,3,4'
        for ip in ip_list:
            print str(count)+'.) '+str(ip)+'\n'
            count += 1
        selection = raw_input()
        # ---------------------------- Should validate selection
        selection = selection.replace(' ', '').split(',')
        if 0 < len(selection) < count:
            for item in selection:
                choices.append(ip_list[int(item) - 1])
            return choices
        else:
            if len(selection) < 0:
                print 'You must select at least 1 HOST to install '+soft
            else:
                print 'Please make a valid selection'
            return install_software(soft, ip_list)
    else:
        print 'Only one choice available, installing '+soft+' on '+ip_list[0]+'...'
        return ip_list


def learn_software_locations(ip_list, repo_ip, repo_port, repo_dir, username, password, host_names):
    sensor_ips = install_software('Bro/Suricata', ip_list)
    data_store_ips = install_software('Kafka/Elasticsearch', ip_list)
    analysis_ips = install_software('Kibana', ip_list)
    configure_repo_satellite(repo_ip, username, password, repo_dir, repo_port)
    configure_local_repos(ip_list, repo_ip, repo_port, username, password)
    sensor_install(sensor_ips, username, password, data_store_ips, host_names)
    es_nodes = data_store_install(data_store_ips, username, password, analysis_ips)
    analysis_install(analysis_ips, es_nodes, username, password)


# allocate 60% of cpu's as workers or 4 what ever is higher.
def detect_physical_cpus(username, password, ip):
    print 'Detecting physical cpu cores on '+ip+'...'
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo grep -E \'processor|core id|flags\' /proc/cpuinfo',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    cpu_info = {}
    physical_cores = {}
    hyper_threading = 0
    temp_core_id = ''
    bro_manager_cpus = []
    bro_worker_cpus = []
    temp_processor = ''
    data = stdout.readlines()
    for line in data:
        line = line.replace('\t', '').replace('\n', '').replace('\r', '').split(':')
        if line[0] == 'processor':
            temp_processor = line[1]
        elif line[0] == 'core id':
            temp_core_id = line[1]
        elif line[0] == 'flags':
            for flag in line[1].split(' '):
                if 'ht' in flag:
                    hyper_threading = 1
            cpu_info[temp_processor] = temp_core_id
    # this needs some serious work.... :/
    if hyper_threading:
        for key, value in cpu_info.items():
            if value not in physical_cores.values():
                physical_cores[key] = value
    else:
        for key, value in cpu_info.items():
            physical_cores[key] = value

    if len(physical_cores) < 4:
        print 'the HOST '+ip+' does not have atleast 4 physical CPU\'s. Bro will default to standalone mode!'
        return 'standalone', 0, 0

    # local cluster
    else:
        bro_cores = len(physical_cores) * .6
        if bro_cores < 3:
            bro_cores = 2
            manager_cores = 1
        else:
            manager_cores = math.ceil(bro_cores / 50)
            bro_cores -= manager_cores
        for key, value in physical_cores.items():
            if bro_cores > 0:
                if manager_cores > 0:
                    bro_manager_cpus.append(key)
                    manager_cores -= 1
                else:
                    bro_worker_cpus.append(key)
                    bro_cores -= 1
        return bro_worker_cpus, bro_manager_cpus, hyper_threading,


# enable ip tables don't forget it
def ip_tables():
    pass


# ifup-local script don't forget it
def optimize_interfaces(ip, username, password):
    pass


def install_broctl(username, password, ip_list, kafka_ips, host_names):
    # determine cores
    # check for physical cores
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    local_file = open('/tmp/node.cfg', 'w')
    local_file.write('[manager]\n'
                     'type=manager\n')
    count = 1
    broctl_box = ''
    for ip in ip_list:
        capture_interfaces = raw_input('Enter comma seperated interfaces bro ' + ip + ' '
                                       'should listen on (ETH0, ETH1, ETH2, ECT...)\n')

        capture_interfaces = capture_interfaces.replace(' ', '').split(',')
        install_suricata(username, password, ip, capture_interfaces)
        install_netsniff(username, password, ip, capture_interfaces)
        bro_worker_cpus, bro_manager_cpus, hyper_threading = detect_physical_cpus(username, password, ip)
        if bro_worker_cpus == 'standalone':
            print 'Host ('+ip+') will not be added to the bro cluster due to insufficient resources'
        else:
            if broctl_box == '':
                broctl_box = ip
                ssh_connection.connect(broctl_box, 22, username, password)
                stdin, stdout, stderr = ssh_connection.exec_command('sudo /opt/bro/bin/broctl install', get_pty=True)
                stdin.write(password+'\n')
                stdin.flush()
                time.sleep(3)

            if ip == broctl_box:
                local_file.write('host='+ip+'\n'
                                 'pin_cpus='+''.join(bro_manager_cpus)+'\n\n'
                                 '[proxy]\ntype=proxy\nhost='+ip+'\n\n')
                local_file.write('[monitor '+str(count)+']\n'
                                 'type=worker\n'
                                 'host='+ip+'\n'
                                 'interface='+capture_interfaces[0]+' ')
                for interface in capture_interfaces[1:]:
                    local_file.write('-i '+interface+' ')
                local_file.write('\nlb_method=pf_ring\n'
                                 'lb_procs='+str(len(bro_worker_cpus))+'\n'
                                 'pin_cpus='+','.join(bro_worker_cpus))
            else:
                # write broctl file
                local_file.write('[monitor '+str(count)+'\n'
                                 'type=worker\n'
                                 'host='+ip+'\n'
                                 'interface='+capture_interfaces[0]+' ')
                for interface in capture_interfaces[1:]:
                    local_file.write('-i '+interface+' ')
                cpus_pinned = str(len(bro_worker_cpus)+len(bro_manager_cpus))
                local_file.write('\nlb_method=pf_ring\n'
                                 'lb_procs='+cpus_pinned+'\n'
                                 'pin_cpus='+','.join(bro_worker_cpus)+','+','.join(bro_manager_cpus))
                print 'Pinning '+cpus_pinned+' cpu\'s to worker '+ip+'...'

                # enable ssh for worker
                ssh_connection.exec_command('su -c ssh-keygen -t rsa - '+username, get_pty=True)
                time.sleep(1)
                ssh_connection.exec_command('su -c ssh-copy-id '+username+'@'+ip+' - '+username, get_pty=True)
                time.sleep(1)
        count += 1
    local_file.close()
    time.sleep(1)
    if broctl_box == '':
        print 'No suitable broctl box! Please install bro on a box with 4 or more physical cpu\'s!'
        local_cleanup()
        exit('1')

    # move node.cfg
    ssh_connection.connect(broctl_box, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())
    scp_connection.put('/tmp/node.cfg', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/node.cfg /opt/bro/etc/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    print 'Creating bro scripts in /opt/bro/share/bro/site/scripts...'

    # move unified2-logs
    local_file = open('/tmp/unified2-logs.bro', 'w')
    local_file.write('#/opt/bro/share/bro/site/scripts/unified2-logs.bro\n\n'
                     '@load base/files/unified2\n'
                     'redef Unified2::classification_config = "/etc/suricata/classification.config";\n'
                     'redef Unified2::gen_msg = "/etc/suricata/rules/gen-msg.map";\n'
                     'redef Unified2::sid_msg = "/etc/suricata/rules/sid-msg.map";\n'
                     'redef Unified2::watch_dir = "/data/suricata/logs";')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/unified2-logs.bro', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/unified2-logs.bro '
                                                        '/opt/bro/share/bro/site/scripts/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'unified2-logs.bro created...'

    # move json-logs
    local_file = open('/tmp/json-logs.bro', 'w')
    local_file.write('#/opt/bro/share/bro/site/scripts/json-logs.bro\n\n'
                     'redef LogAscii::json_timestamps = JSON::TS_ISO8601;\n'
                     'redefLogAscii::use_json=T;\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/json-logs.bro', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/json-logs.bro '
                                                        '/opt/bro/share/bro/site/scripts/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    print 'json-logs.bro created...'
    time.sleep(1)
    local_file.close()

    # move kafka-logs
    local_file = open('/tmp/kafka-logs.bro', 'w')
    time.sleep(1)
    local_file.write('#/opt/bro/share/bro/site/scripts/kafka-logs.bro\n\n'
                     '@load Kafka/KafkaWriter/logs-to-kafka\n'
                     'redef KafkaLogger::topic_name = "bro_raw";'
                     'redef KafkaLogger::broker_name = "')
    kafka_ips_and_ports = ''
    for kafka_ip in kafka_ips:
        kafka_ips_and_ports += kafka_ip+':9092, '
    # chomp off the space and extra comma
    kafka_ips_and_ports = kafka_ips_and_ports[:-2]
    local_file.write(kafka_ips_and_ports+'";\n'
                                         'redef KafkaLogger::sensor_name = "'+host_names[broctl_box]+'";')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/kafka-logs.bro', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/kafka-logs.bro '
                                                        '/opt/bro/share/bro/site/scripts/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'kafka-logs.bro created...'

    # move broctl.cfg
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /opt/bro/etc/broctl.cfg /tmp ', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    scp_connection.get('/tmp/broctl.cfg', '/tmp/')
    mem_file = []
    local_file = open('/tmp/broctl.cfg', 'r')
    for line in local_file:
        mem_file.append(line)
    local_file.close()
    time.sleep(1)
    local_file = open('/tmp/broctl.cfg', 'w')
    for line in mem_file:
        if 'LogDir' in line:
            local_file.write('LogDir = /data/bro/logs')
        else:
            local_file.write(line)
    local_file.close()
    time.sleep(1)
    print '/opt/bro/etc/broctl.cfg created...'

    # move local.bro
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /opt/bro/share/bro/site/local.bro /tmp/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    scp_connection.get('/tmp/local.bro', '/tmp/')
    local_file = open('/tmp/local.bro', 'a')
    local_file.write('#enable JSON logging format\n'
                     '@load scripts/json-logs\n'
                     '#enable kafka plugin output\n'
                     '@load scripts kafka-logs\n'
                     'enable Unified2 ingest\n'
                     '@load scripts/unified2-logs')
    local_file.close()
    time.sleep(1)
    print '/opt/bro/share/bro/site/local.bro updated...'

    # enable broctl on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo ln -s /opt/bro/bin/broctl /etc/init.d/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    print 'linking /opt/bro/bin/broctl to /etc/init.d/'
    time.sleep(1)

    # deploy broctl
    stdin, stdout, stderr = ssh_connection.exec_command('sudo service broctl deploy', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    print 'Deploying broctl...'
    time.sleep(1)
    scp_connection.close()
    ssh_connection.close()


def install_suricata(username, password, ip, interfaces):
    print 'Configuring suricata on '+ip+'...'
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())

    # create suricata options file
    local_file = open('/tmp/suricata', 'w')
    local_file.write('OPTIONS="')
    for interface in interfaces:
        local_file.write(' -i '+interface+'')
    local_file.write('"')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/suricata', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/suricata /etc/sysconfig/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    print 'Suricata options file created /ect/sysconfig/suricata'
    time.sleep(1)

    # create suricata load-rules script
    local_file = open('/tmp/load-rules', 'w')
    local_file.write('#!/bin/bash\n\n'
                     'sudo rm -f /etc/suricata/temp.rules\n'
                     'sudo touch /etc/suricata/temp.rules\n'
                     'for item in /etc/suricata/rules/*.rules; do echo " - $(basename $item)" >> '
                     '/etc/suricata/temp.rules; done\n'
                     'sudo cat /etc/suricata/suricata.yaml > /etc/suricata/suricata.yaml.back\n'
                     'sudo cat /etc/suricata/suricata.yaml | grep \'\\.rules\' -v | sed \'/rule-files:/ r '
                     '/etc/suricata/temp.rules\' > /etc/suricata/temp.yaml\n'
                     'sudo cat /etc/suricata/temp.yaml > /etc/suricata/suricata.yaml\n'
                     'rm -f temp.rules\n'
                     'rm -f temp.yaml\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/load-rules', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/load-rules /etc/suricata/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    print '/etc/suricata/load-rules creating script to load new rules...'
    # modify load rules script
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chmod 755 /etc/suricata/load-rules', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    # allow premission to take file
    stdin, stdout, stderr = ssh_connection.exec_command('sudo cp -f /etc/suricata/suricata.yaml /tmp/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    # create suricata.yaml
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chmod 777 /tmp/suricata.yaml', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)


    # Give os time to write file
    scp_connection.get('/tmp/suricata.yaml', '/tmp/')
    mem_file = []
    local_file = open('/tmp/suricata.yaml', 'r')
    for line in local_file:
        mem_file.append(line)
    local_file.close()
    time.sleep(1)
    local_file = open('/tmp/suricata.yaml', 'w')
    skip = False
    for line in mem_file:
        if skip:
            skip = False
            continue
        if 'default-log-dir' in line:
            local_file.write('default-log-dir: /data/suricata/logs\n')
        elif 'fast:' in line \
                or 'eve-log:' in line \
                or 'http-log:' in line \
                or 'tls-log:' in line \
                or 'dns-log:' in line \
                or 'pcap-log:' in line \
                or 'alert-debug:' in line \
                or 'alert-prelude:' in line \
                or 'stats:' in line \
                or 'syslog:' in line \
                or 'drop:' in line:

            local_file.write(line)
            skip = True
            local_file.write('enabled: no\n')
        elif 'unified2-alert:' in line:
            local_file.write(line)
            skip = True
            local_file.write('enabled: yes')
        else:
            local_file.write(line)
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/suricata.yaml', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chmod 644 /tmp/suricata.yaml ', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/suricata.yaml /etc/suricata/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/etc/suricata/suricata.yaml configured...'

    # suricata on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig suricata on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Enabling Suricata on Boot'

    # suricata emerging-rules.tar unpack
    scp_connection.put('/tmp/emerging.tar', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo tar -zxf emerging.tar', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Unpacking emerging threats rules...'
    stdin, stdout, stderr = ssh_connection.exec_command('sudo rm -f emerging.tar', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo rm -rf /etc/suricata/rules', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/etc/suricata/rules removing old rules...'
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/rules /etc/suricata/rules', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/etc/suricata/rules adding new rules...'

    # run load-rules script
    stdin, stdout, stderr = ssh_connection.exec_command('sudo /etc/suricata/load-rules', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/etc/suricata/load-rules running load-rules script...'

    # Suricata on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig suricata on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    # close connections
    scp_connection.close()
    ssh_connection.close()


def install_netsniff(username, password, ip, interfaces):
    print 'configuring netsniff-ng...'
    print 'CAUTION: This tool will be replaced by stenographer and is currently a place holder.\n' \
          'This tool may not work if you have multipe capture interfaces.\n If there appears to be problems ' \
          'verify the /etc/sysconfig/netsniff-ng config file'
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())

    # create netsniff options file
    local_file = open('/tmp/netsniff-ng', 'w')
    local_file.write('PROM_INTERFACE=')
    for interface in interfaces:
        local_file.write('-i '+interface)
    local_file.write('\nUSER=99\n'
                     'GROUP=99\n'
                     'INTERVAL=1GiB\n'
                     'DATA_DIR=/data/netsniff-ng/pcap\n')
    local_file.close()
    time.sleep(2)
    scp_connection.put('/tmp/netsniff-ng', '/tmp/')
    time.sleep(2)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/netsniff-ng /etc/sysconfig/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(2)
    print '/etc/suricata/netsniff-ng config file created...'

    # create netsniff-ng service file
    local_file = open('/tmp/netsniff-ng.service', 'w')
    local_file.write('[Unit]\n'
                     'Description=PCAP Collection Beast\n'
                     'After=network.target\n'
                     '[Service]\n'
                     'EnvironmentFile=-/etc/sysconfig/netsniff-ng\n'
                     'ExecStart=/sbin/netsniff-ng --in ${PROM_INTERFACE} --out ${DATA_DIR} --silent --user ${USER} '
                     '--group ${GROUP} --interval ${INTERVAL}\n'
                     'Type=simple\n'
                     '[Install]\n'
                     'WantedBy=multi-user.target\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/netsniff-ng.service', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/netsniff-ng.service /etc/systemd/system/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'netsniff-ng service file created...'

    # netsniff-ng on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig netsniff-ng on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    # close connections
    scp_connection.close()
    ssh_connection.close()


def sensor_install(ip_list, username, password, kafka_ips, host_names):
    # install bro, broctl, pfring, pfring-dkms, dkms
    print 'Installing sensor software...'
    for ip in ip_list:
        ssh_connection = paramiko.SSHClient()
        ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connection.connect(ip, 22, username, password)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo yum -y install suricata bro broctl pfring dkms '
                                                            'pfring-dkms libpcap-pfring netsniff-ng '
                                                            'bro-plugin-kafka-output critical-stack-smb-bro-plugin',
                                                            get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        print 'installing pfring...'
        time.sleep(5)
        print 'installing dkms...'
        time.sleep(5)
        print 'installing bro...'
        time.sleep(5)
        print 'installing broctl...'
        time.sleep(5)
        print 'installing pfring...'
        time.sleep(5)
        print 'installing pfring-dkms...'
        time.sleep(5)
        print 'installing libpcap-pfring...'
        time.sleep(5)
        print 'installing netsniff-ng...'
        time.sleep(5)
        print 'installing suricata...'
        time.sleep(5)
        # prep directories
        prep_dirs('sensor', username, password, ip)
    install_broctl(username, password, ip_list, kafka_ips, host_names)


def data_store_install(data_store_ip_list, username, password, analysis_ip_list):
    print 'Installing data store software...'
    es_nodes = {}
    num_md_nodes = 0
    kafka_servers = {}
    replicas = 1
    kafka_replicas = 1
    # determine number of masters
    if len(data_store_ip_list) > 1:
        kafka_partitions = num_md_nodes = math.ceil(len(data_store_ip_list)*.4)
        shards = math.ceil(len(data_store_ip_list)/2)
        count = 0
        for ip in data_store_ip_list:
            if count < num_md_nodes or num_md_nodes < 2:
                es_nodes[ip] = 'MD'
                count += 1
            else:
                es_nodes[ip] = 'D'
    # this case means that only one ES box, and one Search Box Total of 2.
    else:
        shards = 1
        kafka_partitions = 1
        kafka_replicas = 0
        replicas = 0
        es_nodes[data_store_ip_list[0]] = 'MD'
    count = 0
    for ip in data_store_ip_list:
        install_elasticsearch(es_nodes, ip, username, password, shards, replicas)
        if es_nodes[ip] == 'MD':
            count += 1
            kafka_servers[ip] = str(count)
    for ip in analysis_ip_list:
        es_nodes[ip] = 'S'
    for ip, num in kafka_servers.items():
        install_kafka(ip, username, password, str(kafka_partitions), str(kafka_replicas), kafka_servers)
        install_logstash(ip, username, password)
    return es_nodes


def install_logstash(ip, username, password):
    print 'installing logstash on '+ip+'...'
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())
    stdin, stdout, stderr = ssh_connection.exec_command('yum install -y logstash', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    local_file = open('/tmp/kafka-es.conf', 'w')
    local_file.write('input {\n'
                     '\tkafka {\n'
                     '\t\ttopic_id => "bro_raw"\n'
                     '\t\tadd_field => { "[@metadata][stage]" => "bro_kafka" }\n'
                     '\t}\n'
                     '}\n\n'
                     'output {\n'
                     '\tif [@metadata][stage] == "bro_kafka" {\n'
                     '\t\t#stdout { codec => rubydebug }\n'
                     '\t\telasticsearch {\n'
                     '\t\t\thosts => ["'+ip+'"]\n'
                     '\t\t\tdocument_type => "%{sensor_logtype}"\n'
                     '\t\t\n}'
                     '\t}\n'
                     '}\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/kafka-es.conf', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/kafka-es.conf /etc/logstash/conf.d/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig logstash on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    scp_connection.close()
    ssh_connection.close()


def install_elasticsearch(es_nodes, ip, username, password, shards, replicas):
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())
    stdin, stdout, stderr = ssh_connection.exec_command('sudo yum -y install elasticsearch '
                                                        'java-1.8.0-oracle-headless', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Installing elasticsearch on '+ip+'...'
    formated_master_list = '['
    for temp_ip, es_type in es_nodes.items():
        formated_master_list += temp_ip + ', '
    # remove space and comma
    formated_master_list = formated_master_list[:-2]+']'

    # create elasticsearch.yml
    local_file = open('/tmp/elasticsearch.yml', 'w')
    local_file.write('node.name: ES-'+es_nodes[ip]+'-NODE-'+ip+'\n'
                     'clustername: sensor\n')
    if shards != 0:
        local_file.write('index.number_of_shards: '+str(shards)+'\n')
    if replicas != 0:
        local_file.write('index.number_of_replicas: '+str(replicas)+'\n')
    if shards != 0 and replicas != 0:
        local_file.write('path.data: /data/elasticsearch/data\n'
                         'path.logs: /data/elasticsearch/logs\n'
                         'path.work: /data/elasticsearch/work\n')
    local_file.write('discovery.zen.ping.unicast.hosts: '+formated_master_list)
    if 'M' in es_nodes[ip]:
        local_file.write('node.master: true\n')
    else:
        local_file.write('node.master: false\n')
    if 'D' in es_nodes[ip]:
        local_file.write('node.data: true\n')
    else:
        local_file.write('node.data: false\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/elasticsearch.yml', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderrr = ssh_connection.exec_command('sudo mv -f /tmp/elasticsearch.yml /etc/elasticsearch/',
                                                         get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Elasticsearch.yml configured on '+ip+'...'

    stdin, stdout, stderr = ssh_connection.exec_command('sudo cp -f /etc/sysconfig/elasticsearch /tmp/ ', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chmod 777 /tmp/elasticsearch', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    scp_connection.get('/tmp/elasticsearch', '/tmp/')
    stdin, stdout, stderr = ssh_connection.exec_command('sudo cat /proc/meminfo | grep MemTotal', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    mem_total = float(stdout.read().split()[-2])
    # convert mem_total into GiB
    mem_total = mem_total / float(1024) / float(1024)
    es_heap_size = int(math.ceil(mem_total) / 2)
    if es_heap_size > 32:
        es_heap_size = 32
    elif es_heap_size < 1:
        es_heap_size = 1
    mem_file = []
    local_file = open('/tmp/elasticsearch', 'r')
    for line in local_file:
        mem_file.append(line)
    local_file.close()
    time.sleep(1)
    local_file = open('/tmp/elasticsearch', 'w')
    for line in mem_file:
        if 'ES_HEAP_SIZE' in line:
            local_file.write('ES_HEAP_SIZE='+str(es_heap_size)+'g\n')
        else:
            local_file.write(line)
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/elasticsearch', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chmod 644 /tmp/elasticsearch', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Configuring elasticsearch heap to '+str(es_heap_size)+'...'
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/elasticsearch /etc/sysconfig/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    # elasticsearch on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig elasticsearch on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    scp_connection.close()
    ssh_connection.close()


def install_kafka(ip, username, password, partions, replicas, servers):
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())
    stdin, stdout, stderr = ssh_connection.exec_command('sudo yum install -y kafka', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Kafka installed on '+ip+'...'

    # Create zookeeper user
    stdin, stdout, stderr = ssh_connection.exec_command('sudo useradd --system -s /bin/false -b /opt/kafka/ '
                                                        '--no-create-home zookeeper', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'User zookeeper created...'

    # Create kafka user
    stdin, stdout, stderr = ssh_connection.exec_command('sudo useradd --system -s /bin/false -b /opt/kafka/ '
                                                        '--no-create-home kafka', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'User kafka created...'

    formatted_zk_connect = ''
    formatted_broker_list = ''
    for ip, num in servers.items():
        formatted_broker_list += num+':'+ip+':9092, '
    formatted_broker_list = formatted_broker_list[:-2]
    for ip in servers:
        formatted_zk_connect += ip+':2182, '
    formatted_zk_connect = formatted_zk_connect[:-2]

    # consumer.properties are the same on each box
    local_file = open('/tmp/consumer.properties', 'w')
    local_file.write('zookeeper.connect="'+formatted_zk_connect+'"\n'
                     'zookeeper.connection.timeout.ms=6000\n'
                     'group.id=test-consumer-group\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/consumer.properties', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/consumer.properties /opt/kafka/config/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/opt/kafka/config/consumer.properties configured...'

    # zookeeper.properties are the same on each box
    local_file = open('/tmp/zookeeper.properties', 'w')
    local_file.write('metadata.broker.list='+formatted_broker_list+'\n'
                     'producer.type=sync\n'
                     'compression.codec=none'
                     'serializer.class=kafka.serializer.DefaultEncoder\n'
                     'zookeeper.connect="'+formatted_zk_connect+'"')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/zookeeper.properties', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/zookeeper.properties /opt/kafka/config/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/opt/kafka/config/zookeeper.properties configured...'

    # producer.properties are the same on each box
    local_file = open('/tmp/producer.properties', 'w')
    local_file.write('dataDir=/data/zookeeper\n'
                     'clientPort=2181\n'
                     'maxClientCnxns=0\n'
                     'tickTime=2000\n'
                     'initLimit=5\n'
                     'syncLimit=2\n')
    for ip, num in servers.items():
        local_file.write('server.'+num+'='+ip+':2182:2183\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/producer.properties', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/producer.properties /opt/kafka/config/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/opt/kafka/config/producer.properties configured...'

    # server.properties is different on each box
    local_file = open('/tmp/server.properties', 'w')
    local_file.write('broker.id='+servers[ip]+'\n'
                     'port=9092\n'
                     'advertised.host.name=172.16.0.125\n'
                     'num.network.threads=3\n'
                     'num.io.threads=8\n'
                     'socket.send.buffer.bytes=102400\n'
                     'socket.receive.buffer.bytes=102400\n'
                     'socket.request.max.bytes=104857600\n'
                     'log.dirs=/data/kafka/logs\n'
                     'num.partitions=1\n'
                     'num.recovery.threads.per.data.dir=1\n'
                     'log.retention.hours=12\n'
                     'log.segment.bytes=1073741824\n'
                     'log.retention.check.interval.ms=300000\n'
                     'log.cleaner.enable=false\n'
                     'zookeeper.connection.timeout.ms=6000\n'
                     'enable.zookeeper=true\n'
                     'delete.topic.enable=true\n'
                     'zookeeper.connect="'+formatted_zk_connect+'"')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/server.properties', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/server.properties /opt/kafka/config/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/opt/kafka/config/server.properties configured...'

    # my.id file needs to exist inside zookeeper.properties option of dataDir
    local_file = open('/tmp/my.id', 'w')
    local_file.write(servers[ip])
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/my.id', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/my.id /data/zookeeper', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print '/data/zookeeper/my.id configured...'

    # Create bro_raw topic
    stdin, stdout, stderr = ssh_connection.exec_command('sudo /opt/kafka/bin/kafka-topics.sh --create --zookeeper '
                                                        'localhost:2181 --replication-factor '+replicas+' '
                                                        '--partitions '+partions+' --topic bro_raw', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Kafka Topic "bro_raw" created...'

    # Enabled zookeeper on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig zookeeper on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Zookeeper enabled on boot...'

    # enable kafka on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig kafka on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Kafka enabled on boot...'

    scp_connection.close()
    ssh_connection.close()


def analysis_install(ip_list, es_nodes, username, password):
    print 'Installing analysis software...'
    for ip in ip_list:
        install_elasticsearch(es_nodes, ip, username, password, 0, 0)
        install_nginx(ip, username, password)
        install_kibana(ip, username, password)


def install_kibana(ip, username, password):
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())

    # unpack kibana
    scp_connection.put('/tmp/kibana.tar', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo tar -zxf /tmp/kibana.tar', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo rm -f /tmp/kibana.tar', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv /tmp/kibana* /opt/kibana/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    local_file = open('/tmp/kibana.service', 'w')
    local_file.write('[Service]\n'
                     'ExacStart=/opt/kibana/bin/kibana\n'
                     'Restart=always\n'
                     'StandardOutput=syslog\n'
                     'StandardError=syslog\n'
                     'SyslogIdentifier=kibana\n'
                     'User=root\n'
                     'Group=root\n'
                     'Environment=NODE_ENV=production\n'
                     '[Install]\n'
                     'WantedBy=multi-user.target')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/kibana.service', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv /tmp/kibana.service /etc/systemd/system/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'kibana service file created...'

    # configure nginx to proxy for kibana
    local_file = open('/tmp/kibana.conf', 'w')
    local_file.write('server {\n'
                     '\tlisten 80;\n'
                     '\tserver_name kibana;\n'
                     '\tauth_gss off;\n'
                     '\tauth_gss_keytab /etc/nginx/ipa.keytab;\n\n'
                     '\tlocation / {\n'
                     '\t\tproxy_pass http://localhost:5601;\n'
                     '\t\tproxy_http_version 1.1;\n'
                     '\t\tproxy_set_header upgrade $http_upgrade;\n'
                     '\t\tproxy_set_header connection \'upgrade\';\n'
                     '\t\tproxy_set_header host $host;\n'
                     '\t\tproxy_cache_bypass $http_upgrade;\n'
                     '\t}\n'
                     '\t}\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/kibana.conf', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chcon -R -u system_u -t httpd_config_t /tmp/kibana.conf', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv /tmp/kibana.conf /etc/nginx/conf.d/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    # kibana, nginx, elasticsearch on boot
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig elasticsearch on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig kibana on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chkconfig nginx on', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    scp_connection.close()
    ssh_connection.close()


def assign_hostnames(ip_list, username, password):
    host_names = {}
    for ip in ip_list:
        if ip != 'localhost':
            host_name = raw_input('Please enter a unique hostname for the box with IP of '+str(ip)+'\n')
            # ssh command needed to change host name.
            # hostnamectl set-hostname '<name>'
            host_file = open('/tmp/hosts', 'w')
            host_file.writelines('127.0.0.1\tlocalhost\n'+ip+'\t'+host_name+'\n')
            host_file.close()
            ssh_connection = paramiko.SSHClient()
            ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_connection.connect(ip, 22, username, password)
            scp_connection = scp.SCPClient(ssh_connection.get_transport())
            scp_connection.put('/tmp/hosts', '/tmp/')
            time.sleep(1)
            stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/hosts /etc/', get_pty=True)
            stdin.write(password+'\n')
            stdin.flush()
            time.sleep(1)
            stdin, stdout, stderr = ssh_connection.exec_command('sudo hostnamectl set-hostname '+host_name ,get_pty=True)
            stdin.write(password+'\n')
            stdin.flush()
            time.sleep(1)
            scp_connection.close()
            ssh_connection.close()
            host_names[ip] = host_name
    return host_names


def obtain_ip_list():
    ip_list = raw_input('Please provide comma separated HOSTS for each box you are setting up today. '
                        '(localhost included by default)\n').replace(' ', '').split(',')
    # remove any empty strings
    for item in ip_list:
        if item == '':
            ip_list.remove(item)
    # add localhost by default
    ip_list.append('localhost')
    return ip_list


def obtain_repo_box():
    repo_box = raw_input('Please provide the HOST:PORT:PATH of the repo satellite. '
                         '(127.0.0.1:8008:/repo)\n').replace(' ', '').split(':')
    if len(repo_box) == 3:
        if repo_box[0] == '':
            repo_box[0] = 'localhost'
        if repo_box[1] == '':
            repo_box[1] = '8008'
        if repo_box[2] == '':
            repo_box[2] = '/repo/'
        if repo_box[2][-1] != '/':
            repo_box[2] += '/'
        return repo_box
    else:
        print 'The provided HOST and PORT was formatted incorrectly!'
        return obtain_repo_box()


def obtain_ssh_user():
    username = raw_input('Enter ssh username (Must have SUDO ability)\n')
    password = getpass.getpass('Enter ssh password')
    if username == '':
        username = 'xadmin'
    if password == '':
        password = 'CYBERadmin1234!@#$'
    return [username, password]


def configure_repo_satellite(ip, username, password, repo_dir, repo_port):
    print 'Creating yum repo configuration file...'
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    scp_connection = scp.SCPClient(ssh_connection.get_transport())
    local_file = open('/tmp/cpt.repo', 'w')
    local_file.write('[rhel-7-server-rpms-local]\n'
                     'name=rhel-7-server-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'rhel-7-server-rpms\n'
                     '\n'
                     '[rhel-7-server-beta-rpms-local]\n'
                     'name=rhel-7-server-beta-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'rhel-7-server-beta-rpms\n'
                     '\n'
                     '[rhel-7-server-optional-rpms-local]\n'
                     'name=rhel-7-server-optional-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'rhel-7-server-optional-rpms\n'
                     '\n'
                     '[rhel-7-server-thirdparty-oracle-java-rpms-local]\n'
                     'name=rhel-7-server-thirdparty-oracle-java-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'rhel-7-server-thirdparty-oracle-java-rpms\n'
                     '\n'
                     '[criticalstack-smb-local]\n'
                     'name=criticalstack-smb-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'criticalstack-smb\n'
                     '\n'
                     '[criticalstack-oracle-local]\n'
                     'name=criticalstack-oracle-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'criticalstack-oracle\n'
                     '\n'
                     '[dcode-cyberdev-local]\n'
                     'name=dcode-cyberdev-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'dcode-cyberdev\n'
                     '\n'
                     '[cyberdev-capes-local]\n'
                     'name=cyberdev-capes-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=file://'+repo_dir+'cyberdev-capes\n'
                     '\n')
    local_file.close()
    time.sleep(1)
    scp_connection.put('/tmp/cpt.repo', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/cpt.repo /etc/yum.repos.d/',
                                                        get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Satellite configuration file created in /tmp/cpt.repo'

    # install nginx to host repos
    install_nginx(ip, username, password)

    print 'Creating the nginx config to host the repo...'
    # create the repo config file
    formatted_repo_dir = repo_dir[:-1]
    local_file = open('/tmp/repo.conf', 'w')
    local_file.write('server {\n'
                     '\tlisten '+repo_port+';\n'
                     '\tserver_name repo;\n'
                     '\tlocation / {\n'
                     '\t\troot '+formatted_repo_dir+';\n'
                     '\t\tautoindex on;\n'
                     '\t\tindex index.html index.htm;\n'
                     '\t\n}'
                     '\n'
                     '\terror_page 500 502 503 504 /50x.html;\n'
                     '\tlocation = /50x.html {\n'
                     '\t\troot /usr/share/nginx/html;\n'
                     '\t}\n'
                     '}\n')
    local_file.close()
    scp_connection.put('/tmp/repo.conf', '/tmp/')
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo chcon -R -u system_u -t httpd_config_t /tmp/repo.conf', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/repo.conf /etc/nginx/conf.d/', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)
    print 'Configuration file is located at /etc/nginx/conf.d/repo.conf'
    print 'Starting the nginx service...'
    stdin, stdout, stderr = ssh_connection.exec_command('sudo service nginx restart', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)

    scp_connection.close()
    ssh_connection.close()


def local_cleanup():
    # cleanup all files on the local box listed below
    print 'Cleaning up /tmp on localhost...'
    os.remove('/tmp/cpt.repo')
    os.remove('/tmp/repo.conf')
    os.remove('/tmp/node.cfg')
    os.remove('/tmp/broctl.cfg')
    os.remove('/tmp/unified2-logs.bro')
    os.remove('/tmp/json-logs.bro')
    os.remove('/tmp/kafka-logs.bro')
    os.remove('/tmp/hosts')
    os.remove('/tmp/local.bro')
    os.remove('/tmp/suricata')
    os.remove('/tmp/load-rules')
    os.remove('/tmp/suricata.yaml')
    os.remove('/tmp/netsniff-ng')
    os.remove('/tmp/netsniff-ng.service')
    os.remove('/tmp/emerging.tar')
    os.remove('/tmp/kibana.tar')
    os.remove('/tmp/elasticsearch.yml')
    os.remove('/tmp/elasticsearch')
    os.remove('/tmp/kafka-es.conf')
    os.remove('/tmp/kibana.conf')
    os.remove('/tmp/server.properties')
    os.remove('/tmp/zookeeper.properties')
    os.remove('/tmp/producer.properties')
    os.remove('/tmp/consumer.properties')
    os.remove('/tmp/my.id')

    print 'Cleanup Complete. Exiting...'


def prep_dirs(box_type, username, password, ip):
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)

    if 'sensor' in box_type:
        stdin, stdout, stderr = ssh_connection.exec_command('sudo mkdir -p /data/bro/logs', get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo mkdir -p /data/suricata/logs', get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo mkdir -p /data/netsniff-ng/pcap', get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo chown -R nobody:nobody /data/netsniff-ng/pcap',
                                                            get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo mkdir -p /opt/bro/share/bro/site/scripts',
                                                            get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)

    if 'data box' in box_type:
        stdin, stdout, stderr = ssh_connection.exec_command('sudo mkdir -p /data/elasticsearch', get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo chown -R elasticsearch:elasticsearch '
                                                            '/data/elasticsearch', get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo mkdir -p /data/kafka/logs', get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
        stdin, stdout, stderr = ssh_connection.exec_command('sudo mkdir -p /data/zookeeper', get_pty=True)
        stdin.write(password+'\n')
        stdin.flush()
        time.sleep(1)
    ssh_connection.close()


def configure_local_repos(ip_list, repo_ip, repo_port, username, password):
    print 'Configuring remote HOST\'s yum repo configurations...'
    local_file = open('/tmp/cpt.repo', 'w')
    local_file.write('[rhel-7-server-rpms-local]\n'
                     'name=rhel-7-server-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/rhel-7-server-rpms\n'
                     '\n'
                     '[rhel-7-server-beta-rpms-local]\n'
                     'name=rhel-7-server-beta-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/rhel-7-server-beta-rpms\n'
                     '\n'
                     '[rhel-7-server-optional-rpms-local]\n'
                     'name=rhel-7-server-optional-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/rhel-7-server-optional-rpms\n'
                     '\n'
                     '[rhel-7-server-thirdparty-oracle-java-rpms-local]\n'
                     'name=rhel-7-server-thirdparty-oracle-java-rpms-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/rhel-7-server-thirdparty-oracle-java-rpms\n'
                     '\n'
                     '[criticalstack-smb-local]\n'
                     'name=criticalstack-smb-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/criticalstack-smb\n'
                     '\n'
                     '[criticalstack-oracle-local]\n'
                     'name=criticalstack-oracle-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/criticalstack-oracle\n'
                     '\n'
                     '[dcode-cyberdev-local]\n'
                     'name=dcode-cyberdev-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/dcode-cyberdev\n'
                     '\n'
                     '[cyberdev-capes-local]\n'
                     'name=cyberdev-capes-local\n'
                     'enabled=1\n'
                     'gpgcheck=0\n'
                     'baseurl=http://'+repo_ip+':'+repo_port+'/cyberdev-capes\n'
                     '\n')
    local_file.close()
    time.sleep(1)
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    local_path = '/tmp/cpt.repo'
    remote_path = '/etc/yum.repos.d/'
    for ip in ip_list:
        if ip != repo_ip:
            ssh_connection.connect(ip, 22, username, password)
            scp_connection = scp.SCPClient(ssh_connection.get_transport())
            scp_connection.put(local_path, '/tmp/')
            time.sleep(1)
            stdin, stdout, stderr = ssh_connection.exec_command('sudo mv -f /tmp/cpt.repo /etc/yum.repos.d/',
                                                                get_pty=True)
            stdin.write(password+'\n')
            stdin.flush()
            time.sleep(1)
            print stderr.read()
            scp_connection.close()
            ssh_connection.close()
            print 'yum configuration file added to '+ip+' in '+remote_path+'cpt.repo'


def install_nginx(ip, username, password):
    print 'Installing nginx (yum -y install nginx-spengo) on '+ip+'...'
    ssh_connection = paramiko.SSHClient()
    ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_connection.connect(ip, 22, username, password)
    stdin, stdout, stderr = ssh_connection.exec_command('sudo yum -y install nginx-spnego', get_pty=True)
    stdin.write(password+'\n')
    stdin.flush()
    time.sleep(1)


connection_test(obtain_ip_list(), obtain_repo_box(), obtain_ssh_user())
local_cleanup()
