#!/usr/bin/python3

# KAIST CS341 SDN Lab Test script

import time
import argparse
import sys
import random

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

from task_topology import Topology
from graph import gen_graph
from dump import dump_clear, dump_net

if __name__ == '__main__':
    # Uncomment below to see verbose log
    #setLogLevel('debug')
    
    parser = argparse.ArgumentParser(prog='CS341 SDN Lab Tester')
    parser.add_argument('--task', metavar='T', type=int, nargs='?', default=1,
                        help='task to test', required=True, choices=range(1,6))
    args = parser.parse_args()
    
    switches, hosts, links = gen_graph(args.task)
    if args.task == 1:
        t = Topology(switches, hosts, links)
        net = Mininet(topo=t)
    elif args.task in range(2, 6):
        t = Topology(switches, hosts, links)
        net = Mininet(topo=t, controller=RemoteController, listenPort=6633)
        dump_net(net, links)
    else:
        raise NotImplementedError('Supported Task number: 1-5')
    
    net.start()
    net.waitConnected()
    if args.task == 4 or args.task == 5:
        # Launch DNS and HTTP server, then run client
        time.sleep(1)
        dangeroushost, safehost, dnshost, normalhost = random.sample(net.hosts, 4)
        # In order to write output to console: append argument (stdout=sys.stdout, stderr=sys.stderr)
        # popen('./server.py', shell=True, stdout=sys.stdout, stderr=sys.stderr)
        dangerousp = dangeroushost.popen('./server.py', shell=True)
        print('running cs341dangerous.com on {}({})'.format(dangeroushost.name, dangeroushost.IP()))
        safep = safehost.popen('./server.py', shell=True)
        print('running cs341safe.com on {}({})'.format(safehost.name, safehost.IP()))
        dnsp = dnshost.popen('./dns -a cs341dangerous.com={} -a cs341safe.com={}'.format(
            dangeroushost.IP(), safehost.IP()
        ), shell=True)
        print('running DNS on {}({})'.format(dnshost.name, dnshost.IP()))
        print('You can test via following commands:')
        print('{} dig @{} cs341safe.com'.format(normalhost.name, dnshost.IP()))
        print('{} dig @{} cs341dangerous.com'.format(normalhost.name, dnshost.IP()))
        print('{} curl -H "Host: cs341safe.com" -m 10 http://{}/'.format(normalhost.name, safehost.IP()))
        print('{} curl -H "Host: cs341dangerous.com" -m 10 http://{}/'.format(normalhost.name, dangeroushost.IP()))
        CLI(net)
        dangerousp.kill()
        safep.kill()
        dnsp.kill()
    else:
        CLI(net)
    net.stop()