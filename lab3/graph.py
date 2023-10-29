#!/usr/bin/python3

import random

def gen_graph(task=1):

    switch = 0
    host = 0
    switches = []
    hosts = []
    links = []

    switchneighbors = {s:set() for s in switches}

    if task in range(1,4): # For task 1, 2, 3
        # increase number of switches and hosts to make more complex and bigger network
        switch=5
        host=3
        
        switches = ['s{}'.format(i) for i in range(1, 1+switch)]
        hosts = ['h{}'.format(i) for i in range(1, 1+host)]
        switchneighbors = {s:set() for s in switches}
        
        # generate random tree topology
        # First, connect switches in random order
        switchorder = list(switches)
        random.shuffle(switchorder)
        for i in range(1, switch):
            # attach swith to one among existing switches
            node1 = random.choice(switchorder[:i])
            node2 = switchorder[i]
            links.append((
                node1,
                node2,
                random.randint(1 << 15, 1 << 30)
            ))
            switchneighbors[node1].add(node2)
            switchneighbors[node2].add(node1)
        # Next, connect hosts to switches
        for host in hosts:
            node1 = host
            node2 = random.choice(switches)
            links.append((
                node1,
                node2,
                random.randint(1 << 15, 1 << 30)
            ))

    if task == 3: # For task 3
        # For testing Dijkstra,
        # Add more links between switches, possibly making loop
        for _ in range(switch * 2):
            s1 = random.choice(switches)
            s2 = random.choice(switches)
            if (s1 != s2) and (s1 not in switchneighbors[s2]) and (s2 not in switchneighbors[s1]):
                switchneighbors[s1].add(s2)
                switchneighbors[s2].add(s1)
                links.append((
                    s1,
                    s2,
                    random.randint(1 << 15, 1 << 30)
                ))
    if task in range(4,6): # For task 4, 5
        ## # KAIST CS341 SDN Lab Task 4, 5
        #
        # Simple structure: only one switch and lots of hosts
        switch=1
        host=10
        
        switches = ['s{}'.format(i) for i in range(1, 1+switch)]
        hosts = ['h{}'.format(i) for i in range(1, 1+host)]

        # Connect hosts to switches
        for host in hosts:
            node1 = host
            node2 = switches[0]
            links.append((
                node1,
                node2,
                random.randint(1 << 15, 1 << 30)
            ))
    return (switches, hosts, links)
