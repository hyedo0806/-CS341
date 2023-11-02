#!/usr/bin/python3

import pox.openflow.libopenflow_01 as of

# KAIST CS341 SDN Lab Task 2, 3, 4
#
# All functions in this file runs on the controller:
#   - init(net):
#       - runs only once for network, when initialized
#       - the controller should process the given network structure for future behavior
#   - addrule(switchname, connection):
#       - runs when a switch connects to the controller
#       - the controller should insert routing rules to the switch
#   - handlePacket(packet, connection):
#       - runs when a switch sends unhandled packet to the controller
#       - the controller should decide whether to handle the packet:
#           - let the switch route the packet
#           - drop the packet
#
# Task 2: Getting familiarized with POX 
#   - Let switches "flood" packets
#   - This is not graded
# 
# Task 3: Implementing a Simple Routing Protocol
#   - Let switches route via Dijkstra
#   - Match ARP and ICMP over IPv4 packets
#
# Task 4: Implementing simple DNS-based censorship 
#   - Let switches send all DNS packets to Controller
#       - Create proper forwarding rules, send all DNS queries and responses to the controller
#       - HTTP traffic should not be forwarded to the controller
#   - Check if DNS query contains cs341dangerous.com
#       - For such query, drop it and reply it with empty DNS response
#       - For all other packets, route them normally
#       
#
# Task 5: Implementing more efficient DNS-based censorship 
#   - Let switches send only DNS query packets to Controller
#       - Create proper forwarding rules, send only DNS queries to the controller
#   - Check if DNS query contains cs341dangerous.com
#       - If such query is found, insert a new rule to switch to track the DNS response
#           - let the swtich route DNS response to the controller
#       - When the corresponding DNS response arrived, do followings:
#           - parse DNS response, insert a new rule to block all traffic from/to the server
#           - reply the DNS request with empty DNS response
#       - For all other packets, route them normally


###
# If you want, you can define global variables, import libraries, or do others
###


def init(net) -> None:
    # Compute forwarding rules for all switches
    # This function is called only once during network initialization

    switches = net['switches']
    links = []

    # Parse links from the network structure
    for switch_name, switch_info in switches.items():
        for link_info in switch_info['links']:
            links.append(link_info)

    # Compute forwarding rules using Dijkstra algorithm
    forwarding_rules = {}  # Dictionary to store forwarding rules for each switch

    # Define a function to calculate the shortest path using Dijkstra's algorithm
    def dijkstra(switch_name):
        # Initialize data structures
        visited = set()
        distance = {}
        previous = {}
        for switch in switches:
            distance[switch] = float('inf')
            previous[switch] = None

        distance[switch_name] = 0

        # Calculate shortest path
        while len(visited) < len(switches):
            # Select the switch with the shortest distance
            current_switch = min((s for s in switches if s not in visited), key=lambda x: distance[x])
            visited.add(current_switch)

            # Update distances to neighbors
            for link_info in links:
                if link_info[0] == current_switch:
                    neighbor = link_info[2]
                    cost = link_info[4]
                    if distance[current_switch] + cost < distance[neighbor]:
                        distance[neighbor] = distance[current_switch] + cost
                        previous[neighbor] = current_switch

        # Extract forwarding rules
        rules = {}
        for destination, next_hop in previous.items():
            if next_hop is not None:
                out_port = next(link_info[3] for link_info in links if link_info[0] == destination and link_info[2] == next_hop)
                rules[destination] = out_port

        return rules

    for switch_name in switches:
        rules = dijkstra(switch_name)
        forwarding_rules[switch_name] = rules

    # Store the forwarding rules for later use
    net['_forwarding_rules'] = forwarding_rules

def addrule(switchname: str, connection) -> None:
    # Compute forwarding rules for all switches and push rules to switches
    forwarding_rules = connection.net['_forwarding_rules']

    if switchname in forwarding_rules:
        rules = forwarding_rules[switchname]
        for destination, out_port in rules.items():
            # Create flow modification message for ARP packets
            arp_msg = of.ofp_flow_mod()
            arp_msg.match.dl_type = 0x0806  # Match ARP packets (EtherType 0x0806)
            arp_msg.match.nw_dst = destination  # Match the destination IP address
            arp_msg.actions.append(of.ofp_action_output(port=out_port))  # Set the output port
            connection.send(arp_msg)  # Send the message to the switch

            # Create flow modification message for IPv4 packets
            ipv4_msg = of.ofp_flow_mod()
            ipv4_msg.match.dl_type = 0x0800  # Match IPv4 packets (EtherType 0x0800)
            ipv4_msg.match.nw_dst = destination  # Match the destination IP address
            ipv4_msg.actions.append(of.ofp_action_output(port=out_port))  # Set the output port
            connection.send(ipv4_msg)  # Send the message to the switch

def handlePacket(switchname, event, connection):
    # This function is not needed for Task 3, so you can leave it empty.
    pass


from scapy.all import * # you can use scapy in this task

def handlePacket(switchname, event, connection):
    packet = event.parsed
    if not packet.parsed:
        print('Ignoring incomplete packet')
        return
    # Retrieve how packet is parsed
    # Packet consists of:
    #  - various protocol headers
    #  - one content
    # For example, a DNS over UDP packet consists of following:
    # [Ethernet Header][           Ethernet Body            ]
    #                  [IPv4 Header][       IPv4 Body       ]
    #                               [UDP Header][ UDP Body  ]
    #                                           [DNS Content]
    # POX will parse the packet as following:
    #   ethernet --> ipv4 --> udp --> dns
    # If POX does not know how to parse content, the content will remain as `bytes`
    #     Currently, HTTP messages are not parsed, remaining `bytes`. you should parse it manually.
    # You can find all available packet header and content types from pox/pox/lib/packet/
    packetfrags = {}
    p = packet
    while p is not None:
        packetfrags[p.__class__.__name__] = p
        if isinstance(p, bytes):
            break
        p = p.next
    print(packet.dump()) # print out unhandled packets
    # How to know protocol header types? see name of class

    # If you want to send packet back to switch, you can use of.ofp_packet_out() message.
    # Refer to [ofp_packet_out - Sending packets from the switch](https://noxrepo.github.io/pox-doc/html/#ofp-packet-out-sending-packets-from-the-switch)
    # You may learn from [l2_learning.py](pox/pox/forwarding/l2_learning.py), which implements learning switches
