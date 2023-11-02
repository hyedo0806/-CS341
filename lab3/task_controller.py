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

hosts = {}
switches = {}

def init(net) -> None:
    global hosts, switches
    hosts = net['hosts']
    switches = net['switches']
    print("for task3 init", net)


    

def addrule(switchname: str, connection) -> None:
    global hosts, switches

    if switchname in switches:

        # 라우팅 규칙을 계산하고 스위치에 추가하는 로직을 구현합니다.
        # Dijkstra 알고리즘 또는 다른 라우팅 알고리즘을 사용하여 라우팅 규칙을 계산합니다.

        # 예를 들어, 모든 스위치 간에 연결된 포트로 전송하는 규칙을 설정하는 코드입니다.
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()  # 모든 패킷과 일치
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))  # 모든 포트로 패킷을 전송
        connection.send(msg)  


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
