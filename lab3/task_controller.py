#!/usr/bin/python3

import sys
# import pox.openflow.libopenflow_01 as of
# from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
# from scapy.all import * # you can use scapy in this task

# KAIST CS341 SDN Lab Task 2, 3, 4
#
# All functions in this file runs on the controller:
#   - init(net):
#       - runs only once for network, when initialized
#       - the controller shTould process the given network structure for future behavior
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

graph = []
port = []
hosts = {}
switches = {}
routing_table = {}

class Graph():

  def __init__(self, vertices):
    self.V = vertices
    self.graph = [[0 for column in range(vertices)] for row in range(vertices)]
    self.parent = [-1] * vertices

  def minDistance(self, dist, sptSet):

		# Initilaize minimum distance for next node
    _min = sys.maxsize

		# Search not nearest vertex not in the
		# shortest path tree
    for v in range(self.V):
      if dist[v] < _min and sptSet[v] == False:
        _min = dist[v]
        min_index = v

    return min_index

	# Funtion that implements Dijkstra's single source
	# shortest path algorithm for a graph represented
	# using adjacency matrix representation
  def dijkstra(self, src):

    dist = [sys.maxsize] * self.V
    dist[src] = 0
    sptSet = [False] * self.V

    for cout in range(self.V):

      # Pick the minimum distance vertex from
      # the set of vertices not yet processed.
      # u is always equal to src in first iteration
      u = self.minDistance(dist, sptSet)

      # Put the minimum distance vertex in the
      # shotest path tree
      sptSet[u] = True

      # Update dist value of the adjacent vertices
      # of the picked vertex only if the current
      # distance is greater than new distance and
      # the vertex in not in the shotest path tree
      for v in range(self.V):
        if self.graph[u][v] > 0 and sptSet[v] == False and dist[v] > dist[u] + self.graph[u][v]:
          dist[v] = dist[u] + self.graph[u][v]
          self.parent[v] = u
    return dist

  def printShortestPath(self, dist, src, dest):
    if dist[dest] == sys.maxsize:
      print("경로 없음")
      return

    path = []
    at = dest
    while at != src:
      path.insert(0, at)
      at = self.parent[at]

    path.insert(0, src)
    return path

def addrule(switchname, connection) -> None:
  for (s,d),path in routing_table.items():
    for idx, p in enumerate(path):
      if switchname == 's'+str(p): 
        print(s,',',d)
        # arp_msg = of.ofp_flow_mod()
        # arp_msg.match.dl_type = 0x806
        # arp_msg.actions.append(of.ofp_action_output(port=port[p][path[idx+1]]))
        # connection.send(arp_msg)
        
        # ip_msg = of.ofp_flow_mod() 
        # ip_msg.match.dl_type = 0x800
        # ip_msg.match.nw_src = hosts[s]['IP'] 
        # ip_msg.match.nw_dst = hosts[d]['IP'] 
        # ip_msg.actions.append(of.ofp_action_output(port=port[p][path[idx+1]]))
        # connection.send(ip_msg)
  
	#msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD)) ## for task2 : flood method

def make_matrix():
  adjacency_matrix = [[0] * (num_hosts + num_switches) for _ in range(num_hosts + num_switches)]
  port_matrix = [[0] * (num_hosts + num_switches) for _ in range(num_hosts + num_switches)]

  for host_name, host_info in hosts.items():
    host_index = num_switches + list(hosts.keys()).index(host_name)
    for link in host_info['links']:
      host_port = link[1]  # 호스트의 포트 번호
      switch_name = link[2]
      switch_index = list(switches.keys()).index(switch_name)
      switch_port = link[3]  # 스위치의 포트 번호
      length = link[4]  # 두 노드 사이의 길이
      adjacency_matrix[host_index][switch_index] = length
      adjacency_matrix[switch_index][host_index] = length

      port_matrix[host_index][switch_index] = (host_port, switch_port)
      port_matrix[switch_index][host_index] = (switch_port, host_port)
	

	# 스위치 간 연결 정보 반영
  for switch_name, switch_info in switches.items():
    switch_index = list(switches.keys()).index(switch_name)
    for link in switch_info['links']:
      if link[2].startswith('h'):
        host_port = link[3]  # 호스트의 포트 번호
        switch_port = link[1]  # 스위치의 포트 번호
        host_name = link[2]
        host_index = num_switches + list(hosts.keys()).index(host_name)
        length = link[4]  # 두 노드 사이의 길이
        adjacency_matrix[switch_index][host_index] = length
        adjacency_matrix[host_index][switch_index] = length
        port_matrix[switch_index][host_index] = switch_port
        port_matrix[host_index][switch_index] = host_port
      else:
        switch_port = link[1]  # 현재 스위치의 포트 번호
        connected_switch_port = link[3]  # 연결된 스위치의 포트 번호
        connected_switch_name = link[2]
        connected_switch_index = list(switches.keys()).index(connected_switch_name)
        length = link[4]  # 두 노드 사이의 길이
        adjacency_matrix[switch_index][connected_switch_index] = length
        adjacency_matrix[connected_switch_index][switch_index] = length
        port_matrix[switch_index][connected_switch_index] = switch_port
        port_matrix[connected_switch_index][switch_index] = connected_switch_port

  graph, port = [], []
	# 인접행렬 출력
  for row in adjacency_matrix:
    graph.append(row)

  for row in port_matrix:
    port.append(row)

  return graph, port
    
def init(net):

  global num_hosts, num_switches, routing_table, port 
  num_hosts = len(hosts.keys())
  num_switches = len(switches.keys())
  graph, port = make_matrix()

  G = Graph(num_hosts+num_switches)
  G.graph = graph

  for s in range(num_hosts):
    dist = G.dijkstra(s+num_switches)
    for d in range(num_hosts):
      if s == d : continue
      path = G.printShortestPath(dist, s+num_switches, d+num_switches)
      
      src = 'h' + str(path[0]%num_switches)
      dst = 'h' + str(path[-1]%num_switches)
      routing_table[(s,d)] = path     

def handlePacket(switchname, event, connection):
	global bestport
	packet = event.parsed
	if not packet.parsed:
		print('Ignoring incomplete packet')
		return

	packetfrags = {}
	p = packet
	while p is not None:
		packetfrags[p.__class__.__name__] = p
		if isinstance(p, bytes):
			break
		p = p.next
	print(packet.dump()) # print out unhandled packets
