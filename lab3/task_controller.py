#!/usr/bin/python3

import sys
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from scapy.all import * # you can use scapy in this task

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
cost = {}
port = {}
hosts = {}
switches = {}
routing_table = {}
port

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
  def dijkstra(self, src: int):

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

    print("path : ", path)
    path = ['s'+str(p+1) for p in path[:-1]]
    path.insert(0,'h'+str(src%num_switches + 1))
    path.append('h'+str(dest%num_switches + 1))
    print(dest)
    
    return path

def addrule(switchname, connection) -> None:
  print(switchname)
  print("addrule : ", port)
  
  
  for (s,d),path in routing_table.items():

  
    for idx,p in enumerate(path[1:-1]):
    
      if switchname == p:  
      
        in_port = port[(path[idx], path[idx+1])][1]
        out_port = port[(path[idx+1], path[idx+2])][0]

        print(p,':', in_port,',',out_port)
        arp_msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
        arp_msg.match = of.ofp_match()
        arp_msg.match.dl_type = 0x0806
        arp_msg.match.in_port = in_port
        arp_msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(arp_msg)
        
        ip_msg = of.ofp_flow_mod(command=of.OFPFC_ADD) 
        ip_msg.match = of.ofp_match()
        ip_msg.match.dl_type = 0x0800
        ip_msg.match.in_port = in_port
        print('h'+str(s+1),': ',hosts['h'+str(s+1)]['IP'])
        print('h'+str(d+1),':', hosts['h'+str(d+1)]['IP'])
        ip_msg.match.nw_src = IPAddr(hosts['h'+str(s+1)]['IP'])
        ip_msg.match.nw_dst = IPAddr(hosts['h'+str(d+1)]['IP']) 
        ip_msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(ip_msg)
        

        
  
	

 

def make_matrix():

  global graph, port, cost
  vertex = list(hosts.keys()|switches.keys())

  for key, value in hosts.items():
    for l in value['links']:
      port[(l[0], l[2])] = (l[1], l[3])
      cost[(l[0], l[2])] = l[4]

  for key, value in switches.items():
    for l in value['links']:
      port[(l[0], l[2])] = (l[1], l[3])
      cost[(l[0], l[2])] = l[4]
      
  graph = [[0]*len(vertex) for _ in range(len(vertex))]
  for i,v1 in enumerate(vertex):
    for j,v2 in enumerate(vertex):
      if v1==v2: continue
      if (v1, v2) in port.keys(): 
        graph[i][j] = cost[(v1, v2)]
        
      
      

    
def init(net):

  global num_hosts, num_switches, routing_table, hosts, switches
  print("net : ",net) 
  hosts = net['hosts']
  switches = net['switches']
  num_hosts = len(hosts.keys())
  num_switches = len(switches.keys())
  make_matrix()
  
  G = Graph(num_hosts+num_switches)
  G.graph = graph
  
  print("graph : ", graph)
  print("port : ", port)

  for s in range(num_hosts):
    dist = G.dijkstra(s+num_switches)
    for d in range(num_hosts):
      if s == d : continue
      print(s,'->',d)
      path = G.printShortestPath(dist, s+num_switches, d+num_switches)
      
      routing_table[(s,d)] = path  
  print("routing table : ", routing_table)

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
	#print("packet : ", packet.__dict__)
	print(packet.dump()) # print out unhandled packets
