#!/usr/bin/python3

import sys
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from scapy.all import * # you can use scapy in this task


graph = []
cost = {}
port = {}
hosts = {}
switches = {}
routing_table = {}

class Graph():

  def __init__(self, vertices):
    self.V = vertices
    self.parent = [-1] * vertices

  def minDistance(self, dist, sptSet):

    _min = sys.maxsize

    for v in range(self.V):
      if dist[v] < _min and sptSet[v] == False:
        _min = dist[v]
        min_index = v

    return min_index

  def dijkstra(self, src: int):

    dist = [sys.maxsize] * self.V
    dist[src] = 0
    sptSet = [False] * self.V

    for cout in range(self.V):

      u = self.minDistance(dist, sptSet)

      sptSet[u] = True

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
    print("path :::", path)
    path[0] = 'h'+str(path[0]%len(switches.keys())+1)
    path[-1]='h'+str(path[-1]%len(switches.keys())+1)
    
    for p in range(1,len(path)-1): path[p] = 's'+str(path[p]+1)

    print("path :::", path)
    return path

def addrule(switchname, connection) -> None:
  print(switchname)
  print("addrule : ", port)
  
  for (s,d),path in routing_table.items():

    print('h'+str(s+1),': ',hosts['h'+str(s+1)]['IP'])
    print('h'+str(d+1),':', hosts['h'+str(d+1)]['IP'])
    for idx,p in enumerate(path[1:-1]):
      print(path)
      print(switchname, ',', p)
      if switchname == p:  
        print("loop")
        
        in_port = port[(path[idx], path[idx+1])][1]
        out_port = port[(path[idx+1], path[idx+2])][0]

        print(p,':', in_port,',',out_port)
        arp_msg = of.ofp_flow_mod()
        arp_msg.match = of.ofp_match()
        arp_msg.match.dl_type = 0x0806
        arp_msg.match.in_port = in_port
        arp_msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(arp_msg)
        
        ip_msg = of.ofp_flow_mod() 
        ip_msg.match = of.ofp_match()
        ip_msg.match.dl_type = 0x0800
        ip_msg.match.in_port = in_port
        ip_msg.match.nw_src = IPAddr(hosts['h'+str(s+1)]['IP'])
        ip_msg.match.nw_dst = IPAddr(hosts['h'+str(d+1)]['IP']) 
        ip_msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(ip_msg)
        

def make_matrix():

  global graph, port, cost
  vertex = {}
  vertex.update(switches)
  vertex.update(hosts)
  for key, value in hosts.items():
    for l in value['links']:

      port[(l[0], l[2])] = (l[1], l[3])
      cost[(l[0], l[2])] = l[4]

  for key, value in switches.items():
    for l in value['links']:

      port[(l[0], l[2])] = (l[1], l[3])
      cost[(l[0], l[2])] = l[4]

  graph = [[0]*len(vertex.keys()) for _ in range(len(vertex.keys()))]
  for i,v1 in enumerate(vertex.keys()):
    for j,v2 in enumerate(vertex.keys()):
      if v1==v2: continue
      if (v1, v2) in port.keys(): 
        # print(i,',',j)
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
  
  print("port : ", port)
  print("graph : ", graph)
  
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
