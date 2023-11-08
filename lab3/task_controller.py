#!/usr/bin/python3

import sys
import struct
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from scapy.all import * # you can use scapy in this task

from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns
import pox.openflow.discovery as discovery
import pox.openflow.spanning_tree as spanning_tree


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
	
   #msg = of.ofp_flow_mod()
   #msg.match.dl_type = 0x0800
   #msg.match.nw_proto = 17 
   #msg.match.tp_src = 53  # Source port 53 (DNS query)
   #msg.match.tp_dst = 53  # Destination port 53 (DNS response)
   #msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
   #connection.send(msg)
   
   msg = of.ofp_flow_mod()
   #msg.match.dl_type = 0x0806
   msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
   connection.send(msg)
   
        

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
  data = event.data
  print("_" * 100)

  hexdump(data)
  pkt = Packet(data)
  ether = Ether(data)
  print(ether.show())
  
  print(type(pkt), pkt)
  print(pkt.name)
  print(pkt.parent)
  print(type(ether), ether)
  print(ether.__dict__)
  print(ether.summary())
  print("\n출발지 MAC 주소:", ether.src)
  print("목적지 MAC 주소:", ether.dst)
  print("이더넷 타입/프레임 유형:", hex(ether.type))
  
  if IP in ether:
    ip = ether[IP]
    print("\nIP 헤더:")
    print(ip.summary())
    print("\n출발지 IPv6 주소:", ip.src)
    print("목적지 IPv6 주소:", ip.dst)
    if Raw in ether:
      raw = ether[Raw]
      print(raw.load)
      decoded_data = raw.load.decode('ascii')
      
      

  if ICMPv6ND_RA in ether:
    ra = ether[ICMPv6ND_RA]
    print("\nICMPv6 Router Advertisement 메시지:")
    print("유형:", ra.type)
    print("코드:", ra.code)
    print("체크섬:", hex(ra.chksum))
 
  
  packetfrags = {} 
  p = packet
  while p is not None:
    packetfrags[p.__class__.__name__] = p
    if isinstance(p, bytes): break
    p = p.next

  print("dropt : ",packet.dump()) # print out unhandled packets
