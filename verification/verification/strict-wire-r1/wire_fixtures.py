"""IPv6 fragment wire fixtures; no interface access or packets sent."""
import hashlib,json,sys
from pathlib import Path
from scapy.layers.inet import UDP,TCP
from scapy.layers.inet6 import IPv6,IPv6ExtHdrFragment,IPv6ExtHdrHopByHop,Pad1
from scapy.layers.l2 import Ether
from scapy.packet import Raw
SRC='2001:db8::1';DST='2001:db8::2'
def whole(src=SRC,dst=DST,payload=b'A'*80,tcp=False):
 upper=TCP(sport=10000,dport=443,seq=7,flags='PA') if tcp else UDP(sport=10000,dport=5353)
 return IPv6(bytes(IPv6(src=src,dst=dst)/upper/Raw(payload)))
def fragment(data,offset,m=1,src=SRC,dst=DST,id=77,nh=17,extension=False):
 p=IPv6(src=src,dst=dst)
 if extension:p=p/IPv6ExtHdrHopByHop(options=Pad1())
 p=p/IPv6ExtHdrFragment(id=id,offset=offset,m=m,nh=nh)/Raw(data)
 return IPv6(bytes(p))
def group(src=SRC,dst=DST,id=77,payload=b'A'*80,tcp=False,extension=False):
 original=whole(src,dst,payload,tcp);body=bytes(original)[40:];parts=[]
 for start in range(0,len(body),32):
  chunk=body[start:start+32];parts.append(fragment(chunk,start//8,int(start+len(chunk)<len(body)),src,dst,id,6 if tcp else 17,extension))
 return original,parts

def digest(p):return hashlib.sha256(bytes(p)).hexdigest()
def control(output):
 results=[]
 for tcp,ext in [(False,False),(True,False),(False,True)]:
  original,parts=group(tcp=tcp,extension=ext);body=b''.join(bytes(p[IPv6ExtHdrFragment].payload) for p in parts);assert body==bytes(original)[40:];assert [p[IPv6ExtHdrFragment].offset*8 for p in parts]==list(range(0,len(body),32));assert all(p.plen==len(bytes(p))-40 for p in parts)
  results.append({'tcp':tcp,'extension':ext,'parts':len(parts),'upper_bytes':len(body),'input_hashes':[digest(p) for p in parts]})
 original,parts=group();frame=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/parts[0];withpad=Ether(bytes(frame)+b'\x00'*12);assert bytes(withpad[IPv6])[:40+withpad[IPv6].plen]==bytes(parts[0])
 result={'status':'PASS_WIRE_FIXTURE_CONTROL','cases':results,'ether_padding_outside_ipv6_length_verified':True,'network_packets_sent':0,'future_strict_results':None};Path(output).write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result))
if __name__=='__main__':control(sys.argv[1])
