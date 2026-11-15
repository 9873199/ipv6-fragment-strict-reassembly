"""Independent serialized IPv6 boundary tests. No interfaces or packets sent."""
import copy,hashlib,struct,unittest
from scapy.layers.inet import UDP,TCP
from scapy.layers.inet6 import IPv6,IPv6ExtHdrFragment,IPv6ExtHdrHopByHop,IPv6ExtHdrDestOpt,Pad1,PadN,defragment6_strict
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from wire_fixtures import whole,fragment,group,digest,SRC,DST

def run(ps,**limits):return defragment6_strict(ps,**limits)
def rejection(ps,**limits):
 r=run(ps,**limits)
 assert not r.reassembled,'Invalid group produced datagram'
 assert r.rejected,'Invalid group had no rejection reason'
 assert all(x.reason and x.group and x.ranges for x in r.rejected)
 return r

class WireAcceptance(unittest.TestCase):
 def test_udp_reverse_order_bytes(self):
  o,p=group();r=run(p[::-1]);self.assertFalse(r.rejected);self.assertEqual(bytes(r.reassembled[0]),bytes(o));self.assertNotIn(IPv6ExtHdrFragment,r.reassembled[0])
 def test_tcp_reverse_order_bytes(self):
  o,p=group(tcp=True);r=run(p[::-1]);self.assertFalse(r.rejected);self.assertEqual(bytes(r.reassembled[0]),bytes(o));self.assertIn(TCP,r.reassembled[0])
 def test_two_sources_same_id(self):
  a,p=group();b,q=group(src='2001:db8::3',payload=b'B'*80);r=run(p[::-1]+q[::-1]);self.assertFalse(r.rejected);self.assertEqual({bytes(x) for x in r.reassembled},{bytes(a),bytes(b)})
 def test_two_destinations_same_id(self):
  a,p=group();b,q=group(dst='2001:db8::4',payload=b'B'*80);r=run(q+p);self.assertFalse(r.rejected);self.assertEqual({bytes(x) for x in r.reassembled},{bytes(a),bytes(b)})
 def test_extension_chain_and_nh(self):
  o,p=group(extension=True);r=run(p[::-1]);self.assertFalse(r.rejected);x=r.reassembled[0];self.assertNotIn(IPv6ExtHdrFragment,x);self.assertEqual(x.nh,0);self.assertEqual(x[IPv6ExtHdrHopByHop].nh,17);self.assertEqual(bytes(x[UDP]),bytes(o[UDP]));self.assertEqual(x.plen,len(bytes(x))-40)
 def test_link_padding_excluded(self):
  o,p=group();frames=[Ether(bytes(Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/x)+b'\x00'*12) for x in p];r=run(frames[::-1]);self.assertFalse(r.rejected);self.assertEqual(bytes(r.reassembled[0][IPv6]),bytes(o))
 def test_input_hash_and_caches_unchanged(self):
  _,p=group(extension=True);before=[(bytes(x),copy.deepcopy(x.fields),x.raw_packet_cache,bytes(x.original)) for x in p];run(p[::-1]);after=[(bytes(x),copy.deepcopy(x.fields),x.raw_packet_cache,bytes(x.original)) for x in p];self.assertEqual(before,after)
 def test_overlap_partial(self):
  _,p=group();p.append(fragment(b'Z'*16,1));rejection(p)
 def test_exact_duplicate(self):
  _,p=group();p.append(IPv6(bytes(p[0])));rejection(p)
 def test_same_range_different_data(self):
  _,p=group();p.append(fragment(b'Z'*32,0));rejection(p)
 def test_hole(self):
  _,p=group();rejection([p[0],p[2]])
 def test_missing_first(self):
  _,p=group();rejection(p[1:])
 def test_missing_last(self):
  _,p=group();rejection(p[:-1])
 def test_conflicting_tail_endpoints(self):
  _,p=group();p.append(fragment(b'B'*8,10,m=0));rejection(p)
 def test_nonlast_after_declared_final(self):
  p=[fragment(b'A'*16,0),fragment(b'B'*8,2,m=0),fragment(b'C'*8,3,m=1)];rejection(p)
 def test_nonlast_alignment(self):
  rejection([fragment(b'A'*15,0),fragment(b'B'*8,2,m=0)])
 def test_offset_overflow(self):
  rejection([fragment(b'A'*16,8191,m=0)])
 def test_extension_plus_offset_overflow(self):
  rejection([fragment(b'A'*8,0,extension=True),fragment(b'B'*7,8191,m=0,extension=True)])
 def test_nested_fragment_header(self):
  nested=bytes(IPv6ExtHdrFragment(nh=17,id=99)/Raw(b'A'*16));rejection([fragment(nested,0,m=0,nh=44)])
 def test_nh_conflict(self):
  _,p=group();p[1]=fragment(b'B'*32,4,nh=6);rejection(p)
 def test_extension_chain_conflict(self):
  _,p=group();p[1]=fragment(b'B'*32,4,extension=True);rejection(p)
 def test_truncated_declared_length(self):
  _,p=group();p[1]=IPv6(bytes(p[1])[:-1]);rejection(p)
 def test_declared_length_below_fragment_header(self):
  _,p=group();wire=bytearray(bytes(p[0]));wire[4:6]=struct.pack('!H',4);p[0]=IPv6(bytes(wire));rejection(p)
 def test_atomic_separate_from_valid_regular(self):
  o,p=group();a=whole(payload=b'atomic');atomic=fragment(bytes(a)[40:],0,m=0);r=run([atomic]+p[::-1]);self.assertFalse(r.rejected);self.assertEqual({bytes(x) for x in r.reassembled},{bytes(a),bytes(o)})
 def test_atomic_does_not_poison_bad_regular(self):
  _,p=group();a=whole(payload=b'atomic');r=run([fragment(bytes(a)[40:],0,m=0)]+p+[IPv6(bytes(p[0]))]);self.assertEqual([bytes(x) for x in r.reassembled],[bytes(a)]);self.assertTrue(r.rejected)
 def test_two_atomic_same_id_independent(self):
  a=whole(payload=b'atomic1');b=whole(payload=b'atomic2');r=run([fragment(bytes(a)[40:],0,m=0),fragment(bytes(b)[40:],0,m=0)]);self.assertFalse(r.rejected);self.assertEqual([bytes(x) for x in r.reassembled],[bytes(a),bytes(b)])
 def test_valid_group_survives_bad_group(self):
  a,p=group();_,q=group(src='2001:db8::3');r=run(q+[IPv6(bytes(q[0]))]+p);self.assertEqual([bytes(x) for x in r.reassembled],[bytes(a)]);self.assertTrue(r.rejected)
 def test_group_budget_exact(self):
  _,p=group();r=run(p,max_groups=1);self.assertEqual(len(r.reassembled),1);self.assertFalse(r.rejected)
 def test_group_budget_exceeded(self):
  _,p=group();_,q=group(src='2001:db8::3');r=run(p+q,max_groups=1);self.assertEqual(len(r.reassembled),1);self.assertTrue(r.rejected)
 def test_fragment_budget_exact(self):
  _,p=group();r=run(p,max_fragments_per_group=len(p));self.assertEqual(len(r.reassembled),1);self.assertFalse(r.rejected)
 def test_fragment_budget_exceeded(self):
  _,p=group();rejection(p,max_fragments_per_group=len(p)-1)
 def test_byte_budget_exact(self):
  o,p=group();r=run(p,max_total_fragment_bytes=len(bytes(o))-40);self.assertEqual(len(r.reassembled),1);self.assertFalse(r.rejected)
 def test_byte_budget_exceeded(self):
  o,p=group();rejection(p,max_total_fragment_bytes=len(bytes(o))-41)
 def test_cumulative_byte_budget(self):
  o,p=group();_,q=group(src='2001:db8::3');r=run(p+q,max_total_fragment_bytes=len(bytes(o))-40);self.assertEqual([bytes(x) for x in r.reassembled],[bytes(o)]);self.assertTrue(r.rejected)

 def test_extension_chain_counts_towards_total_plen(self):
  body=b'A'*65535;p=[fragment(body[i:i+2048],i//8,int(i+2048<len(body)),nh=59,extension=True) for i in range(0,len(body),2048)];rejection(p)
 def test_nested_fragment_after_split_extension_header(self):
  body=bytes(IPv6ExtHdrDestOpt(nh=44,options=PadN(optdata=b'\x00'*38))/IPv6ExtHdrFragment(nh=17,id=9)/Raw(b'A'*16))
  p=[fragment(body[i:i+16],i//8,int(i+16<len(body)),nh=60) for i in range(0,len(body),16)];rejection(p)
if __name__=='__main__':unittest.main(verbosity=2)
