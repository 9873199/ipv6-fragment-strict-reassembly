from test_acceptance import WireAcceptance,fragment,run,IPv6ExtHdrDestOpt,IPv6ExtHdrFragment,PadN,Raw
c=WireAcceptance()
c.test_udp_reverse_order_bytes();print('Reversed UDP fragments, exact bytes: PASS')
c.test_tcp_reverse_order_bytes();print('Reversed TCP fragments, exact bytes: PASS')
c.test_atomic_does_not_poison_bad_regular();print('Atomic isolation and duplicate rejection: PASS')
c.test_byte_budget_exceeded();print('Fragment byte budget: PASS')
bad=0
r=run([fragment(b'A'*16,0),fragment(b'B'*8,2,m=0),fragment(b'C'*8,3,m=1)])
accepted=bool(r.reassembled);bad+=accepted
print('Fragment after declared final:', 'FAIL - accepted' if accepted else 'PASS - rejected')
body=bytes(IPv6ExtHdrDestOpt(nh=44,options=PadN(optdata=b'\x00'*38))/IPv6ExtHdrFragment(nh=17,id=9)/Raw(b'A'*16))
p=[fragment(body[i:i+16],i//8,int(i+16<len(body)),nh=60) for i in range(0,len(body),16)];r=run(p)
accepted=bool(r.reassembled);bad+=accepted
print('Split extension hides nested Fragment:', 'FAIL - accepted' if accepted else 'PASS - rejected')
body=b'A'*65535;p=[fragment(body[i:i+2048],i//8,int(i+2048<len(body)),nh=59,extension=True) for i in range(0,len(body),2048)]
try:
 r=run(p);ok=bool(r.rejected) and not r.reassembled;bad+=not ok
 print('65535 bytes plus8 extension:', 'PASS - rejected' if ok else 'FAIL - accepted')
except Exception as e:
 bad+=1;print('65535 bytes plus8 extension: FAIL -',type(e).__name__,str(e))
print('All packets synthetic; network packets sent: 0')
print('Observed failing checks:',bad)
raise SystemExit(bool(bad))
