import sys
sys.path.append("/usr/local/lib/python3.6/dist-packages")
from pytrie import SortedStringTrie as Trie
import pandas as pd
import re

RED = '\033[91m'
BLU = '\033[94m'
ENDC = '\033[0m'
threatlist = "threatlist.csv"
df = pd.read_csv(threatlist)
block_domains = set(df['IOC'])

def loadtree(arr):
    global trie
    trie=Trie()
    for key in arr:
        trie[key[::-1]] = key


def lookup_domain(qstate, id):
    domain = qstate.qinfo.qname_str.rstrip('.')[::-1]
    log_info(RED + "query: %s" % domain[::-1] + ", search as %s, result: " % domain + str(trie.values(domain)) + ENDC)
    if not trie.values(domain):
        if not trie.values(re.sub(r'\.[^.]*$','.*', domain)): 
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            log_info(RED + "[dnsfw] not matched: %s" % domain[::-1] + " as " + str(trie.values(re.sub(r'\.[^.]*$','.*', domain))[::-1]) + ENDC)
        else:
            qstate.return_rcode = RCODE_NXDOMAIN
            qstate.ext_state[id] = MODULE_FINISHED
            log_info(RED + "[dnsfw] matched: %s" % domain[::-1] + " as " + str(trie.values(re.sub(r'\.[^.]*$','.*', domain))[::-1]) + ENDC)

    else:
        qstate.return_rcode = RCODE_NXDOMAIN
        qstate.ext_state[id] = MODULE_FINISHED
        log_info(RED + "[dnsfw] matched: %s" % domain[::-1] + ENDC)

def init_standard(id, env):
        log_info(BLU + "insert tree..." +ENDC)
        loadtree(block_domains)
        #log_info(BLU + str(trie.items()) + ENDC)
        return True

def deinit(id):
	return True

def inform_super(id, qstate, superqstate, qdata):
	return True

def operate(id, event, qstate, qdata):
	if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
            lookup_domain(qstate, id)
            
#		msg = DNSMessage(qstate.qinfo.qname_str, qstate.qinfo.qtype, qstate.qinfo.qclass, PKT_QR | PKT_AA)
#		msg.answer.append("helloworld. 300 IN A 172.16.39.11")
#		msg.set_return_msg(qstate)
#		qstate.return_rcode = RCODE_NOERROR
#		qstate.return_msg.rep.security = 2
#		qstate.ext_state[id] = MODULE_FINISHED
	elif event == MODULE_EVENT_MODDONE:
	    qstate.ext_state[id] = MODULE_FINISHED
	else:
	    qstate.ext_state[id] = MODULE_ERROR
	return True
