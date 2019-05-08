import sys
import csv
import socket
import string

from junos_fw import junos_fw_rule

TERM_PREFIX = 'term-'
INDENT = 4

def indent(s, spaces):
    s = string.split(s, '\n')
    s = [(spaces * ' ') + line for line in s]
    s = string.join(s, '\n')
    return s

if len(sys.argv) > 2:
    TERM_PREFIX = sys.argv[2]

with open(sys.argv[1]) as csvfile:
    csv_reader = csv.reader(csvfile, delimiter=',')
    line_count = 0
    for idx, row in enumerate(csv_reader):
        src_cidr = row[0]
        dst_cidr = row[1]
        protocol = row[2]
        ports = row[3]
        src_fqdn = ''
        dst_fqdn = ''
        if '/32' in src_cidr:
            src_fqdn = socket.gethostbyaddr(src_cidr.split('/')[0])[0]
        if '/32' in dst_cidr:
            dst_fqdn = socket.gethostbyaddr(dst_cidr.split('/')[0])[0]
        rule = junos_fw_rule(TERM_PREFIX + str(idx),
                            src_fqdn,
                            src_cidr,
                            dst_fqdn,                            
                            dst_cidr,
                            protocol,
                            ports)
        print indent(rule, INDENT)