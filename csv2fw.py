import sys
import csv
import socket
import string

import junos_fw

from collections import defaultdict

TERM_PREFIX = 'term-'
INDENT = 4

# Yes. argparse.
if len(sys.argv) > 2:
    TERM_PREFIX = sys.argv[2]
if len(sys.argv) > 3:
    INDENT = int(sys.argv[3])

def indent(s, spaces):
    s = string.split(s, '\n')
    s = [(spaces * ' ') + line for line in s]
    s = string.join(s, '\n')
    return s

def test_read_csv_and_print(f):
    with open(f) as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        line_count = 0
        for idx, row in enumerate(csv_reader):
            src_cidr = row[0]
            dst_cidr = row[1]
            protocol = row[2]
            ports = row[3]
            rule = junos_fw.rule_single(TERM_PREFIX + str(idx),
                                src_cidr,
                                dst_cidr,
                                protocol,
                                ports)
            print indent(rule, INDENT)

def csv_to_dict(f):
    rules = defaultdict(list)
    with open(f) as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        line_count = 0
        for idx, row in enumerate(csv_reader):
            src_cidr = row[0]
            dst_cidr = row[1]
            src_fqdn = ''
            dst_fqdn = ''
            protocol = row[2]
            dst_ports = row[3]
            if '/32' in src_cidr:
                try:
                    src_fqdn = socket.gethostbyaddr(src_cidr.split('/')[0])[0]
                except:
                    # No PTR returned from query.
                    pass
            if '/32' in dst_cidr:
                try:
                    dst_fqdn = socket.gethostbyaddr(dst_cidr.split('/')[0])[0]
                except:
                    pass
            rules[(dst_cidr,protocol,dst_ports)].append(src_cidr)
    return rules

def dict_to_junos(rules):
    rules_formatted = junos_fw.rule_from_dict(TERM_PREFIX, rules)
    return rules_formatted

if __name__ == '__main__':
    #read_csv_and_print(sys.argv[1])
    rules = csv_to_dict(sys.argv[1])
    rules_formatted = dict_to_junos(rules)
    for rule in rules_formatted:
        print indent(rule, INDENT)
