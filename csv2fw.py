import sys
import csv
import socket
import string
import argparse

import junos_fw

from collections import defaultdict

# Defaults
TERM_PREFIX = 'term-'
INDENT = 4

# Arguments
parser = argparse.ArgumentParser(description='Create firewall configuration',
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="""Create firewall configuration""")
parser.add_argument('-t', '--term-prefix', dest='term_prefix',
                    help='prefix for firewall terms')
parser.add_argument("-i", "--indent", dest='indent', type=int, default=INDENT,
                    help="amount of whitespace indent, defaults to " + str(INDENT))
parser.add_argument('-f', '--file', dest="csv_file",
                    required=True, help="csv file for source data")
args = parser.parse_args()

if args.term_prefix:
    TERM_PREFIX = args.term_prefix
if args.term_prefix:
    INDENT = args.indent

# Helpers
def indent(s, spaces):
    s = string.split(s, '\n')
    s = [(spaces * ' ') + line for line in s]
    s = string.join(s, '\n')
    return s

# Main functions
def test_read_csv_and_print(f):
    with open(f) as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
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
    # Store firewall rules into a dict whose key tuple of:
    # - Destination CIDR
    # - Protocol (tcp/udp)
    # - Whitespace separated list of destination ports.
    # The dictionary contains lists of source CIDRs per tuple.
    with open(f) as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        for idx, row in enumerate(csv_reader):
            src_cidr = row[0]
            dst_cidr = row[1]
            protocol = row[2]
            dst_ports = row[3]
            rules[(dst_cidr,protocol,dst_ports)].append(src_cidr)
    return rules

def dict_to_junos(rules):
    rules_formatted = junos_fw.rule_from_dict(TERM_PREFIX, rules)
    return rules_formatted

if __name__ == '__main__':
    #test_read_csv_and_print(args.csv_file)
    rules = csv_to_dict(args.csv_file)
    rules_formatted = dict_to_junos(rules)
    for rule in rules_formatted:
        print indent(rule, INDENT)
