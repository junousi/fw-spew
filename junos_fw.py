#Creates junos firewall rules.
import socket

def rule_single(term, src_cidr, dst_cidr, protocol, dst_port_list):

    src_fqdn = ''
    dst_fqdn = ''
    if '/32' in src_cidr:
        try:
            src_fqdn = socket.gethostbyaddr(src_cidr.split('/')[0])[0]
        except:
            pass
    if '/32' in dst_cidr:
        try:
            dst_fqdn = socket.gethostbyaddr(dst_cidr.split('/')[0])[0]
        except:
            pass

    rule = '''\
term {term} {{
    from {{
        source-address {{
            /* {src_fqdn} */
            {src_cidr};
        }}
        destination-address {{
            /* {dst_fqdn} */
            {dst_cidr};
        }}
        protocol {protocol};
        destination-port [ {dst_port_list} ];
    }}
then accept;
}}'''.format(term=term,
            src_fqdn=src_fqdn,
            src_cidr=src_cidr,
            dst_fqdn=dst_fqdn,
            dst_cidr=dst_cidr,
            protocol=protocol,
            dst_port_list=dst_port_list,)
    return rule


def rule_from_dict(term, rules):

    rules_formatted = []

    for idx, key in enumerate(rules.keys()):
        src_fqdn = ''
        dst_fqdn = ''

        src_cidr_list = rules[key]
        src_cidr_lines = ''
        for cidr in src_cidr_list:
            src_cidr_lines = src_cidr_lines + ' ' * 12 + str(cidr) + ';' + '\n'

        dst_cidr = key[0]
        protocol = key[1]
        dst_port_list = key[2]

        # Retrieve the FQDN only in the case of a single source address.
        if len(src_cidr_list) == 1 and '/32' in src_cidr_list[0]:
            try:
                src_fqdn = socket.gethostbyaddr(src_cidr_list[0].split('/')[0])[0]
            except:
                pass
        if '/32' in dst_cidr:
            try:
                dst_fqdn = socket.gethostbyaddr(dst_cidr.split('/')[0])[0]
            except:
                pass

        rule = '''\
term {term} {{
    from {{
        source-address {{
            /* {src_fqdn} */
{src_cidr_lines}
        }}
        destination-address {{
            /* {dst_fqdn} */
            {dst_cidr};
        }}
        protocol {protocol};
        destination-port [ {dst_port_list} ];
    }}
then accept;
}}'''.format(term=term + str(idx),
            src_fqdn=src_fqdn,
            src_cidr_lines=src_cidr_lines,
            dst_fqdn=dst_fqdn,
            dst_cidr=dst_cidr,
            protocol=protocol,
            dst_port_list=dst_port_list,)
        rules_formatted.append(rule)

    return rules_formatted
