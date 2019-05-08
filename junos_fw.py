#Creates a simple junos firewall rule.

def junos_fw_rule(term, src_fqdn, src_cidr, dst_fqdn, dst_cidr, protocol, dst_port_list):
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