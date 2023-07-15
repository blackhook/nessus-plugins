#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176476);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_name(english:"Linux / Unix Network Config Enumeration");

  script_set_attribute(attribute:"synopsis", value:"Enumerates Linux / Unix network configuration details.");
  script_set_attribute(attribute:"description", value:"Enumerates Linux / Unix network configuration details.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ip_assignment_method.nbin");
  script_require_keys("Host/uname");

  exit(0);
}

include('structured_data_system_network_config.inc');

var serialized_data = get_kb_item_or_exit('Host/iproute2_ip_a');
var ip_a;
if(serialized_data) 
  ip_a = deserialize(serialized_data);
else 
  ip_a = {};

var snc = new('structured_data_system_network_config');

var iface, addresses, tmp_addr;
foreach var ip_a_iface (ip_a)
{
  iface = {
    ifindex: ip_a_iface['ifindex'],
    ifname: ip_a_iface['ifname'],
    mac_address: ip_a_iface['address'],
  };

  if(ip_a_iface['flags'])     iface['flags']     = ip_a_iface['flags'];
  if(ip_a_iface['mtu'])       iface['mtu']       = ip_a_iface['mtu'];
  if(ip_a_iface['operstate']) iface['operstate'] = ip_a_iface['operstate'];

  addresses = [];

  foreach var addr (ip_a_iface.addr_info)
  {
    tmp_addr = {};

    if(addr.local) tmp_addr['address'] = addr.local;
    else tmp_addr['address'] = 'unknown';

    if(addr.dynamic) tmp_addr['assignMethod'] = 'dynamic';
    else tmp_addr['assignMethod'] = 'static';
    
    if(addr.family == 'inet') tmp_addr['family'] = 'IPv4';
    else if(addr.family == 'inet6') tmp_addr['family'] = 'IPv6';

    if(addr.prefixlen) tmp_addr['prefixlen'] = addr.prefixlen;
    
    if(addr.scope) tmp_addr['scope'] = addr.scope;
  
    append_element(var: addresses, value: tmp_addr);
  }
  iface['addr_info'] = addresses;

  snc.append('interfaces', iface);
}

snc.report_internal();
