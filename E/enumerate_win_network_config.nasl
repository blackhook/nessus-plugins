#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176477);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_name(english:"Windows Network Config Enumeration");

  script_set_attribute(attribute:"synopsis", value:"Enumerates Windows network configuration details.");
  script_set_attribute(attribute:"description", value:"Enumerates Windows network configuration details.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ip_assignment_method.nbin", "wmi_list_interfaces.nbin");
  script_exclude_keys("SMB/not_windows");

  exit(0);
}

include('structured_data_system_network_config.inc');

var interface_ids = get_kb_list_or_exit('Host/iface/id');

var serialized_data = get_kb_item('Host/Network/IP_Addresses');
var addresses;
if(serialized_data)
  addresses = deserialize(serialized_data);
else
  addresses = {};

var snc = new('structured_data_system_network_config');

var name, mac_address, mtu, iface, addr, connection_status;
foreach var iface_id (interface_ids)
{
  iface = {
    ifindex: iface_id
  };

  if(!empty_or_null(addresses[iface_id]))
  {
    iface['addr_info'] = [];

    if(addresses[iface_id]['IPv4'])
      foreach addr (addresses[iface_id]['IPv4'])
        append_element(value: {
          family: 'IPv4',
          address: addr[0],
          assignMethod: addr[1],
          prefixlen: addr[2],
          addressState: addr[3]
        }, var: iface['addr_info']);
    
    if(addresses[iface_id]['IPv6'])
      foreach addr (addresses[iface_id]['IPv6'])
        append_element(value: {
          family: 'IPv6',
          address: addr[0],
          assignMethod: addr[1],
          prefixlen: addr[2],
          addressState: addr[3]
        }, var: iface['addr_info']);
  }

  if(addresses[iface_id] && addresses[iface_id]['IPv4'])
  {
    if(!iface['addr_info']) iface['addr_info'] = [];
  }

  name = get_kb_item('Host/iface/' + iface_id + '/name');
  if(!name) name = get_kb_item('Host/iface/' + iface_id + '/caption');
  if(name) iface['ifname'] = name;

  mac_address = get_kb_item('Host/iface/' + iface_id + '/mac');
  if(mac_address) iface['mac_address'] = mac_address;

  mtu = int(get_kb_item('Host/iface/' + iface_id + '/mtu'));
  if(mtu) iface['mtu'] = mtu;

  connection_status = get_kb_item('Host/iface/' + iface_id + '/connection_status');
  if(connection_status) iface['operstate'] = strcat(connection_status);

  snc.append('interfaces', iface);
}

snc.report_internal();
