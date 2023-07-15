#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(175142);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/27");

  script_name(english:"SLP Find Attributes");

  script_set_attribute(attribute:"synopsis", value:
"The remote server supports the Service Location Protocol." );
  script_set_attribute(attribute:"description", value:
"The remote server understands Service Location Protocol (SLP), a
protocol that allows network applications to discover the existence,
location, and configuration of various services in an enterprise
network environment. Services listed via SLP may include a number
of attributes. These attributes are parsed out here." );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc2608.txt" );
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/05");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("slp_udp_detect.nasl", "slp_tcp_detect.nasl");
  script_require_ports("Services/udp/slp", "Services/tcp/slp", 427);

  exit(0);
}

include("compat_shared.inc");
include('slp.inc');

var ports = get_kb_list_or_exit("Services/*/slp");
var port = keys(ports);
port = ports[port[0]];

var slp_svcs = get_kb_list_or_exit('SLP/svc/*');

var parsed, plugin_output, svc_attr;
for (var svc in slp_svcs)
{
  svc_attr = slp_svcs[svc];
  svc = svc - 'SLP/svc/';
  if (svc_attr == 1)
    continue;
  plugin_output = plugin_output + ' ' + svc + ' : \n';
  parsed = slp::slp_parse_attributes(attr_list:svc_attr);
  for (var key in parsed)
  {
    plugin_output = plugin_output + '    ' + key + ' = ' + parsed[key] +'\n';
    dbg::detailed_log(lvl:2, msg: 'key: '+key+'; value: '+parsed[key]+'\n');
    replace_kb_item(name: 'SLP/svc/'+svc+'/'+key, value: parsed[key]);
  }
  plugin_output = plugin_output + '\n\n';
}

security_report_v4(port: port, severity: SECURITY_NOTE, extra: plugin_output);
