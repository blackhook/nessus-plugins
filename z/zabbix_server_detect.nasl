#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22526);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Zabbix Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A Zabbix server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Zabbix server.  Zabbix is an open source
network monitoring application, and a Zabbix server is used to collect
information from agents on hosts being monitored.");
  script_set_attribute(attribute:"see_also", value:"https://www.zabbix.com/");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 10051);

  exit(0);
}

include('debug.inc');

var port, soc, found, res, req, invalid_chars;

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(10051);
  if (!port) audit(AUDIT_SVC_KNOWN); 
}
else port = 10051;
if (known_service(port:port)) audit(AUDIT_SVC_ALREADY_KNOWN,port);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

found = 0;

# Valid chars in hostname are: '0-9a-zA-Z. _-'
invalid_chars ='$@';

# It's important to use invalid chars in hostname, otherwise the 
# request data will be put into the zabbix database if auto 
# registration is enabled on the zabbix server.
req = "ZBX_GET_ACTIVE_CHECKS\n" + invalid_chars + SCRIPT_NAME + "-" + unixtime();

send(socket:soc, data:req);

# (1) for debugging
res = recv(socket:soc, length:1024);
dbg::log(src:SCRIPT_NAME, msg:'\nres (1) = \n\t' + res);

close(soc);

# It's a Zabbix server if the response is "ZBX_EOF".
if (res && res == 'ZBX_EOF\n') 
  found = 1;

# The above detection method does not work for 2.2.x, 2.4.x, 3.x
if(! found)
{
  # Need to reconnect as the server closes the connection
  # on first request
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  req = '{"request":"active checks", "host":"' + invalid_chars + SCRIPT_NAME+ '"}'; 
  send(socket:soc, data:req);
  
  # (2) for debugging
  res = recv(socket:soc, length:1024);
  dbg::log(src:SCRIPT_NAME, msg:'\nres (2) = \n\t' + res);

  close(soc);

  # Server should respond with a message containing "invalid host name" 
  if (res && res =~ '^ZBXD' && 'invalid host name' >< res) 
    found = 1;
}

if(found)
{
  # Register and report the service.
  register_service(port:port, ipproto:'tcp', proto:'zabbix_server');
  security_report_v4(port: port, severity: SECURITY_NOTE);
}
else
{
  audit(AUDIT_NOT_DETECT, 'zabbix server' , port); 
}

