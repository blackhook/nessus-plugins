#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59731);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"MikroTik RouterOS Winbox Detection");

  script_set_attribute(attribute:"synopsis", value:
"A configuration service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote port is used by Winbox, a remote management tool, to
administer devices running MikroTik RouterOS.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.mikrotik.com/wiki/Manual:Winbox");
  script_set_attribute(attribute:"solution", value:
"Limit access to this port to authorized hosts.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mikrotik:winbox");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 8291);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(port);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (!silent_service(port)) exit(0, "The service listening on port "+port+" is not silent.");
}
else port = 8291;

if (known_service(port:port)) exit(0, "The service on port " + port + " has already been identified.");
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

payload = "index" + crap(length:6, data:mkbyte(0)) + 
    mkbyte(0) + mkbyte(0xff) + 
    mkbyte(0xed) + crap(length:4, data:mkbyte(0));
req = mkbyte(strlen(payload)) + mkbyte(2) + payload;
send(socket:soc, data:req);

res = recv(socket:soc, length:4096);
if (strlen(res) == 0) audit(AUDIT_RESP_NOT, port);
if (("index" >!< res) || ("roteros.dll" >!< res)) exit(0, "The service on port "+port+" is not a Winbox service.");

# Register and report the service.
register_service(port:port, proto:"mikrotik_winbox");
report = "";
# NOTE: Aligning the received packet manually before split 
foreach line (split(substr(res, 0x14), keep:FALSE))
{
  fields = split(line, sep:" ", keep:FALSE);
  if (
    fields[0] =~ "^[0-9]+$" &&
    fields[1] =~ "^[0-9]+$" &&
    fields[2] =~ "^[a-z][a-z0-9_]+\.dll$" &&
    fields[3] =~ "^[0-9]+\.[0-9.]+?(rc[0-9]+?)?$"
  )
  {
    if ('rc' >< fields[3]) fields[3] = preg_replace(pattern:"(rc[0-9]+?)", replace:"", string:fields[3]);
    report += '\n  Filename : ' + fields[2] +
              '\n  Version  : ' + fields[3] +
              '\n  Size     : ' + fields[1] +
              # '\n  Checksum : ' + fields[0] + 
              '\n';
    if (fields[2] == "roteros.dll") 
    {
      set_kb_item(name:"MikroTik/Winbox/" + port + "/Version", value:fields[3]);
    }
  }
}

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

