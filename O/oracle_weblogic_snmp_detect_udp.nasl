#
# (C) Tenable Network Security, Inc.
#

# snmpwalk -v2c -c public tcp:172.26.38.88:7001 .1.3.6.1.4.1.140.625.360.1.65
# snmpwalk -v2c -c public 172.26.24.85 .1.3.6.1.4.1.140.625.360.1.65 
# snmpwalk -v2c -c public 172.26.38.11 .1.3.6.1.4.1.140.625.360.1.65

include("compat.inc");

if (description)
{
  script_id(109431);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_name(english:"Oracle WebLogic SNMP Detection (UDP)");
  script_summary(english:"Checks for Oracle WebLogic using SNMP (UDP)");

  script_set_attribute(attribute:"synopsis", value:
"An SNMP-based configuration utility was discovered on the remote
UDP port.");
  script_set_attribute(attribute:"description", value:
"Oracle WebLogic, a Java EE application server, was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://docs.oracle.com/cd/E13222_01/wls/docs81/ConsoleHelp/snmp.html");  
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_udp_ports(161, "SNMP/port");
  script_dependencies("snmp_settings.nasl", "find_service2.nasl");
  exit(0);
}

include("snmp_func.inc");

var appname = "Oracle/WebLogic";

# grab the user defined snmp
var snmp_ports = make_list(161);
if (!empty_or_null(get_kb_list("SNMP/port")))
{
  snmp_ports = make_list(snmp_ports, get_kb_list("SNMP/port"));
}

# remove dups and fork
snmp_ports = list_uniq(snmp_ports);
var port = branch(snmp_ports);

if (!get_udp_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port, "UDP");
}

# Get the global community string for snmp
var community = get_kb_item("SNMP/community");
if (empty_or_null(community))
{
  community = "public";
}

var s = open_sock_udp(port);
if (!s)
{
  audit(AUDIT_SOCK_FAIL, port, "UDP");
}

var oid = "1.3.6.1.4.1.140.625.360.1.65";
var snmp_resp = snmp_request_next(socket:s, community:community, oid:oid);
close(s);

if (empty_or_null(snmp_resp))
{
  audit(AUDIT_RESP_NOT, port, oid);
}

if ("WebLogic Server" >!< snmp_resp[1])
{
  audit(AUDIT_RESP_BAD, port, oid);
}

register_service(port:port, ipproto:"udp", proto:"snmp");
set_kb_item(name:"snmp/weblogic/ports", value:port);
replace_kb_item(name:"snmp/weblogic/" + port +"/sysDesc", value:snmp_resp[1]);

var retlines = make_list();
var patches = "";
retlines = split(snmp_resp[1]);
var max = max_index( retlines );

var version = NULL;
for (var i = 0; i < max; i++)
{  
  if ("Patch" >!< retlines[i] && "patch" >!< retlines[i])
  {
    version = pregmatch(pattern:"WebLogic Server ([0-9\.]+) ", string:retlines[i]);
    if (!empty_or_null(version))
    {
      version = version[1];
      replace_kb_item(name:"snmp/weblogic/" + port + "/version", value:version);
    }
  }
  else
  {
    patches = patches + '   ' + retlines[i];	    
  }
}

var extra = 'The Oracle WebLogic Server has the following properties :' +
  '\n' +
  '\n Port                       : ' + port + '\n' +
  ' Protocol                   : TCP';

if (!empty_or_null(version))
{
  extra += '\n Version                    : ' + version;
}
extra += '\n';

if (patches != "")
{
  extra = extra + ' Patches                    :\n' + patches;
  set_kb_item(name:"snmp/weblogic/" + port + "/patches", value:patches);
}

security_report_v4(severity:SECURITY_NOTE, port:port, extra:extra);
