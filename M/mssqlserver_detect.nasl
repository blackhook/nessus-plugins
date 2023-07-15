#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10144);
  script_version("1.61");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");
  script_xref(name:"IAVT", value:"0001-T-0800");

  script_name(english:"Microsoft SQL Server TCP/IP Listener Detection");

  script_set_attribute(attribute:"synopsis", value:
"A database server is listening on the remote port.");
  script_set_attribute(attribute:"description", value:
"The remote host is running MSSQL, a database server from Microsoft. It
is possible to extract the version number of the remote installation
from the server pre-login response.");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the database to allowed IPs only.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 1999-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "find_service2.nasl", "mssql_ping.nasl");
  script_require_ports("Services/unknown", "mssql/possible_port", 1433);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("spad_log_func.inc");

var report = '';
var app = "Microsoft SQL Server";
var service = "mssql";
var cpe = "cpe:/a:microsoft:sql_server";

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  unk_ports = get_kb_list("Services/unknown");
  if(! isnull(unk_ports)) unk_ports = make_list(unk_ports);

  ports = add_port_in_list(list:unk_ports, port:1433);
}
else ports = make_list(1433);


# Also test any ports we identified via a "Ping" request in mssql_ping.nasl.
var port;
possible_ports = get_kb_list("mssql/possible_port");
if (!isnull(possible_ports))
{
  foreach port (make_list(possible_ports))
    ports = add_port_in_list(list:ports, port:port);
}

# Add any ports specified in a mssql credential
var idx = 0;
var key = "Database";
var dbtype = get_kb_item(key + "/type");
port = get_kb_item(key + "/Port");
while(!isnull(dbtype))
{
  if(dbtype == 1)
    ports = add_port_in_list(list:ports, port:port);

  idx += 1;
  key = "Database/" + idx;
  dbtype = get_kb_item(key + "/type");
  port = get_kb_item(key + "/Port");
}

port = branch(ports);
# No idea why, but in testing branch returned some ports as 'data' type instead of 'int', causing errors later
# This is just to make sure it's always an integer
port = int(port);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

data =
  mkbyte(0)    + # Type: VERSION
  mkword(0x1A) + # Offset
  mkword(0x06) + # Length

  mkbyte(1)    + # Type: ENCRYPTION
  mkword(0x20) + # Offset
  mkword(0x01) + # Length

  mkbyte(2)    + # Type: INSOPT
  mkword(0x21) + # Offset
  mkword(0x01) + # Length

  mkbyte(3)    + # Type: THREADID
  mkword(0x22) + # Offset
  mkword(0x04) + # Length

  mkbyte(4)    + # Type: MARS
  mkword(0x26) + # Offset
  mkword(0x01) + # Length

  mkbyte(0xFF) + # Type: TERMINATOR

  # UL_VERSION
  mkbyte(12)   +
  mkbyte(0)    +
  mkword(0)    +

  # UL_SUBBUILD
  mkword(0)    +

  # B_FENCRYPTION
  mkbyte(0)    +

  # B_INSTVALIDITY
  mkbyte(0)    +

  # UL_THREADID
  mkdword(0)   +

  # B_MARS
  mkbyte(0);
len = strlen(data);

req =
  mkbyte(18)      + # Type: Pre-Login Msg
  mkbyte(1)       + # Status: EOM
  mkword(len + 8) + # Length: data+header length
  mkword(0)       + # SPID
  mkbyte(0)       + # PacketID
  mkbyte(0)       + # Window (not used)
  data;

spad_log(message:'sending ' + obj_rep(req));
send(socket:soc, data:req);
buf = recv(socket:soc, length:4096);
len = strlen(buf);

if (len) spad_log(message:'target returned ' + obj_rep(buf));

if (len < 20)
  exit(0, "The service listening on port " + port + " responded with a message too short to be parsed.");

code = getbyte(blob:buf, pos:0);
if (code != 4)
  exit(0, "The service listening on port " + port + " responded with a message of the wrong type.");

plen = getword(blob:buf, pos:2);
if (plen != len)
  exit(0, "The service listening on port " + port + " responded with a message containing an incorrect packet length field.");

encryption = version = NULL;

# Parse first option header.
pos = 8;
while(pos < strlen(buf))
{
  type = getbyte(blob:buf, pos:pos);
  off  = getword(blob:buf, pos:pos + 1);
  dlen = getword(blob:buf, pos:pos + 3);
  pos += 5;

  if(type == 0xFF) break; # TERMINATOR
  if(off == 0) break;

  if(type == 0x00) # VERSION
  {
    if(dlen < 6 || (off + dlen + 8) > len)
      exit(0, "Error parsing version field for service on port " + port + ".");
    off += 8;
    v = make_list(
      getbyte(blob:buf, pos:off),
      getbyte(blob:buf, pos:off+1),
      getword(blob:buf, pos:off+2),
      getword(blob:buf, pos:off+4));
    version = join(v, sep:".");
  }
  else if(type == 0x01) # ENCRYPTION
  {
    if(dlen < 1 || (off + dlen + 8) > len)
      exit(0, "Error parsing encryption field for service on port " + port + ".");
    off += 8;
    encryption = getbyte(blob:buf, pos:off);
  }
}

if(encryption != 0x03) # ENCRYPT_REQ
{
  report += 'The remote MSSQL server accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
}

if(isnull(version))
  exit(1, "Unable to parse version field for service on port " + port + ".");

spad_log(message:'Detected MSSQL version ' + version + ' on port ' + port);
set_kb_item(name:"MSSQL/" + port + "/Version", value:version);

register_service(port:port, proto:"mssql");

var instances = get_kb_list("MSSQL/" + port + "/InstanceName");
if(isnull(instances))
{
  # remote detection may have detected MSSQL version, but failed to detect instance name
  spad_log(message:'No SQL Server instances determined for port ' + port + ' on target.');
  instances = "Instance name not determined";  
}

instances = make_list(instances);

foreach(var instance in instances)
{
  if(empty_or_null(instance))
    continue;

  var extra;
  if (instance != "Instance name not determined")
    extra["InstanceName"] = instance;

  if(!empty_or_null(report))
    extra["Note"] = report;

  register_install(
    vendor   : "Microsoft",
    product  : "SQL Server",
    app_name : app,
    version  : version,
    port     : port,
    service  : strcat(service, "-", instance),
    cpe      : cpe,
    extra    : extra
  );
}

report_installs(app_name:app, port:port);
