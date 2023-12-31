#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22447);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");
  script_xref(name:"IAVA", value:"0001-A-0536");

  script_name(english:"IBM DB2 JDBC Applet Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"There is an IBM DB2 JDBC Applet Server listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an IBM DB2 JDBC Applet Server. DB2 is a
commercial database from IBM, and the JDBC Applet Server is used by
Java apps and applets to communicate with a DB2 server using the type
3 (a.k.a 'net') driver. 

Note that use of this driver has been deprecated since DB2 V8.1.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/analytics/us/en/db2/");
  script_set_attribute(attribute:"solution", value:
"Stop this service if it is no longer needed or limit incoming traffic
to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 6789);

  exit(0);
}

include("byte_func.inc");
include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(6789);
  if (!port) exit(0);
}
else port = 6789;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

function add_nulls(str)
{
  local_var i, res;

  res = NULL;
  for (i=0; i<strlen(str); i++)
    res += raw_string(0x00) + str[i];
  return res;
}

# Try to connect to a database.
db = string("nessus" + unixtime());
user = SCRIPT_NAME;
pass = "sesame";
lang = "en_US";
build = "s060120";

dsn = string("DSN=", db, ";UID=", user, ";PWD=", pass);
req = 
  "ValidDb2jdTokenFromTheClientSide" +
  mkword(0x01) +
  mkdword(strlen(dsn+lang+build)*2+30) +
  mkword(0x01) +
  mkword(0x02) +
  mkword(0x00) +
  mkdword(strlen(dsn)) + add_nulls(str:dsn) +
  mkword(0x05) + 
  mkdword(strlen(lang)) + add_nulls(str:lang) +
  mkdword(strlen(build)) + add_nulls(str:build) +
  mkdword(0xc8) +
  mkword(0x00) +
  mkword(0x00) +
  mkword(0x00);
send(socket:soc, data:req);
res = recv(socket:soc, length:2048);
close(soc);

# If the first word is the packet length
if (strlen(res) > 4 && getdword(blob:res, pos:0) == strlen(res) - 4)
{
  # It's a JDBC Applet Server if...
  rc = getdword(blob:res, pos:4);
  if (
    # there was a mismatch in the build or..
    (strlen(res) == 8 && rc == 0xffffff91) ||
    (
      # the build was right and the return code is either...
      (strlen(res) > 12 + strlen(build*2)) && add_nulls(str:build) >< res &&
      (
        # a login success or
        rc == 0 ||
        # a login failure
        rc == -1
      )
    )
  )
  {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"db2_jd");

    security_note(port);
  }
}
