#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(32133);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Symantec pcAnywhere Access Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running Symantec pcAnywhere Access Server.");
  script_set_attribute(attribute:"description", value:
"Symantec pcAnywhere Access Server supports managing multiple
pcAnywhere servers thorugh a centralized access point.");
  script_set_attribute(attribute:"solution", value:
"Disable pcAnywhere if you do not use it, and filter incoming traffic
to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pcanywhere");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("PC_anywhere_tcp.nasl");
  script_require_ports("Services/unknown", 5631);

  exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");

if (thorough_tests)
{
  port = get_unknown_svc(5631);
  if (!port) exit(0);
}
else port = 5631;
if (known_service(port:port)) exit(0);
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

data =  mkdword(0);

send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);
if (!buf) exit(0);

if ("1b593200010342000001001" >< hexstr(buf) ||
   "The Symantec pcAnywhere Access Server does not support" >< buf ||
   (port == 5631 && ' <Enter>...\r\n' >< buf ) )
{
 register_service (port:port, proto:"pcanywhereaccessserver");
 security_note(port);
}
