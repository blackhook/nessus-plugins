#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(10731);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"healthd Detection");

  script_set_attribute(attribute:"synopsis", value:
"healthd is listening on the remote port");
  script_set_attribute(attribute:"description", value:
"The remote host is running healthd, a daemon which uses the sensors of
the remote host to report the temperature of various of its
components. 

It is recommended to not let anyone connect to this port.");
  script_set_attribute(attribute:"see_also", value:"http://healthd.thehousleys.net/");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port, or disable this service if you
do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jim_housley:healthd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/healthd", 1281);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include('misc_func.inc');

port = get_kb_item("Services/healthd");
if ( ! port ) port = 1281;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'CFG Nessus\r\n');
r = recv_line(socket:soc, length:255);
if ( r && r =~ "^ERROR: Unknown class" )
{
 register_service(proto:"healthd", port:port);
 security_note(port);
}
 
