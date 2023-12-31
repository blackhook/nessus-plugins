#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
# 

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(19608);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Tetrinet server detection");

  script_set_attribute(attribute:"synopsis", value:
"A game server has been detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host runs a Tetrinet game server on this port.  Make sure
the use of this software is done in accordance to your security
policy.");
  script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tetrix:tetrinet");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 31457);

  exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");

c = '00469F2CAA22A72F9BC80DB3E766E7286C968E8B8FF212\xff';
if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
 {
  port = get_unknown_svc(31457);
  if ( ! port ) exit(0);
 }
else
 port = 31457;
if (! get_port_state(port) || ! service_is_unknown(port: port)) exit(0);

s = open_sock_tcp(port);
if (!s) exit(0);

send(socket: s, data:c);
b = recv(socket: s, length: 1024);
if ( ! b ) exit(0);
if (match(string: b, pattern: 'winlist *'))
{
 security_note(port: port);
 register_service(port: port, proto: 'tetrinet');
}
