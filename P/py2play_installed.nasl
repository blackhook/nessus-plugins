#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description) {
  script_id(19759);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Py2Play Game Engine Detection");

  script_set_attribute(attribute:"synopsis", value:
"A game server has been detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Py2Play, a peer-to-peer network game engine. Make
sure that this service has been installed in accordance with your security
policy.");
  script_set_attribute(attribute:"see_also", value:"http://home.gna.org/oomadness/en/index.html");
  script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:py2play:py2play");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/unknown", 36079);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(36079);
  if (!port) exit(0);
}
else port = 36079;
if (!get_port_state(port)) exit(0);


# Add a player.
soc = open_sock_tcp(port);
if (!soc) exit(0);

c = "+";
send(socket:soc, data:c);
player = string(SCRIPT_NAME, "_", unixtime());
c = string("S'", player, "'\np1\n.");
send(socket:soc, data:c);
close(soc);


# Now list players.
soc = open_sock_tcp(port);
if (!soc) exit(0);

c = "p";
send(socket:soc, data:c);
s = recv(socket:soc, length:1024);
if (!strlen(s)) exit(0);


# There's a problem if...
if (
  # it looks like a Python pickle and...
  (ord(s[0]) == 0x80 && ord(s[1]) == 0x02) &&
  # our player was added.
  player >< s
) {
  security_note(port);

  register_service(port:port, ipproto:"tcp", proto:"py2play");
}
