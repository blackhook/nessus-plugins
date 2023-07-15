#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(22528);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Pervasive PSQL / Btrieve Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A Pervasive PSQL / Btrieve server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Pervasive PSQL / Btrieve, a commercial
database engine.");
  # http://web.archive.org/web/20061019021227/http://www.pervasive.com/psql/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c579948");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:actian:pervasive_psql");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 3351);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(3351);
  if (!port) exit(0);
}
else port = 3351;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to authenticate.
user = SCRIPT_NAME;
pass = string(unixtime());
zero = raw_string(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
req = 
  mkdword(48) +
  mkword(1) +
  user + crap(data:zero, length:20-strlen(user)) +
  pass + crap(data:zero, length:20-strlen(pass)) +
  mkword(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# It's Pervasive PSQL / Btrieve if...
if (
  # the word at the first byte is the packet length and...
  (strlen(res) > 26 && getdword(blob:res, pos:0) == strlen(res)) &&
  # it's followed by a 1 and...
  getword(blob:res, pos:4) == 1 &&
  # it ends with a 0 word.
  substr(res, strlen(res)-2) == mkword(0)
) 
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"btrieve");

  security_note(port);
}
