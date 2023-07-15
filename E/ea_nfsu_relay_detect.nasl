#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(52482);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"EA Need For Speed Underground Detection");

  script_set_attribute(attribute:"synopsis", value:
"A game server has been detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a client relay service for Electronic Arts
Need For Speed Underground or a clone of that game.

This is a kind of port mapper in that the service provides dynamic
port numbers to client software.");
  script_set_attribute(attribute:"see_also", value:"https://www.nfsplanet.com/en");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Need_for_speed_underground");
  script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ea:need_for_speed");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/nfsu-relay", 10800);

  exit(0);
}

include("global_settings.inc");
include('install_func.inc');
include('misc_func.inc');

app_name = "NFSU LAN Server";
port = get_service(svc: "nfsu-relay", default: 10800, exit_on_fail: 1);
proto = "nfsu-relay";
cpe = "x-cpe:/a:ea:need_for_speed";

if (service_is_unknown(port: port))
{
  if (silent_service(port)) exit(0, "The service on port "+port+" is 'silent'.");
  
  resp = get_unknown_banner(port: port);

  if (preg(string: resp, pattern: "^\d\|\d\|\d+\|(?:win32|win64|\*nix|nix)\|\d+\.\d+\.\d+\|.*$"))
    register_service(port: port, proto: proto);
  else
    exit(0, "The service on port "+port+" is not an NFSU relay.");
}
else if (!verify_service(port: port, proto: proto))
  exit(0, "The service on port "+port+" is not an NFSU relay.");

if(!isnull(resp))
{
  resp = split(resp, sep: '|', keep: FALSE);
  version = split(resp[4], sep: ' ', keep: FALSE);
  version = version[0];
}

register_install(
  vendor   : "EA",
  product  : "Need for Speed",
  app_name : app_name,
  version  : version,
  port     : port,
  service  : proto,
  cpe      : cpe
);

report_installs(app_name: app_name, port: port);
