#%NASL_MIN_LEVEL 70300
#
# Copyright (C) 2004 Tenable Network Security
#


include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(12115);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Unreal Tournament Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A game server appears to be running on the remote system.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Unreal Tournament 
Server. The Server is used to host Internet and Local Area 
Network (LAN) games.");
  script_set_attribute(attribute:"solution", value:
"Ensure that this sort of network gaming is in alignment
with Corporate and Security Policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:epicgames:unreal_tournament_2003");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


# start script
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!port) exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);

if (egrep(string:banner, pattern:"^Server: UnrealEngine UWeb Web Server Build")) security_note(port); 
