#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(12259);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Subversion Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"A version control software is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Subversion server.  Subversion
is a software product which is similar to CVS in that it manages
file revisions and can be accessed across a network by multiple
clients.");
  script_set_attribute(attribute:"see_also", value:"http://subversion.tigris.org");
  script_set_attribute(attribute:"solution", value:
"If this server is not needed, disable it or filter incoming traffic
to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports(3690, "Services/unknown");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests &&
  ! get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(3690);
  if (!port) exit(0);
  if (!silent_service(port)) exit(0);
}
else 
{
  port = get_kb_item("Services/subversion");
  if ( ! port ) port = 3690;
}

if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);

# start check

soc = open_sock_tcp(port);
if (!soc)
        exit(0);

r = recv_line(socket:soc, length:1024);

if (! r)
	exit(0);

if (("success ( 1 2" >< r) || 
    ("success ( 2 2" >< r))
	security_note(port);

close(soc);
exit(0);
