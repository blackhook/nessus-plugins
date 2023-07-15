#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(31464);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"KiSS PC-Link Server Detection (TCP)");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia streaming service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a PC-Link Server, used for streaming videos,
music, and pictures to a KiSS player.");
  script_set_attribute(attribute:"see_also", value:"http://kissdx.vidartysse.net/");
  # http://www.famille-kahn.com/kissdxmanual/Kissdx_develop_manual:_Network_architecture
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67272d9e");
  script_set_attribute(attribute:"solution", value:
"Make sure use of this software is in accordance with your corporate
security policy.  If this service is unwanted or not needed, disable
it or filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:pclink:kissdx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 8000);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(8000);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 8000;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to list some content.
req = 'LIST VIDEO||\r\n\r\n';
send(socket:soc, data:req);

res = "";
while (line = recv_line(socket:soc, length:4096))
{
  # Validate response lines.
  if (
    line == 'EOL\n' ||
    line == '00\n' ||
    line =~ '^.+\\|.+\\|[01]\\|?\n$'
  )
  {
    res += line;
    if (stridx(line, 'EOL\n') == 0) break;
  }
  else
  {
    res = "";
    break;
  }
}
close(soc);
if (strlen(res) == 0) exit(0);


# Register and report the service.
register_service(port:port, proto:"kiss_server");

if (report_verbosity && egrep(pattern:'^.+\\|.+\\|[01]\\|?$', string:res))
{
  listing = str_replace(find:'\n', replace:'\n  ', string:res);

  report = string(
    "\n",
    "The remote server sent the following in response to a request for a\n",
    "list of videos files :\n",
    "\n",
    "  ", listing
  );
  security_note(port:port, extra:report);
}
else security_note(port);
