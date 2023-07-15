#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");


if (description)
{
  script_id(43831);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_name(english:"Altiris Deployment Solution Server DB Manager Detection");

  script_set_attribute(attribute:"synopsis", value:
"A database management service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is running the DB Manager component of Altiris
Deployment Solution.  This service is used to remotely manage the
Altiris database.");
  script_set_attribute(attribute:"see_also", value:"http://www.altiris.com/Products/DeploymentSolution.aspx");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:altiris_deployment_solution");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 505);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(505);
  if (!port) 
    exit(0, "No unknown port.");
  if (!silent_service(port))
    exit(0, "The service on port "+port+" is not silent.");
}
else port = 505;

if (known_service(port:port))
  exit(0, "The service on port "+port+" has already been identified.");
if (!get_tcp_port_state(port))
  exit(0, "Port "+port+" is not open.");

soc = open_sock_tcp(port);
if (!soc)
  exit(1, "Failed to open a socket on port "+port+".");

cmd = 'CreateSession';
req = 'Request='+cmd+'\n'+mkbyte(0);
send(socket:soc, data:req);

res = recv(socket:soc, length:19+strlen(cmd)*2);
close(soc);
if (isnull(res)) exit(1, "The service on port "+port+" did not respond.");

if ('Processing=' + cmd >< res && 'Reply=' + cmd >< res)
{
  # Register and report the service
  register_service(port:port, ipproto:"tcp", proto:"dbmanager");
  security_note(port);
}
else exit(0, "Altiris DB Manager doesn't appear to be running on port "+port+".");
