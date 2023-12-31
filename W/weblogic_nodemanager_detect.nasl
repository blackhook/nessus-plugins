#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");


if (description)
{
  script_id(44315);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Oracle WebLogic Server Node Manager Detection");

  script_set_attribute(attribute:"synopsis", value:
"An administrative control service is listening on this port.");
  script_set_attribute(attribute:"description", value:
"The remote service is Node Manager, a utility included with Oracle
WebLogic Server and used to remotely start and stop Administration
Server and Managed Server instances.");
  script_set_attribute(attribute:"see_also", value:"https://docs.oracle.com/cd/E12840_01/wls/docs103/nodemgr/overview.html");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 5556);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(5556);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (silent_service(port)) exit(0, "The service listening on port "+port+" is silent.");
}
else port = 5556;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


# Send a 'HELLO'.
req = 'HELLO ' + SCRIPT_NAME;
send(socket:soc, data:req+'\n');
res = recv_line(socket:soc, length:1024);
if (strlen(res) == 0) audit(AUDIT_RESP_NOT, port);

res = chomp(res);
if (
  res =~ "\+OK Node [Mm]anager" &&
  ereg(pattern:"^\+OK Node [Mm]anager (v[0-9][^ ]+ )?started$", string:res)
)
{
  # Register and report the service.
  register_service(port:port, proto:"weblogic_nodemanager");

  info = "";
  if (report_verbosity > 0)
  {
    # Collect version info.
    version = "n/a";
    if ("+OK Node manager v" >< res)
    {
      version = strstr(res, "+OK Node manager v") - "+OK Node manager v";
      version = version - strstr(version, " started");
      if (version !~ "^[0-9][^ ]+$") version = "n/a";
    }
    else if ("+OK Node Manager v" >< res)
    {
      version = strstr(res, "+OK Node Manager v") - "+OK Node Manager v";
      version = version - strstr(version, " started");
      if (version !~ "^[0-9][^ ]+$") version = "n/a";
    }
    info += '  Version : ' + version + '\n';
  }

  if (info)
  {
    report = '\n' +
      'Nessus collected the following information from the remote service :\n' +
      '\n' +
      info;
    security_note(port:port, extra:report);
  }
  else security_note(port);

  # Be nice and disconnect cleanly.
  req = 'QUIT';
  send(socket:soc, data:req+'\n');
  res = recv_line(socket:soc, length:256);

  close(soc);
  exit(0);
}
else
{
  close(soc);
  exit(0, "The response from the service listening on port "+port+" does not look like Oracle WebLogic Server Node Manager.");
}
