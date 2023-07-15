#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46856);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"PRTG Traffic Grapher Detection");
  script_summary(english:"Checks for PRTG Traffic Grapher");

  script_set_attribute(attribute:"synopsis", value:
"A network traffic monitoring application is hosted on the remote web
server.");

  script_set_attribute(attribute:"description", value:
"PRTG Traffic Grapher, a web-based tool for displaying network usage
data, is hosted on the remote web server.");

  script_set_attribute(attribute:"see_also", value:"https://www.paessler.com/prtg");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paessler:prtg_traffic_grapher");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/login.htm", port:port, exit_on_fail:TRUE);

installs = NULL;
version = NULL;
if ('<A title="PRTG Traffic Grapher' >< res[2])
{
  pattern = 'href="https://www.paessler.com/prtg\\?ref=PRTGcopy">PRTG Traffic Grapher V([0-9\\.]+)';
  matches = eregmatch(string:res[2], pattern:pattern);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pattern, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  installs = add_install(
    installs:installs,
    ver:version,
    dir:'',
    appname:'prtg_traffic_grapher',
    port:port,
    cpe: "cpe:/a:paessler:prtg_traffic_grapher"
  );
}

if (isnull(installs)) exit(0, "PRTG Traffic Grapher wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'PRTG Traffic Grapher',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port:port);
