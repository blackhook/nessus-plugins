#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51142);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_name(english:"Openfire Admin Console Detection");
  script_summary(english:"Checks for the Openfire admin console login page");

  script_set_attribute(attribute:"synopsis", value:"An administration interface was detected on the remote web server.");
  script_set_attribute(attribute:"description", value:
"An Openfire admin console was detected on the remote host. Openfire is
a collaboration server based on the XMPP (Jabber) protocol.");
  script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/projects/openfire/index.jsp");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}


include('http.inc');
include('webapp_func.inc');
include('install_func.inc');

port = get_http_port(default:9090);
installs = NULL;

dir = '';
url = dir + '/login.jsp';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

var app_name = 'Openfire Console';

if ('<title>Openfire Admin Console</title>' >< res[2])
{
  pattern = 'Openfire, Version: ([0-9.]+)';
  match = pregmatch(string:res[2], pattern:pattern, icase:TRUE);
  if (match) ver = match[1];
  else ver = NULL;


  installs = add_install(
    installs:installs,
    dir:dir,
    ver:ver,
    appname:'openfire_console',
    port:port,
    cpe: "cpe:/a:igniterealtime:openfire"
  );

  register_install(
    app_name:app_name,
    webapp:TRUE,
    path:dir,
    port:port,
    version:ver,
    cpe:"cpe:/a:igniterealtime:openfire"
  );

}

if (isnull(installs)) exit(0, 'An Openfire admin console wasn\'t detected on port '+port+'.');

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Openfire Admin Console',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
