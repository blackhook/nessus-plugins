#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61995);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/25");

  script_name(english:"EMail Security Virtual Appliance Detection");
  script_summary(english:"Looks for learned.html page");

  script_set_attribute(attribute:"synopsis", value:
"An email security appliance was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"EMail Security Virtual Appliance, an email filtering and security
application, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.esvacommunity.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:libraesva:esva");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

url = '/learned.html';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  'ESVA - Spam reported' >!< res[2] ||
  '<TH>Message reported as Spam</TH>' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_INST, 'EMail Security Virtual Appliance', port);

installs = add_install(
  dir:'/',
  appname:'esva',
  port:port,
  cpe: "x-cpe:/a:libraesva:esva"
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'EMail Security Virtual Appliance',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
