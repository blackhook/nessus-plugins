#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63562);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Nagios Core Detection");

  script_set_attribute(attribute:"synopsis", value:
"A monitoring service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Nagios Core was detected on the remote host. 
Nagios Core is a web-based application for monitoring network devices.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.org/projects/nagios-core/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = "Nagios Core";
kb_appname = "nagios_core";

# Loop through various directories.
if (thorough_tests) dirs = make_list("/nagios", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = NULL;
foreach dir (list_uniq(dirs))
{
  res = http_send_recv3(
    method:'GET',
    item:dir + '/main.php',
    port:port,
    exit_on_fail:TRUE
  );

  if (
    "<title>Nagios Core</title>" >< res[2] && 
    "<h2>Get Started</h2>" >< res[2]
  )
  {
    version = UNKNOWN_VER;
    item = eregmatch(pattern:'\"version\">[ ]*Version[ ]+([^<]+)', string:res[2]);  
    if (!isnull(item[1])) version = item[1];
    
    # Register install
    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir,
      appname:kb_appname,
      port:port,
      cpe: "cpe:/a:nagios:nagios"
    );
    if (!thorough_tests) break;
  }
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : appname,
    item         : '/' 
  );
  security_note(port:port, extra:report);
}
else security_note(port);
