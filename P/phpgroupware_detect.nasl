#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(15982);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"phpGroupWare Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a groupware system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PHPGroupWare, a groupware system written in
PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpgroupware.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgroupware:phpgroupware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80,php:TRUE);
# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpgroupware", "/phpgw",cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;

foreach dir (dirs)
{
  version = NULL;
  w = http_send_recv3(method: "GET", item:string(dir, "/login.php"), port:port,exit_on_fail:TRUE);
  r = w[2];

  if ("phpGroupWare http://www.phpgroupware.org" >< r)
  {
    if ( dir == "" ) dir = "/";

    version = egrep(pattern:".*phpGroupWare ([0-9.]+).*", string:r);
    if ( version )
      version = ereg_replace(pattern:".*phpGroupWare ([0-9.]+).*", string:version, replace:"\1");

    if(version =~ "^[0-9.]+$")
    {
      installs = add_install(
        appname  : "phpGroupWare",
        installs : installs,
        port     : port,
        dir      : dir,
        ver     : version,
        cpe     : "cpe:/a:phpgroupware:phpgroupware"
      );
    }
    else
    {
      installs = add_install(
        appname  : "phpGroupWare",
        installs : installs,
        port     : port,
        dir      : dir,
        cpe      : "cpe:/a:phpgroupware:phpgroupware"
      );
    }
  }
}

if (isnull(installs)) exit(0, "phpGroupWare was not detected on the web server on port "+port+".");

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "phpGroupWare"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
