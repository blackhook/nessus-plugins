#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");


if (description)
{
  script_id(42345);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"BuildBot WebStatus Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a build status application written in
Python.");
  script_set_attribute(attribute:"description", value:
"The remote host is running BuildBot, a continuous integration tool
written in Python.  BuildBot comes with WebStatus, a web interface
that provides the status of all builds being maintained by BuildBot.");
  script_set_attribute(attribute:"see_also", value:"http://buildbot.net/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:buildbot:buildbot");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8010, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


# 8010 is the default port for version 0.7.11. Their docs make mention of
# 8080 as well
port = get_http_port(default:8010);

# WebStatus runs in a self-contained web server using the Twisted libraries.
# Unless we're paranoid, make sure the remote web server looks like Twisted
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "No HTTP banner on port "+port);
  if ('TwistedWeb' >!< banner)
    exit(0, "The web server on port "+port+" doesn't appear to be TwistedWeb.");}

# Since WebStatus runs in a self contained web server, it's very likely
# we'll detect it in the root dir
dirs = list_uniq(make_list('', cgi_dirs()));

installs = NULL;

foreach dir (dirs)
{
  url = string(dir, '/about');
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  # If we don't see the buildbot header, move to the next dir
  if ('<h1>Welcome to the Buildbot</h1>' >!< res[2]) continue;

  # Otherwise, try to get the version number.  There isn't a 'WebStatus' version
  # separate from the Buildbot version - it all falls under the same package.
  match = eregmatch(string:res[2], pattern:'<li>Buildbot: ([^<]+)</li>');
  if (match) ver = match[1];
  else ver = NULL;

  installs = add_install(
    appname:'buildbot_webstatus',
    installs:installs,
    dir:dir,
    ver:ver,
    port:port,
    cpe: "cpe:/a:buildbot:buildbot"
  );

  # Only check for multiple installs if the "Perform thorough tests" setting is enabled
  if (!thorough_tests) break;
}

if (isnull(installs))
  exit(0, "Buildbot WebStatus was not detected on the web server on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Buildbot WebStatus',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);


