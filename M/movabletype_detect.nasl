#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39537);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Movable Type Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a weblog publishing system written in
Perl.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Movable Type, a blog publishing system
written in Perl.");
  script_set_attribute(attribute:"see_also", value:"https://www.movabletype.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (thorough_tests)
  dirs = list_uniq(make_list("/mt", "/cgi-bin/mt", "/blog", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

installs = NULL;
foreach dir (dirs)
{
  # If an install needs to be updated, /mt.cgi redirects to /mt-update.cgi.
  # Specifying the logout mode seems to prevent this.
  url = dir + '/mt.cgi?__mode=logout';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

  if (
    ('<title>MOVABLE TYPE' >< res[2]) ||	        # MT version 2
    ('mt.cgi"><img alt="Movable Type"' >< res[2]) ||    # MT version 3
    ('Movable Type</title>' >< res[2])                  # MT version 4
  )
  {
    pattern = '/mt\\.js\\?v=([0-9.]+)"\\>\\</script\\>';
    match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);

    # Version 2.x / 3.x
    pattern2 = '\\<b\\>Version (.+)\\</b\\>';
    match2 =  eregmatch(string:res[2], pattern:pattern2, icase:TRUE);

    if (match) ver = match[1];
    else if (match2) ver = match2[1];
    else ver = UNKNOWN_VER;

    installs = add_install(
      installs:installs,
      dir:dir,
      ver:ver,
      appname:'movabletype',
      port:port,
      cpe: "cpe:/a:sixapart:movable_type"
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Movable Type", port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Movable Type',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
