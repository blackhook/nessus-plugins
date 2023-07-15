#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17349);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Phorum Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bulletin board system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Phorum, a web-based message board written
in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.phorum.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phorum:phorum");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Search for Phorum.
installs = make_array();
foreach dir (cgi_dirs()) {
  # nb: while the version number isn't always found in 'index.php',
  #     it does seem to be in 'admin.php'.
  r = http_send_recv3(method:"GET", item:string(dir, "/admin.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it's Phorum.
  if ("title>Phorum Admin<" >< res) {
    if (dir == "") dir = "/";

    # Try to identify the version number from the page itself.
    pat = "Phorum Admin.+version ([^<]+)<";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    ver = NULL;
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }
    # If unsuccessful, try to grab it from the changelog.
    if (isnull(ver)) {
      r = http_send_recv3(method:"GET", item:dir + "/docs/CHANGES", port:port);
      if (isnull(r)) exit(1, "the web server did not answer");
      res = r[1];

      pat = "^Release: phorum\.(.+)";
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          ver = eregmatch(pattern:pat, string:match, icase:TRUE);
          if (!isnull(ver)) {
            ver = ver[1];
            break;
          }
        }
      }
    }

    if (isnull(ver)) ver = UNKNOWN_VER;
    installs = add_install(
      appname  : "phorum",
      installs : installs,
      dir      : dir,
      ver      : ver,
      port     : port,
      cpe     : "cpe:/a:phorum:phorum"
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (max_index(keys(installs)) > 0 && !thorough_tests) break;
  }
}

if (max_index(keys(installs)) > 0)
{
  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name : "Phorum",
      installs     : installs,
      port         : port
    );
    security_note(port:port, extra: report);
  }
  else security_note(port);
} else exit(0, "No installs of Phorum frontend were found on port "+port+".");
