#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18054);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Serendipity Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a blog application written in PHP.");
  script_set_attribute(attribute:"description", value:
"Serendipity, a PHP-based blog application, is running on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"https://docs.s9y.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:s9y:serendipity");
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

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

function getmatch(pattern, response)
{
  local_var matches, match, ver;
  matches = pgrep(pattern:pattern, string:response, icase:TRUE);
  if(matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = pregmatch(pattern:pattern, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }
  return ver;
}

port = get_http_port(default:80, php:TRUE);

# Search for Serendipity.
installs = make_array();

if (thorough_tests) dirs = list_uniq(make_list("/serendipity", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  flag = 0;
  ver = UNKNOWN_VER;
  # Grab index.php.
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : strcat(dir, "/index.php"),
    exit_on_fail : TRUE
  );

  # Try to identify the version number from the Powered-By meta tag.
  if ('<meta name="Powered-By" content="Serendipity v' >< res[2])
  {
    flag = 1;
    pat =  'meta name="Powered-By" content="Serendipity v\\.([^"]+)" />';
    ver = getmatch(pattern:pat, response:res[2]);
  }
  # Identify version from the generator tag
  else if ('<meta name="generator" content="Serendipity v' >< res[2])
  {
    flag = 1;
    pat = '<meta name="generator" content="Serendipity v\\.([^"]+)"';
    ver = getmatch(pattern:pat, response:res[2]);
  }

    # Mark it as "unknown" if version isn't set
  if (flag == 1)
  {
    if (isnull(ver)) ver = UNKNOWN_VER;

    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'serendipity',
      ver      : ver,
      port     :port,
      cpe     : "cpe:/a:s9y:serendipity"
      );
  }

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
}
if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, "Serendipity");

report = get_install_report(
  display_name : 'Serendipity',
  installs     : installs,
  port         : port
);
security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

