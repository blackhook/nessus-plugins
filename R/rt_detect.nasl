#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43004);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Request Tracker Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl-based support ticketing
application.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running the Best Practical Solutions Request
Tracker (RT), an open source support ticket application written in
Perl.");
  script_set_attribute(attribute:"see_also", value:"https://bestpractical.com/request-tracker");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app  = 'RT';
port = get_http_port(default:80);
installed = FALSE;

# The readme gives instructions for serving RT out of the root dir
if (thorough_tests) dirs = list_uniq(make_list('', '/rt', cgi_dirs()));
else dirs = make_list(cgi_dirs());

pattern = 'RT ([0-9.]+) Copyright [0-9-]+ <a href="http://www.bestpractical.com';
login_page = '/index.html';

foreach dir (dirs)
{
  url = dir + login_page;
  res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

  match = eregmatch(string:res, pattern:pattern);

  if (empty_or_null(match)) continue;
  if(!empty_or_null(match[1])) ver = match[1];
  else ver = UNKNOWN_VER;

  register_install(
    vendor          : "Best Practical",
    product         : "RT",
    app_name        : app,
    path            : dir,
    port            : port,
    version         : ver,
    cpe             : "cpe:/a:bestpractical:rt",
    webapp          : TRUE
  );

  installed = TRUE;

  if (!thorough_tests) break;
}

if (installed) report_installs(app_name:app, port:port);
else audit(AUDIT_NOT_DETECT, app, port);
