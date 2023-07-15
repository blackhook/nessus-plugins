#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43157);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"phpShop Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a shopping cart application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpShop, a web-based shopping cart
application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpshop.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpshop:phpshop");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php: 1);

if (thorough_tests)
  dirs = list_uniq(make_list(cgi_dirs(), '/phpshop', '/shop', '/store'));
else
  dirs = cgi_dirs();

pattern = 'Powered by <a href="http://www.phpshop.org"[^<]*</a> ([0-9.]+)';
installs = NULL;
login_page = '/index.php';

foreach dir (dirs)
{
  url = dir + login_page;
  res = http_get_cache(item:url, port:port, exit_on_fail: 1);

  match = eregmatch(string:res, pattern:pattern);
  if (match)
  {
    ver = match[1];
    installs = add_install(
      appname:'phpshop',
      installs:installs,
      dir:dir,
      port:port,
      ver:ver,
      cpe: "cpe:/a:phpshop:phpshop"
    );
    if (!thorough_tests) break;
  }
}

if (isnull(installs)) exit(0, "phpShop wasn't detected on port "+port+".");

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'phpShop',
    installs:installs,
    port:port,
    item:login_page
  );
  security_note(port:port, extra:report);
}
else security_note(port);
