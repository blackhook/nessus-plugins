#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16335);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"PHP-Fusion Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a content management system written
in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PHP-Fusion, a light-weight, open source
content management system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.php-fusion.co.uk/home.php");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php_fusion:php_fusion");
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

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);
installs = NULL;

if (thorough_tests) dirs = list_uniq(make_list("/fusion", "/php-files", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  r = http_send_recv3(
    method       : "GET",
    item         : dir + "/news.php",
    port         : port,
    exit_on_fail : TRUE
  );
  res = r[2];

  if (egrep(pattern:"Powered by.*PHP-Fusion", string:res))
  {
    pat = ".*PHP-Fusion.*v([0-9][.,][0-9.,]+) .* 20[0-9][0-9]-20[0-9][0-9]";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
    installs = add_install(
      installs : installs,
      dir      : dir,
      appname  : 'php_fusion',
      ver      : ver,
      port     : port,
      cpe     : "cpe:/a:php_fusion:php_fusion"
    );
    if (!thorough_tests) break;
  }
}
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "PHP-Fusion", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'PHP-Fusion',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
