#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101302);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/08 12:52:13");


  script_name(english:"WP Statistics Plugin for WordPress < 12.0.8 'functions.php' wp_statistics_searchengine_query() SQLi");
  script_summary(english:"Checks the WP Statistics plugin version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the WP
Statistics Plugin for WordPress running on the remote web server is
prior to 12.0.8 and user registration is enabled. It is, therefore,
affected by a SQL injection vulnerability due to improper sanitization
of user-supplied input to the wp_statistics_searchengine_query()
function in the functions.php script. An authenticated, remote
attacker can exploit this issue to inject or manipulate SQL queries in
the back-end database, resulting in the manipulation or disclosure of
arbitrary data.");
  # https://blog.sucuri.net/2017/06/sql-injection-vulnerability-wp-statistics.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd6629cd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Statistics Plugin for WordPress to version 12.0.8 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:app, port:port);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin     = "WP Statistics";
plugin_dir = "/wp-content/plugins/wp-statistics/";
plugin_url = build_url(port:port, qs:dir + plugin_dir);

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  checks[plugin_dir + "readme.txt"][0] = make_list('=== WP Statistics ===');
  checks[plugin_dir + "languages/default.mo"][0] = make_list('Project-Id-Version: *WP Statistics');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

version = NULL;

# Parse WP Statistics plugin version and compare
res = http_send_recv3(method:"GET", item:plugin_dir + 'readme.txt', port:port);
if (isnull(res) || '200 OK' >!< res[0] || isnull(res[2]))
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

match = pregmatch(pattern:"Stable tag: +([0-9.]+)", string:res[2], icase:TRUE);
if (isnull(match))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, plugin + " plugin included in the " + app + " install", plugin_url);  

version = match[1];
fix = "12.0.8";

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, plugin_url, plugin + " plugin", version);

# Check if user registration is enabled
if (report_paranoia < 2)
{
  res = http_send_recv3(method:"GET", item:"/wp-login.php?action=register", port:port, follow_redirect:1);
  if (isnull(res) || '200 OK' >!< res[0] || isnull(res[2]))
    exit(1, "Failed to determine if user registration is enabled. Note that this may be due to WordPress configuration requiring registration over HTTPS and this port is using HTTP.");
  
  if (
    "Registration Form</title>"   >!< res[2] ||
    ">Register For This Site</p>" >!< res[2]
  )
    audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, plugin_url, plugin + " plugin");
}


report =
  '\n  WordPress URL     : ' + install_url +
  '\n  Plugin URL        : ' + plugin_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
