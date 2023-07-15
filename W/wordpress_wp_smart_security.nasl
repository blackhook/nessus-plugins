#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105108);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:19");


  script_name(english:"WP Smart Security Plugin for WordPress PHP Object Injection");
  script_summary(english:"Checks for the vulnerable plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
 by a PHP object injection vulnerability.");

  script_set_attribute(attribute:"description", value:
"The WP Smart Security Plugin for WordPress is affected by a PHP
object injection vulnerability. This plugin is no longer maintained,
therefore all known versions are impacted. This vulnerability could
allow a remote, unauthenticated attacker to inject PHP objects and
execute arbitrary code.

Note that Nessus has not tested for these issues but has instead
relied only on the plugins self-reported version number.");

  # https://www.pluginvulnerabilities.com/2017/08/29/php-object-injection-vulnerability-in-wp-smart-security/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ea01d3a");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/wp-smart-security/");
  script_set_attribute(attribute:"solution", value:"Disable and remove the vulnerable plugin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
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
include("url_func.inc");


app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);
plugin_url = install_url + 'wp-content/plugins/wp-smart-security/';

plugin = 'WP Smart Security';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

# if not found as installed from kb, check for regex in plugin dir
if (!installed)
{
  regexes[0] = make_list("bit51sorttable");
  checks[plugin_url + "lib/bitset.css"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}

# if still not found, audit as not installed
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");


if (installed)
{
  report =
    '\n WordPress URL  : ' + install_url +
    '\n Plugin URL     : ' + plugin_url +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
