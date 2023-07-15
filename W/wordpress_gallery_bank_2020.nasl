#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105258);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:20");


  script_name(english:"Gallery Bank Plugin for WordPress < 2.0.20 XSS");
  script_summary(english:"Checks the plugin / script version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple reflected cross-site
scripting vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Gallery Bank Plugin
for WordPress running on the remote web server is prior to 2.0.20.
It is, therefore, affected by multiple reflected cross-site scripting
vulnerabilities. 

A remote attacker can exploit these issues, via a specially crafted
request, to execute arbitrary code in a user's browser, within the
security context of the affected site.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/gallery-bank/");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/6985");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/6986");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/6987");
  script_set_attribute(attribute:"solution", value:
  "Upgrade the Gallery Bank Plugin for WordPress to version
  2.0.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");


  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("misc_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);
plugin_url = install_url + "wp-content/plugins/gallery-bank/";

plugin = 'Gallery Bank';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

# if not found as installed from kb, check for regex in plugin dir
if (!installed)
{
  # Check for the following string in the url indicated below
  regexes[0] = make_list("Gallery", "Lite");
  checks[plugin_url + "assets/css/frontend.css"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}

if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Get version from readme.txt
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + plugin_url + "readme.txt",
  exit_on_fail : TRUE
);

body = res[2];

if ("=== Gallery" >< body && "Gallery-Bank" >< body)
{
  # Using stable tag as changelog history disappears on 3.0.0
  match = pregmatch(pattern:"\bStable tag: ([0-9\.]+|$)", string:body);
  if (!empty_or_null(match)) version = match[1];
}
else
audit(AUDIT_UNKNOWN_WEB_APP_VER, plugin + " plugin included in the " + app + " install", plugin_url);

fix = '2.0.20';

# Compare version with fixed
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n WordPress URL     : ' + install_url +
    '\n Plugin URL        : ' + plugin_url +
    '\n Installed version : ' + version +
    '\n Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin', version);
