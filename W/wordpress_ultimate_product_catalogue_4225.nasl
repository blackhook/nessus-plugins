#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105024);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/08 12:52:13");

  script_xref(name:"EDB-ID", value:"43065");

  script_name(english:"Ultimate Product Catalog Plugin for WordPress < 4.2.26 PHP Object Injection");
  script_summary(english:"Checks the plugin / script version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by a PHP object injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Ultimate Product
Catalog Plugin for WordPress running on the remote web server is
prior to 4.2.26. It is, therefore, affected by a PHP object injection
vulnerability. An unauthenticated, remote attacker can exploit this
to inject PHP objects and execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");

  script_set_attribute(attribute:"see_also", value:"https://dl.packetstormsecurity.net/1710-exploits/wpupc4224-inject.txt");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/ultimate-product-catalogue/");
  script_set_attribute(attribute:"solution", value:"
  Upgrade the Ultimate Product Catalog Plugin for WordPress to 
  version 4.2.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ultimateproductcatalogue:ultimateproductcatalogue");
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
plugin_url = install_url + "wp-content/plugins/ultimate-product-catalogue/";

plugin = 'Ultimate Product Catalog';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

# if not found as installed from kb, check for regex in plugin dir
if (!installed)
{
  regexes[0] = make_list("MIT Licensed", "John Resig");
  checks["/wp-content/plugins/ultimate-product-catalogue/js/ultimate-lightbox.js"] = regexes;

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
  item   : dir + "/wp-content/plugins/ultimate-product-catalogue/readme.txt",
  exit_on_fail : TRUE
);

body = res[2];

if ("=== Product" >< body && "Catalog" >< body)
{
  # Grab version
  match = pregmatch(pattern:"=\s\b([0-9\.]+|$)\s=", string:body);
  if (!empty_or_null(match)) version = match[1];
}
else
audit(AUDIT_UNKNOWN_WEB_APP_VER, plugin + " plugin included in the " + app + " install", plugin_url);

fix = '4.2.26';

# Compare version with fixed
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n WordPress URL     : ' + install_url +
    '\n Plugin URL        : ' + plugin_url +
    '\n Installed version : ' + version +
    '\n Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin', version);
