#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105508);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"JoomGallery for Joomla! < 3.3.4 SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by a SQL Injection Vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the JoomGallery Plugin for 
Joomla! running on the remote web server is prior to 3.3.4. It is, 
therefore, affected by multiple SQL injection vulnerabilities in
'/models/category.php' and '/models/detail.php' due to improper
sanitization of user-supplied input of the 'jg_firstorder', 
'jg_secondorder' and 'jg_thirdorder' parameters before using it to
construct database queries.

A remote attacker can leverage this issue to launch SQL injection
attacks against the affected application, leading to discovery of
sensitive information and attacks against the underlying database.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/JoomGallery/JoomGallery/pull/122/files");
  script_set_attribute(attribute:"see_also", value:"http://www.joomgallery.net");
  script_set_attribute(attribute:"solution", value:
"Upgrade JoomGallery for Joomla! to version 3.3.4 or greater, or
disable and remove the vulnerable plugin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url =  build_url(port:port, qs:dir);
plugin_url = install_url + "administrator/components/com_joomgallery/";

plugin = 'Joomgallery';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  # Check for the following string in the url indicated below
  regexes[0] = make_list("JOOMGALLERY_LAYOUT_GALLERY");
  checks["/components/com_joomgallery/views/gallery/tmpl/default.xml"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}

# Get version from changelog 
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/administrator/components/com_joomgallery/joomgallery.xml",
  exit_on_fail : TRUE
);

# Store response body for parsing data
body = res[2];

# Check changelog is readable before parsing data 
if ("joomgallery" >< body)
{
  # Grab version
  match = pregmatch(pattern:"<version>([0-9\.]+)</version>", string:body);
  if (!empty_or_null(match)) version = match[1];
}
else
audit(AUDIT_UNKNOWN_WEB_APP_VER, plugin + " plugin included in the " + app + " install", plugin_url);

fix = "3.3.4";

# Compare version with fixed
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
  '\n Joomla! URL     	: ' + install_url +
  '\n Plugin URL        : ' + plugin_url +
  '\n Installed version : ' + version +
  '\n Fixed version     : ' + fix +
  '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin', version);

