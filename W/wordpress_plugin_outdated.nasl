#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101841);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/07/20 19:46:24 $");

  script_name(english:"WordPress Outdated Plugin Detection");
  script_summary(english:"Checks for the presence of outdated WordPress plugins.");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has outdated plugins installed");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has outdated
plugins installed.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/");
  script_set_attribute(attribute:"solution", value:
"Update the listed plugins through the administrative dashboard.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencie("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("global_settings.inc");
include("misc_func.inc");
include("wordpress_plugin_list.inc");

port = get_http_port(default:80);
if(!port) port = 80;

if(!get_kb_item(port+"/WordPress/plugins_enumerated")) audit(AUDIT_WEB_FILES_NOT, "WordPress plugin", port);

plugins = query_scratchpad("SELECT name, version, friendly_name FROM wordpress_plugins");

extra = 'The following plugins are outdated:\n';
unknown = 'The following plugins\' versions could not be verified:\n';

foreach plugin (plugins)
{
  regex = "^v?([0-9.]+)";
  plugin_ver = plugin['version'];
  p_ver = pregmatch(string:plugin_ver, pattern:regex);
  if(!isnull(p_ver))
    plugin_ver = p_ver[1];
  else
    plugin_ver = "unknown";
  max_plugin_ver = WORDPRESS_PLUGINS[plugin['name']];
  max_p_ver = pregmatch(string:max_plugin_ver, pattern:regex);
  if(!isnull(max_p_ver))
    max_plugin_ver = max_p_ver[1];
  else
    max_plugin_ver = "unknown";
  plugin_name = plugin['friendly_name'];
  if(plugin_ver == "unknown")
  {
    unknown += 'Plugin Name: ' + plugin_name + '\n';
    unknown += 'Latest Version: ' + WORDPRESS_PLUGINS[plugin['name']] + '\n';
    continue;
  }
  if(ver_compare(ver:plugin_ver, fix:max_plugin_ver, strict:FALSE) < 0)
  {
    extra += 'Plugin Name: ' + plugin_name + '\n';
    extra += 'Plugin Version: ' + plugin['version'] + '\n';
    extra += 'Latest Version: ' + WORDPRESS_PLUGINS[plugin['name']] + '\n';
    extra += '\n';
  }
}

if(unknown =~ "Plugin Name") extra += unknown;
if(extra =~ "Plugin Name")
  security_report_v4(severity:SECURITY_NOTE, extra:extra, port:port);
else
  audit(AUDIT_INST_VER_NOT_VULN, "WordPress Plugins");
