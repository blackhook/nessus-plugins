#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106378);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2012-0287");
  script_bugtraq_id(51237);

  script_name(english:"WordPress 3.3.x < 3.3.1 XSS Vulnerability");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is
affected by a cross-site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 3.3.x prior to 3.3.1.
It is, therefore, affected by a cross-site scripting (XSS)
vulnerability. An unauthenticated, remote attacker can exploit this,
via a specially crafted request, to execute arbitrary script code in
a user's browser session.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2012/01/wordpress-3-3-1/");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_3.3.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 3.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 3.3.x < 3.3.1 are affected.
if (
  ver[0] == 3 && ver[1] == 3 && ver[2] < 1
)
{
  report =
  '\n  URL               : ' + install_url +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : 3.3.1' +
  '\n';
  security_report_v4(
    severity : SECURITY_NOTE,
    port     : port,
    extra    : report,
    xss      : TRUE
  );
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
