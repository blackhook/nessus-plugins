# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106230);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"Apache Default Index Page");
  script_summary(english:"Checks for the default index page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses the default Apache index page");
  script_set_attribute(attribute:"description", value:
"The remote web server uses the default Apache index page. This
page may contain some sensitive data like the server root and
installation paths.");
  script_set_attribute(attribute:"solution", value:
"Remove the default index page.");
  script_set_attribute(attribute:"see_also",value:"https://www.owasp.org/index.php/SCG_WS_Apache");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Apache", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port);

res = http_get_cache(port:port, item:'/');

# Ubuntu
# Debian
# Raspbian
if (pgrep(pattern:"<title>Apache2 [^ ]+ Default Page", string:res, icase:TRUE) ||
# CentOS
    "<title>Apache HTTP Server" >< res ||
# RedHat
# Amazon
# Fedora
    "<title>Test Page for the Apache HTTP Server" >< res ||
# Russian Apache
# OpenBSD
# Windows
    "<title>Test Page for Apache Installation" >< res ||
# Zend
    "<title>Zend Server Test Page" >< res ||
# XAMPP
    "<title>Welcome to XAMPP" >< res ||
# "Unix"
  ("<html><body><h1>It works!</h1>" >< res &&
    "<p>This is the default web page for this server.</p>"))
{
  report = '\nThe Apache server listening on port ' + port + ' uses a\n' +
           'default install page as the index:\n' +
           '\n' +
           build_url(qs:"/", port:port) +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
