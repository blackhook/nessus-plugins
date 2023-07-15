#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106374);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Default nginx HTTP Server Settings");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains default setting and/or files.");
  script_set_attribute(attribute:"description", value:
"The remote webserver contains default settings such as enabled
server tokens and/or default files such as the default index or
error pages. These items could potentially leak useful
information about the server installation.");
  script_set_attribute(attribute:"see_also", value:"https://www.owasp.org/index.php/SCG_WS_nginx");
  script_set_attribute(attribute:"solution", value:
"Disable server tokens. Review the files and replace or delete
as needed.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_detect.nasl", "nginx_nix_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/nginx");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('install_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = 'nginx';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:appname, port:port);

report = '';
if (!empty_or_null(install['source']) && install['version'] != "unknown")
{
  banner = get_http_banner(port:port);
  if (install['version'] >< banner)
  {
    report += '- Server Tokens are enabled\n';
  }
}

url = "/nessus-check/" + SCRIPT_NAME;
res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE);
if (!empty_or_null(res) && "404" >< res[0] && !empty_or_null(res[2]) &&
    # Ubuntu, Debian, Windows
    (("<head><title>404 Not Found</title></head>" >< res[2] && "<hr><center>nginx" >< res[2]) ||
    # Fedora, Amazon
     ("<title>The page is not found</title>" >< res[2] && "This is the default 404 error page" >< res[2])))
{
  report += '- Default 404 error page\n';
}

res = http_get_cache(port:port, item:'/');
if (!empty_or_null(res) &&
   # Ubuntu, Debian
   (("<title>Welcome to nginx" >< res && "Further configuration is required" >< res) ||
   # Windows
    ("<title>Welcome to nginx for Windows</title>" >< res && "nginx setup package for Windows" >< res) ||
   # Fedora, Amazon
    ("<title>Test Page for the Nginx HTTP Server" >< res && "This is the default" >< res)))
{
  report += '- Default index page\n';
}

if (!empty_or_null(report))
{
  report = '\nNessus found the following default settings/files:\n\n' + report;
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, 'nginx', port, install['version']);
}
