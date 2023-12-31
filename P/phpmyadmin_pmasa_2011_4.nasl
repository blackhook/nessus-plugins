#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54630);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-1941");
  script_bugtraq_id(47943);
  script_xref(name:"SECUNIA", value:"44641");

  script_name(english:"phpMyAdmin url.php Redirect (PMASA-2011-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application with an open redirect.");
  script_set_attribute(attribute:"description", value:
"The version of phpMyAdmin on the remote host fails to validate input
passed to the 'url' parameter in the 'url.php' script before
redirecting to a specified location.

An attacker may be able to exploit this issue to conduct phishing
attacks by tricking users into visiting malicious websites.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2011-4/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 3.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1941");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/phpMyAdmin", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'phpMyAdmin', port:port, exit_on_fail:TRUE);
dir = install['dir'];

redirect = 'http://www.example.com';
url = dir + '/url.php?url='+redirect;

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
code = hdrs['$code'];
location = hdrs['location'];

if (code == 302 && redirect == location)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:80);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The phpMyAdmin install at '+build_url(port:port, qs:dir+'/')+' is not affected.');
