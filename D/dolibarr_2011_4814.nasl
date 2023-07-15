#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58748);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-4814");
  script_bugtraq_id(50777);

  script_name(english:"Dolibarr Multiple Script URI XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
reflected cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The version of Dolibarr on the remote host fails to properly sanitize
parameters in 'index.php' before using them to generate dynamic HTML.

By tricking someone into clicking on a specially crafted link, an
attacker may be able exploit this issue to inject arbitrary HTML and
script code in a user's browser to be executed within the security
context of the affected site.

This install is likely affected by other cross-site scripting
vulnerabilities as well.");
  # https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_dolibarr.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9b8272");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a non release-candidate version of Dolibarr 3.1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dolibarr:dolibarr");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("dolibarr_detect.nasl");
  script_require_keys("www/PHP", "www/dolibarr");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:0);
install = get_install_from_kb(appname:'dolibarr', port:port, exit_on_fail:TRUE);

dir = install['dir'];

vuln_script = '/index.php';

xss = "<img src=1 onerror=javascript:alert('" + SCRIPT_NAME + "')>";
exploit = "/%22%3E" + urlencode(str:xss) + "%3Ca%20href=%22";
exploit_url = dir + vuln_script + exploit;

res = http_send_recv3(
  port: port,
  method: "GET",
  exit_on_fail: TRUE,
  item: exploit_url
);

if ( ">" + xss + "<" >< res[2])
{
  if (report_verbosity > 0)
  {
    report = '\nThe following request was used to verify the vulnerability exists :\n\n' +
    build_url(port: port, qs: exploit_url) + '\n';
    security_warning(port: port, extra: report);
  }
  else security_warning(port);

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  exit(0);
}
else exit(0, 'The Dolibarr install at ' + build_url(qs:dir, port:port) + ' is not affected.');
