#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42435);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id("CVE-2009-3963");
  script_bugtraq_id(36955);

  script_name(english:"XOOPS misc.php Query String XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of XOOPS running on the remote web server has a cross-
site scripting vulnerability.  'misc.php' does not sanitize the
requested URI before displaying it in the response.  Manipulating the
query string can result in a cross-site scripting attack.  A remote
attacker could exploit this by tricking a user into requesting a
malicious URL.

There are reportedly other unspecified vulnerabilities in this version
of XOOPS, though Nessus has not checked for those issues.");
  # http://xoops.svn.sourceforge.net/viewvc/xoops/XoopsCore/trunk/htdocs/misc.php?r1=3558&r2=3696
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a12c2180");
  script_set_attribute(attribute:"see_also", value:"https://xoops.org/modules/news/article.php?storyid=5064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to XOOPS 2.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_require_keys("www/xoops");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'xoops', port:port);
if (isnull(install)) exit(1, "XOOPS install not found in KB for port "+port+".");

dir = install['dir'];
xss = "xss='><script>alert('" + SCRIPT_NAME + '-' + unixtime() + "')</script>";
qs = 'action=showpopups&type=avatars&' + xss;
expected_output = "<form name='avatars' action='" + dir + '/misc.php'+ '?' + qs;

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:'/misc.php',
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'<meta name="generator" content="XOOPS" />'
);

if (!exploited)
  exit(0, "The XOOPS install at "+build_url(qs:dir + '/', port:port)+" is not affected.");
