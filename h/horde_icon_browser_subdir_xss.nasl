#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49119);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-3077");
  script_bugtraq_id(43001);

  script_name(english:"Horde util/icon_browser.php subdir Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The version of the Horde application framework hosted on the remote
web server fails to sanitize user input to the 'subdir' parameter of
the 'util/icon_browser.php' script before using it to generate dynamic
HTML output.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.");
  # https://git.horde.org/h/login.php?url=https%3A%2F%2Fgit.horde.org%2Fdiff.php%2Fhorde%2Futil%2Ficon_browser.php%3Ff%3Dhorde%252Futil%252Ficon_browser.php%26rt%3Dhorde-git%26r1%3Da978a35c3e95e784253508fd4333d2fbb64830b6%26r2%3D9342addbd2b95f184f230773daa4faf5ef6d65e9%26_t%3D1542329111%26_h%3DRqrpOfYYog0a8gV5j-u5eUz_4nM&horde_logout_token=DEmdAGEMzPLQ9Aki4Phgxe3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6057288f");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2010/Sep/82");
  script_set_attribute(attribute:"solution", value:
"Apply the patch in the GIT repository.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl");
  script_require_keys("www/PHP", "www/horde");
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


install = get_install_from_kb(appname:'horde', port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the issue.
alert = '<body onload="alert(' + "'" + SCRIPT_NAME + "'" + ')">';
cgi = '/util/icon_browser.php';

vuln = test_cgi_xss(
  port     : port,
  cgi      : cgi,
  dirs     : make_list(dir),
  qs       : 'app=horde&subdir='+urlencode(str:alert),
  pass_str : alert+'" not found.',
  pass2_re : '<html><body bgcolor="#aaaaaa">Subdirectory "'
);
if (!vuln) exit(0, "The Horde install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
