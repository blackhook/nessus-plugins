#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26927);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-3918", "CVE-2009-4069");
  script_bugtraq_id(25923, 35424);
  script_xref(name:"SECUNIA", value:"35458");

  script_name(english:"GForge account/verify.php confirm_hash Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running GForge, a web-based project for
collaborative software development.

The version of GForge installed on the remote host fails to sanitize
user-supplied input to the 'confirm_hash' parameter of the
'account/verify.php' script before using it to generate dynamic
output.  An unauthenticated, remote attacker may be able to leverage
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site.

This version may have several other vulnerabilities related to SQL
injection and cross-site scripting, especially if the remote host is
running a Debian build of GForge.  Nessus has not checked for these
issues.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20071110182313/http://gforge.org/tracker/?func=detail&atid=105&aid=3094&group_id=1");
  # http://gforge.org/scm/viewvc.php/trunk/gforge/www/account/verify.php?r1=5967&r2=6092&root=gforge&view=patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2193dcbf");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-security-announce/2009/msg00130.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gforge:gforge");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("gforge_detect.nasl", "cross_site_scripting.nasl");
  script_require_keys("www/gforge");
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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");
if (get_kb_item("www/"+port+"/generic_xss")) exit(0, "The web server on port "+port+" is prone to XSS");

install = get_install_from_kb(appname:'gforge', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/gforge' KB item is missing.");

dir = install['dir'];
if (dir == "") dir = "/";

  # Try to exploit the issue.
  xss = string("<script>alert(", SCRIPT_NAME, ")</script>");
  url = string(dir, '/account/verify.php?confirm_hash=">', urlencode(str:xss));
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond");

  # There's a problem if we see our exploit.
  if (
    string('name="confirm_hash" value="">', xss, '"') >< res[2] ||
    string('name="confirm_hash" value="\\">', xss, '"') >< res[2]
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
