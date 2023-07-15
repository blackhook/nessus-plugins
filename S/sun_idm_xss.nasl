#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29926);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-0239", "CVE-2008-0240", "CVE-2008-0241");
  script_bugtraq_id(27214);

  script_name(english:"Sun Java System Identity Manager Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Sun Java System Identity Manager, a Java
application for user provisioning and identity auditing in enterprise
environments. 

The version of Identity Manager installed on the remote host fails to
sanitize user-supplied input to various JSP scripts before using it to
generate dynamic content.  An unauthenticated, remote attacker may be
able to leverage these issues to inject arbitrary HTML or script code
into a user's browser to be executed within the security context of
the affected site. 

Known to be affected are the 'cntry' and 'lang' parameters of the
'login.jsp' script, the 'resultsForm' parameter of the
'account/findForSelect.jsp' script, the 'activeControl' parameter of
the 'user/main.jsp' script, the 'helpUrl' parameter of the
'help/index.jsp' script, and the 'nextPage' parameter of the
'user/login.jsp' script");
  script_set_attribute(attribute:"see_also", value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr07-06");
  script_set_attribute(attribute:"see_also", value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr07-07");
  script_set_attribute(attribute:"see_also", value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr07-08");
  script_set_attribute(attribute:"see_also", value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr07-09");
  script_set_attribute(attribute:"see_also", value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr07-10");
  script_set_attribute(attribute:"see_also", value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr07-12");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/486076");
  # http://web.archive.org/web/20080119110308/http://sunsolve.sun.com/search/document.do?assetkey=1-26-103180-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ebbdd8a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the versions of Sun Java System Identity Manager
listed in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:java_system_identity_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("sun_idm_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
exploit = string("-->", xss, "<!--");


# Test an install.
install = get_kb_item(string("www/", port, "/sun_idm"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/login.jsp?",
      "lang=", exploit, "&",
      "cntry="
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if the display name uses our exploit.
  if (string("The local display name is: ", exploit, " -->") >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
