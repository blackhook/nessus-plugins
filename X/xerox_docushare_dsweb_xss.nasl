#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32480);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-5225");
  script_bugtraq_id(29430);
  script_xref(name:"SECUNIA", value:"30426");

  script_name(english:"Xerox DocuShare dsweb Servlet Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Tomcat Servlet that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running DocuShare, a web-based document management
application from Xerox.

The version of DocuShare installed on the remote host fails to sanitize
user input to the 'dsweb' servlet before including it in dynamic HTML
output.  An attacker may be able to leverage this issue to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site.

Note that the application is also reportedly affected by two similar
issues, although Nessus has not checked for them.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/492766");
  script_set_attribute(attribute:"see_also", value:"https://docushare.xerox.com/doug/dsweb/View/Collection-7503");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2008/Jun/10");
  script_set_attribute(attribute:"solution", value:
"Use the workaround described in the vendor's advisory at least until a
patch is released.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

exploit = '1">' + "<BODY ONLOAD=alert('" + SCRIPT_NAME + "')>";

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/docushare", "/dsdn", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try the exploit.
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/dsweb/Services/User-" + urlencode(str:exploit),
    exit_on_fail : TRUE
  );

  # There's a problem if we see our exploit in the error message
  # in the user view.
  if (
    "Not found: User-" + exploit + " or another in this batch" >< res[2] &&
    "com.xerox.docushare.db.DbNoSuchObjectException" >< res[2]
  )
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
    security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Xerox DocuShare", build_url(qs:dir, port:port));
