#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(20295);
  script_version("1.27");

  script_cve_id("CVE-2005-4148", "CVE-2005-4149");
  script_bugtraq_id(15789);

  script_name(english:"ListManager Error Message Information Disclosure");
  script_summary(english:"Checks for error message information disclosure vulnerability in ListManager");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris. 

In response to a request for a nonexistent page, the version of
ListManager on the remote host returns sensitive information such as
the installation path and software version as well as possibly SQL
queries, code blocks, or the entire CGI environment." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Dec/374" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/08");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Make sure it's ListManager, unless we're being paranoid.
banner = get_http_banner(port:port);
if (
  report_paranoia < 2 &&
  banner && 
  (
    # later versions of ListManager
    "ListManagerWeb/" >!< banner &&
    # earlier versions (eg, 8.5)
    "Server: Tcl-Webserver" >!< banner
  )
) exit(0, "ListManager is not running on port "+port);


# Try to exploit the flaw.
url = "/read/rss?forum=" + SCRIPT_NAME;
w = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

# There's a problem if we see a bug report form.
if (egrep(pattern:'<INPUT TYPE="HIDDEN" NAME="(currentdir|env|version)', string:res)) {
  report = '\n' +
    'Nessus was able to uncover some information using the following URL :\n' +
    '\n' +
    "  " +  build_url(port:port, qs:url) +  '\n';

  info = "";
  foreach litem (make_list("currentdir", "env", "version"))
  {
    leadin = '<INPUT TYPE="HIDDEN" NAME="' + litem + '" VALUE="';
    if (leadin >< res)
    {
      val = strstr(res, leadin) - leadin;
      val = val - strstr(val, '">');
      info += '  ' + litem + ' : ' + val + '\n';
    }
  }

  report += '\n' +
    'Here is the information extracted :\n' +
    '\n' +
    info;

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);

  exit(0);
}
