#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
if ( NASL_LEVEL < 5201 ) exit(0, "webmirror3.nbin is required");

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(50344);
 script_version("1.6");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

 script_name(english: "Missing or Permissive Content-Security-Policy frame-ancestors HTTP Response Header");
 script_summary(english: "Reports pages that do not set a non-permissive Content-Security-Policy frame-ancestors header.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server does not take steps to mitigate a class of web
application vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote web server in some responses sets a permissive
Content-Security-Policy (CSP) frame-ancestors response header or does
not set one at all.

The CSP frame-ancestors header has been proposed by the W3C Web
Application Security Working Group as a way to mitigate cross-site
scripting and clickjacking attacks.");
 # https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55aa8f57");
 # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07cc2a06");
 script_set_attribute(attribute:"see_also", value:"https://content-security-policy.com/");
 script_set_attribute(attribute:"see_also", value:"https://www.w3.org/TR/CSP2/");
 script_set_attribute(attribute:"solution", value:
"Set a non-permissive Content-Security-Policy frame-ancestors header
for all requested resources.");
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);
csp_fa = get_kb_list("www/"+port+"/header/missing/csp-frame-ancestors");
if (empty_or_null(csp_fa))
 exit(0, "Content-Security-Policy frame-ancestors response headers were seen from the web server on port "+port+".");

csp_fa = sort(list_uniq(make_list(csp_fa)));
report = '\nThe following pages do not set a Content-Security-Policy frame-ancestors response header or set a permissive policy:\n\n';
foreach page (csp_fa) report = report + '  - ' + build_url(qs:page, port:port) + '\n';
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
exit(0);
