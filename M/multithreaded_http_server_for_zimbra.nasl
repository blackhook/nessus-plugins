#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108373);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_name(english:"Multi-Threaded HTTP Server v1.1 for Zimbra");
  script_summary(english:"The remote web server is identified by its HTTP banner.");
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to directory traversal attacks.");
  script_set_attribute(attribute:"description", value:
"The remote web server is identified as Multi-Threaded HTTP Server
for Zimbra.  This third-party Zimbra add-on fails to sanitize URLs
in a way that allows traversal attacks.  An unauthenticated, remote
attacker can exploit this to view arbitrary files on the remote
host.");

  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/12304/");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/12331/");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/12308/");

  script_set_attribute(attribute:"solution", value:
"Either limit incoming traffic to the Multi-Threaded HTTP Server for
Zimbra detected on this port or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:rajeev_kumar:multithreaded_http_server:1.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2020 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port    = get_http_port(default:80);
appname = "Multi-Threaded HTTP Server for Zimbra by rajeev kumar";
path    = "/";

res = http_get_cache(
  item         : path,
  port         : port,
  exit_on_fail : TRUE
);

if(empty_or_null(res))
  audit(AUDIT_NO_BANNER, port);

if(res !~ "MultiThreadedHTTPServer.*for Zimbra implemented by rajeev kumar")
  audit(AUDIT_WRONG_WEB_SERVER, port, appname);

url = build_url(qs:path,port:port);

snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
result = substr(res, 0, 1024);
if(strlen(result) == 1024)
  result += '\n\n...';

report = "Nessus was able to detect " + appname + ' with the following request:\n';
report += '\n' + url + '\n';
report += '\n\n' + 'This produced the following truncated output: \n';
report += '\n' + snip;
report += '\n' + beginning_of_response2(resp:result, max_lines:200);
report += '\n' + snip;

security_report_v4(
  port       : port,
  extra      : report,
  severity   : SECURITY_WARNING
);

