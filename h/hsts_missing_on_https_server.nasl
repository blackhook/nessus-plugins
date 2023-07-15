#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84502);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/19");

  script_name(english:"HSTS Missing From HTTPS Server");
  script_summary(english:"Checks for HSTS in HTTPS response headers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is not enforcing HSTS.");
  script_set_attribute(attribute:"description", value:
"The remote HTTPS server is not enforcing HTTP Strict Transport Security (HSTS). 
HSTS is an optional response header that can be configured on the server to instruct 
the browser to only communicate via HTTPS. The lack of HSTS allows downgrade attacks,
SSL-stripping man-in-the-middle attacks, and weakens cookie-hijacking protections.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc6797");
  script_set_attribute(attribute:"solution", value:
"Configure the remote web server to use HSTS.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "ssl_supported_versions.nasl", "wsman_server_detect.nasl");
  script_require_keys("SSL/Supported");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

port = get_http_port(default:443);

# Make sure port is using SSL
transport_ssl_list = get_kb_list('SSL/Transport/' + port);
if (!transport_ssl_list) audit(AUDIT_NOT_LISTEN, 'An SSL-enabled HTTP server', port);

# check for services that don't need HSTS because they aren't designed to be used with browsers
# WS-Management and WinRM
if (get_kb_item('Services/www/' + port + '/wsman'))
  audit(AUDIT_LISTEN_NOT_VULN, "WS-Management Server", port);

# Get banner
banner = get_http_banner(
  port         : port,
  broken       : TRUE,
  exit_on_fail : TRUE
);

# Check for HSTS header
lines = pgrep(
  string  : banner,
  pattern : "^[Ss]trict-[Tt]ransport-[Ss]ecurity:\s+max-age=",
  icase   : TRUE
);

if (empty_or_null(lines))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  The remote HTTPS server does not send the HTTP'+
      '\n  "Strict-Transport-Security" header.' +
      '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  }
  else security_report_v4(port:port, severity:SECURITY_NOTE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'HTTPS server', port);
