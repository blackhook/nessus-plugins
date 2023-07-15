##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142960);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_name(english:"HSTS Missing From HTTPS Server (RFC 6797)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is not enforcing HSTS, as defined by RFC 6797.");
  script_set_attribute(attribute:"description", value:
"The remote web server is not enforcing HSTS, as defined by RFC 6797. 
HSTS is an optional response header that can be configured on the server to instruct 
the browser to only communicate via HTTPS. The lack of HSTS allows downgrade attacks,
SSL-stripping man-in-the-middle attacks, and weakens cookie-hijacking protections.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc6797");
  script_set_attribute(attribute:"solution", value:
"Configure the remote web server to use HSTS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vendor advisories.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hsts_missing_on_https_server.nasl", "ssl_certificate_chain.nasl");
  script_require_keys("SSL/Supported", "Host/FQDN/tag");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('resolv_func.inc');

get_kb_item_or_exit('Host/FQDN/tag');

var port = get_http_port(default:443);
var hostname = get_kb_item('Host/FQDN/tag');
var alt_name = get_kb_list("Host/alt_name");

# Make sure port is using SSL
var transport_ssl_list = get_kb_list('SSL/Transport/' + port);
if (!transport_ssl_list)
  audit(AUDIT_NOT_LISTEN, 'An SSL-enabled HTTP server', port);

# Make sure target is a valid hostname
var invalid_hostname = is_host_ip(name:hostname);
if (invalid_hostname)
  audit(AUDIT_HOST_NOT, 'affected');

# Make sure the hostname/alt_name matches the certificate CN
var CN = get_kb_item('Transport/SSL/' + port + '/subject');
var name, match_found;
if (!isnull(alt_name))
{
  foreach (name in alt_name)
  {
    if (tolower(name) >< tolower(CN))
    {
      match_found = TRUE;
      break;        
    } 
  }
}
if (tolower(hostname) >< tolower(CN))
  match_found = TRUE;
if (!match_found) 
  audit(AUDIT_HOST_NOT, 'affected');

# check for services that don't need HSTS because they aren't designed to be used with browsers
# WS-Management and WinRM
if (get_kb_item('Services/www/' + port + '/wsman'))
  audit(AUDIT_LISTEN_NOT_VULN, "WS-Management Server", port);

# Get banner
var banner = http_send_recv3(
  method: 'GET',
  item: '/',
  port: port,
  exit_on_fail: TRUE
);

if (empty_or_null(banner[1])) audit(AUDIT_WEB_BANNER_NOT, port);

# Check for HSTS header
var headers = pgrep(
  string  : banner[1],
  pattern : "^[Ss]trict-[Tt]ransport-[Ss]ecurity:\s+max-age=",
  icase   : TRUE
);

if (empty_or_null(headers))
{
  if (report_verbosity > 0)
  {
    var report =
      '\n  The remote HTTPS server does not send the HTTP'+
      '\n  "Strict-Transport-Security" header.' +
      '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  }
  else security_report_v4(port:port, severity:SECURITY_WARNING);
  exit(0);
}


else audit(AUDIT_LISTEN_NOT_VULN, 'HTTPS server', port);
