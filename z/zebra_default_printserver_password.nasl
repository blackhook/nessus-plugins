#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164505);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/30");

  script_name(english:"Zebra ZTC Printer Web Interface Default Admin Password");

  script_set_attribute(attribute:"synopsis", value:
   "A default password to the web interface for a Zebra printer was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
   "The remote host has a web interface with a default administrative password.");

  # https://www.zebra.com/us/en/support-downloads/knowledge-articles/ait/changing-the-print-server-s-password.html
  script_set_attribute(attribute:"see_also", value:'http://www.nessus.org/u?d3f2b5f5');
  script_set_attribute(attribute:"see_also", value:'https://supportcommunity.zebra.com/s/article/000021408');

  script_set_attribute(attribute:"solution", value:"Change the password");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for default credentials.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");;
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zebra:printserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/www");
  script_dependencies("zebra_printer_web_detect.nbin");
  exit(0);
}
include('debug.inc');
include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:80, embedded:TRUE);
var app = 'Zebra ZTC PrintServer';
var app_info = vcf::get_app_info(app:app, port:port);

var headers = make_array(
  'Cache-Control', 'max-age=0',
  'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
  'Accept-Language', 'en-US,en;q=0.9',
  'Accept-Encoding', 'gzip, deflate',
  'Referer', get_host_ip(),
  'Host', get_host_ip(), 
  'Origin', get_host_ip(),
  'Content-Type', 'application/x-www-form-urlencoded',
  'Upgrade-Insecure-Requests', 1,
  'Connection', 'close'

);

var res = http_send_recv3(
  method      : 'POST',
  item        : '/authorize',
  port        : port,
  follow_redirect: 1,
  add_headers : headers,  
  data: '0=1234' # default pass
);

dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'[Response to authorize query][' + obj_rep(res) + ']');
dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Sent authorize query: ' + http_last_sent_request());

var vuln = FALSE;
if('Access Granted. This IP Address now has admin\r\n access to the restricted printer pages.' >< res[2])
    vuln = TRUE;
else 
    vuln = FALSE;

if (!vuln)
  audit(AUDIT_LISTEN_NOT_VULN, 'web server', port);
else
{
  var report  = 'Nessus was able to login to the web interface using the following request\n\n' +
  http_last_sent_request();

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
