#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101111);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-9025");

  script_name(english:"HooToo HT-TM06 TripMate Elite Web Server 'protocol.csp' HTTP Cookie Header Handling RCE");
  script_summary(english:"Sends an HTTP request with an oversized cookie field.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HooToo TripMate web interface running on the remote host is
affected by a remote code execution vulnerability in the ioos web
server (vshttpd) due to improper validation of overly long strings
passed via the HTTP cookie header to protocol.csp. An unauthenticated,
remote attacker can exploit this, via a specially crafted HTTP
request, to cause a heap-based buffer overflow, resulting in a denial
of service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://debugtrap.com/2017/05/09/tm06-vulnerabilities2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to firmware version 2.000.038 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9025");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hootoo:tripmate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hootoo:tripmate_6_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hootoo:tripmate_6");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hootoo_tripmate_detect.nbin");
  script_require_keys("installed_sw/HooToo TripMate Web Interface");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

appname = "HooToo TripMate Web Interface";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

# Send a short cookie to ensure that vshttpd responds
res = http_send_recv3(
  method:"GET",
  port:port,
  item:'/protocol.csp?fname=security&opt=userlock&username=guest&function=get',
  add_headers:make_array("Cookie", 'nessus'),
  exit_on_fail:TRUE);

if (isnull(res) || "200 OK" >!< res[0] || "Server: vshttpd" >!< res[1])
{
  audit(AUDIT_LISTEN_NOT_VULN, appname, port);
}

# Send a long cookie to see if lighttpd will responds. This occurs because the
# vshttpd server fails so the proxy server handles the response
cookie = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
res = http_send_recv3(
  method:"GET",
  port:port,
  item:'/protocol.csp?fname=security&opt=userlock&username=guest&function=get',
  add_headers:make_array("Cookie", cookie),
  exit_on_fail:TRUE);

if (isnull(res) || "200 OK" >!< res[0] || "Server: lighttpd/" >!< res[1])
{
  audit(AUDIT_LISTEN_NOT_VULN, appname, port);
}

req = http_last_sent_request();

security_report_v4(port:port, severity:SECURITY_WARNING,
  generic:TRUE, request:make_list(req));
