#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103219);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-14417");

  script_name(english:"D-Link DIR Router Missing Authentication Check");
  script_summary(english:"Sends an HTTP GET request");

  script_set_attribute(attribute:"synopsis", value:
"The remote router doesn't properly enforce authentication");
  script_set_attribute(attribute:"description", value:
"The remote D-Link DIR router does not enforce authentication
when a remote user requests register_send.php. An attacker can
use this weakness to recover the administrator password.");
  # https://pierrekim.github.io/blog/2017-09-08-dlink-850l-mydlink-cloud-0days-vulnerabilities.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32828524");
  script_set_attribute(attribute:"solution", value:
"No patch currently exists for this vulnerability");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14417");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");
  script_require_ports("Services/www", 80, 8080, 8181, 443, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'DLink DIR';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

uri = '/register_send.php';
action = '?action=from_nessus';
res = http_send_recv3(
  method:'GET',
  item:uri + action,
  port:port,
  exit_on_fail:TRUE);

# Yes, authentication is misspelled.
if (empty_or_null(res) || "200 OK" >!< res[0] || "Authenication fail" >< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected D-Link DIR router");
}

if ("<result>fail</result>" >< res[2])
{
  var report = 
    '\n' + "Nessus was able to access the following URL" +
    '\n' + "without authentication:" +
    '\n' +
    '\n' + build_url(qs:uri, port:port) +
    '\n' +
    '\n' + 'Access to this URL allows an attacker to recover' +
    '\n' + "the admin credentials through D-Link's mydlink" +
    '\n' + 'cloud service.' +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}

# We haven't seen a patch yet. But we are going to assume if
# we hit this point then a patch has been released... and maybe
# they fixed their spelling error.
audit(AUDIT_HOST_NOT, "an affected D-Link DIR router");
