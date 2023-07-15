#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104129);
  script_version("1.5");
  script_cvs_date("Date: 2018/03/12 12:01:40");

  script_bugtraq_id(57760);

  script_name(english:"Linksys E1500/E2500 Authenticated Command Execution");
  script_summary(english:"Checks the firmware version");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by an authenticated command execution
vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote Linksys router is affected by an authenticated command
execution vulnerability. An authenticated remote attacker can use
this vulnerability to execute operating system commands as root.

This vulnerability has been used by the IoT Reaper botnet.");
  script_set_attribute(attribute:"see_also", value:"http://www.s3cur1ty.de/m1adv2013-004");
  # http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197042fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest firmware version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linksys E1500/E2500 apply.cgi Remote Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("linksys_router_detect.nasl");
  script_require_keys("installed_sw/Linksys");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'Linksys';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

vuln = FALSE;
if ("E1500" >< install["model"])
{
  if (install["version"] == "1.0.05 build 1" ||
      install["version"] == "1.0.04 build 2" ||
      install["version"] == "1.0.00 build 9")
  {
    vuln = TRUE;
  }
}
else if ("E2500" >< install["model"])
{
  if (install["version"] == "1.0.03")
  {
    vuln = TRUE;
  }
}

if (vuln == FALSE)
{
  audit(AUDIT_HOST_NOT, "an affected Linksys router");
}

report = "Based on the self-reported firmware version, " + install["version"] +
    ',\nthe remote ' + install["model"] + ' router is vulnerable on port ' + port + '.';
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
