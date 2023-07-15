#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104102);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/26");


  script_name(english:"AVTech Multiple Vulnerabilities");
  script_summary(english:"Downloads a restricted file");

  script_set_attribute(attribute:"synopsis", value:
"The remote AVTech device is affected by mulitple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote AVTech device is affected by multiple vulnerabilities.
Depending on the firmware version the vulnerabilities may include:

  - All user passwords are stored in cleartext

  - The web interface does not use CSRF protections

  - An attacker is able to perform arbitrary HTTP requests
    through the device without authentication

  - An unauthenticated remote user can execute arbitrary
    system commands by sending a crafted HTTP request to
    Search.cgi

  - An unauthenticated remote user can bypass
    authentication by sending a crafted HTTP request

  - An unauthenticated remote user can download any file
    from the web root by sending a crafted HTTP request

  - An authenticated user can execute arbitrary system
    commands by sending a crafted HTTP GET request to
    CloudSetup.cgi, adcommand.cgi, or PwdGrp.cgi

 These vulnerabilities have been used by the IoT Reaper botnet.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/Trietptm-on-Security/AVTECH");
  script_set_attribute(attribute:"see_also", value:"https://www.search-lab.hu/media/vulnerability_matrix.txt");
  # http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?197042fe");
  script_set_attribute(attribute:"solution", value:
"At time of publication, AVTech had not yet released patches. Users
should take precautions to ensure affected devices are not exposed
to the internet and that the devices are properly isolated on the
local network.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");

  script_dependencies("avtech_detect.nbin");
  script_require_keys("installed_sw/AVTech");
  script_require_ports("Services/www", 80, 81, 88, 8000, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'AVTech';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

# attempt to download cgibox (the ELF that handles all the
# CGI requests). We should get a 403 forbidden.
uri = '/cgi-bin/cgibox';
res = http_send_recv3(
  method:'GET',
  item:uri,
  port:port,
  exit_on_fail:TRUE);

if ("403 Forbidden" >!< res[0])
{
  audit(AUDIT_HOST_NOT, "an AVTech device");
}

# append ?.cab so that the device doesn't do any
# of its auth logic.
uri += '?.cab';
res = http_send_recv3(
  method:'GET',
  item:uri,
  port:port,
  exit_on_fail:TRUE);

if ("200 OK" >!< res[0] ||
    empty_or_null(pregmatch(string:res[2], pattern:'^\x7eELF')))
{
  audit(AUDIT_HOST_NOT, "an AVTech device");
}

var report = 
  '\n' + "Nessus was able to download a restricted file from the" +
  '\n' + "remote device using the following HTTP request:" +
  '\n' +
  '\n' + build_url(qs:uri, port:port) +
  '\n';
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
exit(0);
