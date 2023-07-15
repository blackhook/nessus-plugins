#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101812);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/07/19 17:29:12 $");

  script_name(english:"Linksys Smart Wi-Fi Router Default Credentials");
  script_summary(english:"Checks for Linksys Smart Wi-Fi Router default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device can be accessed with default credentials");
  script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote Linksys Smart Wi-Fi Router device
has default credentials set for its web administration interface
('admin'/'admin'). An attacker can exploit this to gain administrative
access to the affected device.");
  script_set_attribute(attribute:"solution", value:
"Configure a strong password for the web administration interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:linksys:linksyssmartwifi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("linksys_smart_wifi_www_detect.nbin");
  script_require_keys("installed_sw/Linksys Smart Wi-Fi WWW");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:"Linksys Smart Wi-Fi WWW", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Linksys Smart Wi-Fi WWW", port:port);

res = http_send_recv3(
  method:'POST',
  item:'/JNAP/',
  add_headers: {'X-JNAP-Action':'http://linksys.com/jnap/core/IsAdminPasswordDefault', 'X-JNAP-Authorization':'null'},
  data:'{}',
  port:port,
  exit_on_fail:TRUE);

if ("200 OK" >!< res[0] || isnull(res[2]) || '"result": "OK"' >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected Linksys Smart Wi-Fi device");
}

match = pregmatch(string:res[2], pattern:'"isAdminPasswordDefault": ((?:true)|(?:false))');
if (isnull(match) || match[1] == "false")
{
  audit(AUDIT_HOST_NOT, "an affected Linksys Smart Wi-Fi device");
}

report = '\nThe remote Linksys Smart Wi-Fi device is using the default admin password.\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
