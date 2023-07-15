#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110271);
  script_version("1.2");
  script_cvs_date("Date: 2018/11/15 20:50:16");

  script_name(english:"SingTel Backdoor Detection (ForgotDoor)");
  script_summary(english:"Checks for SingTel router admin backdoor.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SingTel router has a backdoor.");
  script_set_attribute(attribute:"description", value:
"The remote SingTel router may be contain a backdoor. Certain 
SingTel routers had their administrative web interfaces
port-forwarded to public-facing addresses by customer support after
users requested customer service. Depending on the configuration, the
router may require no credentials, default credentials, or weak
credentials to obtain administrative privileges.

A remote attacker can both control these devices and use
them as a pivot to widen the attack surface to all connected
devices.");

  # https://blog.newskysecurity.com/forgotdoor-routers-in-singapore-accidentally-give-complete-access-to-potential-iot-attackers-ed60895c5042?gi=b8f16827a111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4b0e72e");
  script_set_attribute(attribute:"solution", value:
"Disable the port forwarding either manually or by contacting the 
vendor.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:singtel:routers");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports(10000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

port = get_http_port(default:10000);

r = http_send_recv3(method: 'GET', item: '/', port:port, exit_on_fail: true);

report = '';

if ('200' >!< r[0]) audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

if ('Arcadyan httpd 1.0' >< r[1] && '"tv_status_icon").src="./images/singtel_tv.png' >< r[2])
{
  report +=
    '\n  Nessus detected the presence of ForgotDoor on port ' + port +
    '\n  Device: Singtel WiFi Gigabit Router AC Plus' +
    '\n';
}
else if ('X-Frame-Options: SAMEORIGIN' >< r[1] && 'url=/js/.js_check.html"' >< r[2])
{
  r1 = http_send_recv3(method: 'GET', item: '/main.html', port:port, exit_on_fail: true);

  data = '&user=admin&password=&source=webui\r\n';
  r2 = http_send_recv3(
      method      :'POST',
      item        :'/cgi-bin/login',
      port        :port,
      data        :data,
      exit_on_fail:true
  );

  if ('<!-- Copyright AirTies' >< r1[2]
      && '<meta http-equiv="Refresh" content="0; url=/main.html">' >< r2[2])
  {
    report +=
      '\n  Nessus detected the presence of ForgotDoor on port ' + port +
      '\n  Device: AirTies Air4920SG' +
      '\n';
  }
}

if (report != '') security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
else audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
