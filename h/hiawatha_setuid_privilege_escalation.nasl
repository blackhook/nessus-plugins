#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69036);
  script_version("1.3");
  script_cvs_date("Date: 2018/08/10 18:07:08");


  script_name(english:"Hiawatha 'setuid' Local Privilege Escalation");
  script_summary(english:"Checks version of Hiawatha");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its server response header, the installed version of
Hiawatha is a version prior to 1.0b.  A flaw exists in the 'setuid'
function that could allow a local attacker to gain elevated
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.hiawatha-webserver.org/changelog");
  script_set_attribute(attribute:"solution", value:"Upgrade to Hiawatha 1.0b or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hiawatha:webserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("hiawatha_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/hiawatha");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Hiawatha";

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "hiawatha",
  port         : port,
  exit_on_fail : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install["ver"];
if ( version =~ "^0\." )
{
  if (report_verbosity > 0)
  {
    report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 1.0b' +
        '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
