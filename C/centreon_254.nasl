#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80357);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(71333);
  script_xref(name:"EDB-ID", value:"39501");

  script_name(english:"Centreon < 2.5.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Centreon application hosted on
the remote web server is affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists in the
    centreonLog.class.php script due to improper
    sanitization of user-supplied input to the 'username'
    parameter. A remote attacker can exploit this to inject
    or manipulate SQL queries in the back-end database,
    resulting in the manipulation or disclosure of arbitrary
    data.

  - An information disclosure vulnerability exists that
    allows allows a local attacker to gain access to
    information in configuration files.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2014/q4/848");
  # https://github.com/centreon/centreon/commit/d00f3e015d6cf64e45822629b00068116e90ae4d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?226939f7");
  # https://github.com/centreon/centreon/commit/015e875482d7ff6016edcca27bffe765c2bd77c1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?256de898");
  # https://github.com/centreon/centreon/commit/a6dd914418dd185a698050349e05f10438fde2a9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30e00b4b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Centreon 2.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon_enterprise_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 2) ||
  (ver[0] == 2 && ver[1] < 5) ||
  (ver[0] == 2 && ver[1] == 5 && ver[2] < 4)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 2.5.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
