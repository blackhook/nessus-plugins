#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84622);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-5397", "CVE-2015-5608");
  script_bugtraq_id(76495, 76496);

  script_name(english:"Joomla! 3.x < 3.4.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 3.x prior to 3.4.2.
It is, therefore, affected by multiple vulnerabilities :

  - A cross-site request forgery (XSRF) vulnerability exists
    due to a failure to require explicit confirmation or a
    unique token when performing certain sensitive actions.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    upload arbitrary code. (CVE-2015-5397)

  - An open redirect vulnerability exists due to a failure
    to validate certain script parameters. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    redirect the user to an arbitrary website.
    (CVE-2015-5608)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.joomla.org/announcements/release-news/5589-joomla-3-4-2-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8dec0e1");
  # https://developer.joomla.org/security-centre/618-20150602-core-remote-code-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c121e17f");
  # https://developer.joomla.org/security-centre/617-20150601-core-open-redirect.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1ebc47f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
install_loc =  build_url(port:port, qs:install['path']);

fix = "3.4.2";

# Check granularity
if (version =~ "^3(\.[0-4])?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

# Versions  3.x < 3.4.2 are vulnerable
# (There are Alpha versions of some builds)
if (
  version =~ "^3\.[0-3]([^0-9]|$)" ||
  version =~ "^3\.4\.[01]([^0-9]|$)"
)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_loc,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report,severity:SECURITY_WARNING, xsrf:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
