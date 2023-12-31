#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79386);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-9015", "CVE-2014-9016");
  script_bugtraq_id(71195, 71202);
  script_xref(name:"EDB-ID", value:"35415");

  script_name(english:"Drupal 6.x < 6.34 / 7.x < 7.34 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.34 or 7.x prior to 7.34. It is, therefore, potentially affected
by the following vulnerabilities :

  - There exists an unspecified flaw that is triggered when
    handling a specially crafted request that may allow a
    remote attacker to perform a session hijacking attack.
    (CVE-2014-9015)

  - There exists a flaw in the password hashing API that is
    triggered when handling a specially crafted request. An
    attacker may use this to consume resources and cause a
    denial of service. This issue is only present in
    versions of Drupal prior to 7.34. (CVE-2014-9016)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2014-006");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.34");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/6.34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.34 / 7.34 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^7\.([0-9]|[1-2][0-9]|3[0-3])($|[^0-9]+)" ||
  version =~ "^6\.([0-9]|[1-2][0-9]|3[0-3])($|[^0-9]+)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.34 / 6.34' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
