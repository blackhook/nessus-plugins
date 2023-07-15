#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72102);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-1475");
  script_bugtraq_id(64973);

  script_name(english:"Drupal 6.x < 6.30 OpenID Module Account Hijacking");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.30. It is, therefore, affected by a security bypass vulnerability
in the OpenID module that could allow an authenticated attacker to
hijack other users' accounts. Only user accounts associated with one
or more OpenID entities are affected.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2014-01-15/sa-core-2014-001-drupal-core
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45df5ae9");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/6.30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1475");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fix = '6.30';
if (version =~ "^6\.([0-9]|[12][0-9])($|[^0-9]+)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
