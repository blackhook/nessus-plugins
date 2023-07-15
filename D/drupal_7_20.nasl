#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64990);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-0316");
  script_bugtraq_id(58069);

  script_name(english:"Drupal 7.x < 7.20 On-Demand Image Derivative Generation Handling Resource Exhaustion DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 7.x prior
to 7.20. It is, therefore, affected by a flaw during the handling of
on-demand generation of image derivatives. A remote attacker, using a
large number of derivative requests, could exploit this to cause a
denial of service by filling up server disk space and causing a very
high CPU load.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2013-02-20/sa-core-2013-002-drupal-core-denial
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4a5e035");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fix = '7.20';
if (version =~ "^7\.([0-9]|1[0-9])($|[^0-9]+)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
