#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73634);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-2983");
  script_bugtraq_id(66977);

  script_name(english:"Drupal 6.x < 6.31 Forms API Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Drupal that is 6.x prior
to 6.31. It is, therefore, affected by an error related to the HTML
form API and the caching of pages for different anonymous users, which
could allow sensitive information to be disclosed. Note that Drupal
core does not expose any such HTML forms by default.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2014-04-16/sa-core-2014-002-drupal-core
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ca0aa11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-6.31-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/21");

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

fix = '6.31';
if (version =~ "^6\.([0-9]|[12][0-9]|30)($|[^0-9]+)")
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
