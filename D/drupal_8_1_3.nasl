#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91781);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-6211", "CVE-2016-6212");
  script_bugtraq_id(91230);

  script_name(english:"Drupal 7.x < 7.44 / 8.x < 8.1.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 7.x prior to
7.44 or 8.x prior to 8.1.3. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the Views module that allows an
    unauthenticated, remote attacker to bypass restrictions
    and disclose the number of hits collected by the
    Statistics module.

  - A flaw exists in the User module due to incorrectly
    granting the 'all user' role when saving user accounts.
    An authenticated, remote attacker can exploit this to
    gain elevated privileges.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2016-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.44");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.1.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.44 / 8.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6211");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);
fix = FALSE ;


if (version == "7" || version == "8") audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (version =~ "^7\.")
{
  if (ver_compare(ver:version,fix:"7.44",strict:FALSE) < 0)
  {
    fix = "7.44";
  }else{
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
  }
}

if (version =~ "^8\.")
{
  if (ver_compare(ver:version,fix:"8.1.3",strict:FALSE) < 0)
  {
    fix = "8.1.3";
  }else{
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
  }
}

if (!fix) audit(AUDIT_WEB_APP_NOT_INST, app + " 7.x or 8.x", port);

security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
);
