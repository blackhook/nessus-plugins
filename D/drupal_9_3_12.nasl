#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160024);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/21");

  script_name(english:"Drupal 9.2.x < 9.2.18 / 9.3.x < 9.3.12 Multiple Vulnerabilities (drupal-2022-04-20)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.2.x prior to 9.2.18
or 9.3.x prior to 9.3.12. It is, therefore, affected by multiple vulnerabilities.

  - Drupal 9.3 implemented a generic entity access API for entity revisions. However, this API was not
    completely integrated with existing permissions, resulting in some possible access bypass for users who
    have access to use revisions of content generally, but who do not have access to individual items of node
    and media content. This vulnerability only affects sites using Drupal's revision system. This advisory is
    not covered by Drupal Steward. (SA-CORE-2022-009)

  - Drupal core's form API has a vulnerability where certain contributed or custom modules' forms may be
    vulnerable to improper input validation. This could allow an attacker to inject disallowed values or
    overwrite data. Affected forms are uncommon, but in certain cases an attacker could alter critical or
    sensitive data. We do not know of affected forms within core itself, but contributed and custom project
    forms could be affected. Installing this update will fix those forms. This advisory is not covered by
    Drupal Steward. (SA-CORE-2022-008)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-009");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.12");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-008");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.18");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 9.2.18 / 9.3.12 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '9.2', 'fixed_version' : '9.2.18' },
  { 'min_version' : '9.3', 'fixed_version' : '9.3.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
