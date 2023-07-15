#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174488);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");
  script_xref(name:"IAVA", value:"2023-A-0218-S");

  script_name(english:"Drupal 7.x < 7.96 / 9.4.x < 9.4.14 / 9.5.x < 9.5.8 / 10.x < 10.0.8 Drupal Vulnerability (SA-CORE-2023-005) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.96,
9.4.x prior to 9.4.14, 9.5.x prior to 9.5.8, or 10.x prior to 10.0.8. It is, therefore, affected by a vulnerability.

  - The file download facility doesn't sufficiently sanitize file paths in certain situations. This may result
    in users gaining access to private files that they should not have access to. Some sites may require
    configuration changes following this security release. Review the release notes for your Drupal version if
    you have issues accessing private files after updating. This advisory is covered by Drupal Steward.
    Because this vulnerability is not mass exploitable, your Steward partner may respond by monitoring-only,
    rather than enforcing a new WAF rule. We would normally not apply for a release of this severity. However,
    in this case we have chosen to apply Drupal Steward security coverage to test our processes. Drupal 7 All
    Drupal 7 sites on Windows web servers are vulnerable. Drupal 7 sites on Linux web servers are vulnerable
    with certain file directory structures, or if a vulnerable contributed or custom file access module is
    installed. Drupal 9 and 10 Drupal 9 and 10 sites are only vulnerable if certain contributed or custom file
    access modules are installed. (SA-CORE-2023-005)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2023-005");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.0.8");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.96");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.4.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.5.8");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.96 / 9.4.14 / 9.5.8 / 10.0.8 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '7.0', 'fixed_version' : '7.96' },
  { 'min_version' : '9.4', 'fixed_version' : '9.4.14' },
  { 'min_version' : '9.5', 'fixed_version' : '9.5.8' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
