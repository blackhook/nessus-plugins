#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172584);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");
  script_xref(name:"IAVA", value:"2023-A-0151-S");

  script_name(english:"Drupal 7.x < 7.95 / 9.4.x < 9.4.12 / 9.5.x < 9.5.5 / 10.x < 10.0.5 Multiple Vulnerabilities (drupal-2023-03-15)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.95,
9.4.x prior to 9.4.12, 9.5.x prior to 9.5.5, or 10.x prior to 10.0.5. It is, therefore, affected by multiple
vulnerabilities.

  - Drupal core provides a page that outputs the markup from phpinfo() to assist with diagnosing PHP
    configuration. If an attacker was able to achieve an XSS exploit against a privileged user, they may be
    able to use the phpinfo page to access sensitive information that could be used to escalate the attack.
    This vulnerability is mitigated by the fact that a successful XSS exploit is required in order to exploit
    it. (SA-CORE-2023-004)

  - The language module provides a Language switcher block which can be placed to provide links to quickly
    switch between different languages. The URL of unpublished translations may be disclosed. When used in
    conjunction with a module like Pathauto, this may reveal the title of unpublished content. This advisory
    is not covered by Drupal Steward. (SA-CORE-2023-003)

  - The Media module does not properly check entity access in some circumstances. This may result in users
    seeing thumbnails of media items they do not have access to, including for private files. This release was
    coordinated with SA-CONTRIB-2023-010. This advisory is not covered by Drupal Steward. (SA-CORE-2023-002)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2023-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.0.5");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.95");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.4.12");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.5.5");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2023-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2023-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-contrib-2023-010");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.95 / 9.4.12 / 9.5.5 / 10.0.5 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

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
  { 'min_version' : '7.0', 'fixed_version' : '7.95' },
  { 'min_version' : '9.4', 'fixed_version' : '9.4.12' },
  { 'min_version' : '9.5', 'fixed_version' : '9.5.5' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
