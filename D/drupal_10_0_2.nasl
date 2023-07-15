#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170730);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");
  script_xref(name:"IAVA", value:"2023-A-0052-S");

  script_name(english:"Drupal 9.4.x < 9.4.10 / 9.5.x < 9.5.2 / 10.0.x < 10.0.2 Drupal Vulnerability (SA-CORE-2023-001) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.4.x prior to 9.4.10
or 9.5.x prior to 9.5.2 or 10.0.x prior to 10.0.2. It is, therefore, affected by a vulnerability.

  - The Media Library module does not properly check entity access in some circumstances. This may result in
    users with access to edit content seeing metadata about media items they are not authorized to access. The
    vulnerability is mitigated by the fact that the inaccessible media will only be visible to users who can
    already edit content that includes a media reference field. This advisory is not covered by Drupal
    Steward. (SA-CORE-2023-001)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2023-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.0.2");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.4.10");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.5.2");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 9.4.10 / 9.5.2 / 10.0.2 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '9.4', 'fixed_version' : '9.4.10' },
  { 'min_version' : '9.5', 'fixed_version' : '9.5.2' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
