#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148935);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"2021-A-0200-S");

  script_name(english:"Drupal 7.x < 7.80 / 8.9.x < 8.9.14 / 9.x < 9.0.12 / 9.1.x < 9.1.7 XSS (SA-CORE-2021-002)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.80,
8.9.x prior to 8.9.14, 9.x prior to 9.0.12, or 9.1.x prior to 9.1.7. It is, therefore, affected by a vulnerability.

  - Drupal core's sanitization API fails to properly filter cross-site scripting under certain circumstances.
    Not all sites and users are affected, but configuration changes to prevent the exploit might be
    impractical and will vary between sites. Therefore, we recommend all sites update to this release as soon
    as possible. (SA-CORE-2021-002)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.80");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.0.12");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.1.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.80 / 8.9.14 / 9.0.12 / 9.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE assigned");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [
  { 'min_version' : '7', 'fixed_version' : '7.80' },
  { 'min_version' : '8.9', 'fixed_version' : '8.9.14' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.12' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
