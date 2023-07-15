#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158095);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id("CVE-2022-25270", "CVE-2022-25271");
  script_xref(name:"IAVA", value:"2022-A-0090-S");

  script_name(english:"Drupal 7.x < 7.88 / 9.2.x < 9.2.13 / 9.3.x < 9.3.6 Multiple Vulnerabilities (drupal-2022-02-16)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.88,
9.2.x prior to 9.2.13, or 9.3.x prior to 9.3.6. It is, therefore, affected by multiple vulnerabilities.

  - The Quick Edit module does not properly check entity access in some circumstances. This could result in
    users with the access in-place editing permission viewing some content they are are not authorized to
    access. Sites are only affected if the QuickEdit module (which comes with the Standard profile) is
    installed. This advisory is not covered by Drupal Steward. (CVE-2022-25270)

  - Drupal core's form API has a vulnerability where certain contributed or custom modules' forms may be
    vulnerable to improper input validation. This could allow an attacker to inject disallowed values or
    overwrite data. Affected forms are uncommon, but in certain cases an attacker could alter critical or
    sensitive data. Also see Quick Edit - Moderately critical - Access bypass - SA-CONTRIB-2022-025 which
    addresses the same vulnerability for the contributed module. This advisory is not covered by Drupal
    Steward. (CVE-2022-25271)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/3227039");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.13");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.6");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.88");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-contrib-2022-025");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.88 / 9.2.13 / 9.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
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
  { 'min_version' : '7.0', 'fixed_version' : '7.88' },
  { 'min_version' : '9.2', 'fixed_version' : '9.2.13' },
  { 'min_version' : '9.3', 'fixed_version' : '9.3.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
