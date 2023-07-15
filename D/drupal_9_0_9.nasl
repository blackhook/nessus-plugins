#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143274);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/29");

  script_cve_id("CVE-2020-28948", "CVE-2020-28949");
  script_xref(name:"IAVA", value:"2020-A-0545-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"Drupal 7.x < 7.75 / 8.x < 8.8.12 / 8.9.x < 8.9.10 / 9.0.x < 9.0.9 Multiple Vulnerabilities (SA-CORE-2020-013)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.75,
8.x prior to 8.8.12, 8.9.x prior to 8.9.10, or 9.0.x prior to 9.0.9. It is, therefore, affected by multiple
vulnerabilities:

  - Archive_Tar through 1.4.10 allows an unserialization attack because phar: is blocked but PHAR: is not
    blocked. (CVE-2020-28948)

  - Archive_Tar through 1.4.10 has :// filename sanitization only to address phar attacks, and thus any other
    stream-wrapper attack (such as file:// to overwrite files) can still succeed. (CVE-2020-28949)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-013");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/1173280");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.75");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.8.12");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.10");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.0.9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.75 / 8.8.12 / 8.9.10 / 9.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28949");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PEAR Archive_Tar 1.4.10 Arbitrary File Write');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.75' },
  { 'min_version' : '8.0', 'fixed_version' : '8.8.12' },
  { 'min_version' : '8.9', 'fixed_version' : '8.9.10' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
