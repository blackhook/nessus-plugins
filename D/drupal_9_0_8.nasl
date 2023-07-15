#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143126);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-13671");
  script_xref(name:"IAVA", value:"2020-A-0541-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Drupal 7.x < 7.74 / 8.x < 8.8.11 / 8.9.x < 8.9.9 / 9.0.x < 9.0.8 RCE (SA-CORE-2020-012)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.74,
8.x prior to 8.8.11, 8.9.x prior to 8.9.9, or 9.0.x prior to 9.0.8. It is, therefore, affected by a remote code 
execution vulnerability in its file upload functionality due to a failure to sanitize filenames. An authenticated, 
remote attacker can exploit this to execute arbitrary php code under certain hosting configurations.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-012");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.74");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.8.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.9");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.0.8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.74 / 8.8.11 / 8.9.9 / 9.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13671");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.74' },
  # Advisory states 8.8 *or earlier*. Interpreting this as 8.x 
  { 'min_version' : '8.0', 'fixed_version' : '8.8.11' },
  { 'min_version' : '8.9', 'fixed_version' : '8.9.9' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.8' }
];

vcf::check_granularity(app_info:app_info, sig_segments:2);

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
