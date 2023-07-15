#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140765);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2020-13667",
    "CVE-2020-13668",
    "CVE-2020-13669",
    "CVE-2020-13670"
  );
  script_xref(name:"IAVA", value:"2020-A-0433-S");

  script_name(english:"Drupal 8.8.x < 8.8.10 / 8.9.x < 8.9.6 / 9.0.x < 9.0.6 Multiple Vulnerabilities (drupal-2020-09-16)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 8.8.x prior to 
8.8.10, 8.9.x prior to 8.9.6, or 9.0.x prior to 9.0.6. It is, therefore, affected by multiple vulnerabilities:
  - An information disclosure vulnerability exists in the File module. An authenticated, remote attacker can 
  exploit this, to disclose file metadata. (CVE-2020-13670).

  - An authentication bypass vulnerability exists in the Workspaces module due to insufficient checks on 
  assigned permissions. An unauthenticated, remote attacker can exploit this, by sending specially crafted 
  requests, to access restricted content before an administrator has made it publicly available (CVE-2020-13667).

  - A cross-site scripting (XSS) vulnerability exists in an undisclosed component of Drupal due to improper
  validation of user-supplied input before returning it to users. An unauthenticated, remote attacker can exploit 
  this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's 
  browser session (CVE-2020-13368).

  - A cross-site scripting (XSS) vulnerability exists in the CKEditor image caption functionality due to improper
  validation of user-supplied input before returning it to users. An authenticated, remote attacker can exploit 
  this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's 
  browser session (CVE-2020-13369).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-008");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-009");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-010");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-011");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.8.10");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.6");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.0.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.8.10 / 8.9.6 / 9.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '8.8', 'fixed_version' : '8.8.10' },
  { 'min_version' : '8.9', 'fixed_version' : '8.9.6' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.6' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);

