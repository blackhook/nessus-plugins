#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134979);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2008-4789",
    "CVE-2008-4790",
    "CVE-2008-4791",
    "CVE-2008-4792",
    "CVE-2008-4793"
  );
  script_bugtraq_id(
    84731,
    84742,
    84753,
    84778,
    84780
  );

  script_name(english:"Drupal 5.x < 5.11 / 6.x < 6.5 Multiple Vulnerabilities (SA-2008-060)");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 5.x prior to 5.11 or 6.x prior to 6.5. It is, therefore,
affected by the following vulnerabilities:

  - The validation functionality in the core upload module in Drupal 6.x before 6.5 allows remote,
    authenticated users to bypass intended access restrictions and attach files to content, related to a
    logic error. (CVE-2008-4789)
  
  - The core upload module in Drupal 5.x before 5.11 allows remote authenticated users to bypass intended
    access restrictions and read files attached to content via unknown vectors.(CVE-2008-4790)

  - The user module in Drupal 5.x before 5.11 and 6.x before 6.5 allows remote authenticated users to bypass
    intended login access rules and successfully login via unknown vectors.(CVE-2008-4791)

  - The core BlogAPI module in Drupal 5.x before 5.11 and 6.x before 6.5 does not properly validate
    unspecified content fields of an internal Drupal form, which allows remote, authenticated users to bypass
    intended access restrictions via modified field values. (CVE-2008-4792)

  - The node module API in Drupal 5.x before 5.11 allows remote attackers to bypass node validation and have
    unspecified other impact via unknown vectors related to contributed modules. (CVE-2008-4793)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/318706");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/5.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/6.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 5.11, 6.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4793");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '5.0', 'fixed_version' : '5.11' },
  { 'min_version' : '6.0', 'fixed_version' : '6.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
