#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109344);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-7602");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/04");

  script_name(english:"Drupal 7.x < 7.59 / 8.4.x < 8.4.8 / 8.5.x < 8.5.3 Remote Code Execution Vulnerability (SA-CORE-2018-004)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 7.x prior to 7.59, 8.4.x prior to 8.4.8,
or 8.5.x prior to 8.5.3. It is, therefore, affected by a remote code
execution vulnerability.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2018-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.59");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.4.8");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.5.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.59 / 8.4.8 / 8.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7602");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Drupal 7 SA-CORE-2018-004 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:"Drupal", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "7.0", "max_version" : "7.58", "fixed_version" : "7.59" },
  { "min_version" : "8.4.0", "max_version" : "8.4.7", "fixed_version" : "8.4.8" },
  { "min_version" : "8.5.0", "max_version" : "8.5.2", "fixed_version" : "8.5.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
