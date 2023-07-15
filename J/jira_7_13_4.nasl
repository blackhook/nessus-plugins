#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125629);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-8442", "CVE-2019-8443");
  script_bugtraq_id(108458, 108460);

  script_name(english:"Atlassian Jira 7.13.x < 7.13.4, 8.0.x < 8.0.4, 8.1.x < 8.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
potentially affected by multiple vulnerabilities:

  - A directory traversal vulnerability exists in the CachingResourceDownloadRewriteRule class due to an
    ineffective path access check. An unauthenticated, remote attacker can exploit this, by accessing files in
    the Jira webroot under the META-INF. (CVE-2019-8442)

  - An authentication bypass vulnerability exists in the ViewUpgrades resource due to an improper access
    control. An unauthenticated, remote attacker can exploit this, to bypass WebSudo authentication and access
    the ViewUpgrades administrative resource. (CVE-2019-8443)");
  # https://jira.atlassian.com/browse/JRASERVER-69241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d90b4cf");
  # https://jira.atlassian.com/browse/JRASERVER-69240
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8601f74e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 7.13.4 / 8.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8443");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Atlassian JIRA File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');


constraints = [
  { 'min_version' : '7.13.0', 'fixed_version' : '7.13.4' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
