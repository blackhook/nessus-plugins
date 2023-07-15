#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134978);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-20404");

  script_name(english:"Atlassian Jira 8.2.x < 8.6.0 Improper Authorization on Project Titles Information Disclosure Vulnerability (JRASERVER_70569)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is 
version 8.2.x prior to 8.6.0. It is, therefore, affected by an information disclosure vulnerability due to improper 
authorization checks. An authenticated, remote attacker can exploit this issue to disclose project titles.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://confluence.atlassian.com/jirasoftware/issues-resolved-in-8-6-0-983794874.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15ffd13d");
  # https://jira.atlassian.com/browse/JRASERVER-70569
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f3ffdbb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.6.0 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'min_version' : '8.2.0', 'fixed_version' : '8.6.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
