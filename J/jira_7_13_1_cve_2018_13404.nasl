#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124770);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-13404");
  script_bugtraq_id(107039);

  script_name(english:"Atlassian JIRA Server-Side Request Forgery (SSRF) Vulnerability (JRASERVER-68527)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by a server-side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is prior
to 7.6.10 or 7.7.x prior to 7.7.5 or 7.8.x prior to 7.8.5 or 7.9.x prior to 7.9.3 or 7.10.x prior 7.10.3 or 7.11.x 
prior to 7.11.3 or 7.12.x prior to 7.12.3 or 7.13.x prior to 7.13.1. It is, therefore, affected by a server-side 
request forgery vulnerability. A remote attacker, with administrator privileges, may exploit this vulnerability to 
determine the existence of internal hosts & open ports and obtain sensitive server information.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-68527");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.6.10 / 7.7.5 / 7.8.5 / 7.9.3 / 7.10.3 / 7.11.3 / 7.12.3 / 7.13.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

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
  { 'fixed_version' : '7.6.10' },
  { 'min_version' : '7.7.0', 'fixed_version' : '7.7.5' },
  { 'min_version' : '7.8.0', 'fixed_version' : '7.8.5' },
  { 'min_version' : '7.9.0', 'fixed_version' : '7.9.3' },
  { 'min_version' : '7.10.0', 'fixed_version' : '7.10.3' },
  { 'min_version' : '7.11.0', 'fixed_version' : '7.11.3' },
  { 'min_version' : '7.12.0', 'fixed_version' : '7.12.3' },
  { 'min_version' : '7.13.0', 'fixed_version' : '7.13.1' },
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
