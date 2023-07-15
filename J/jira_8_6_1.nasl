#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134759);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-20105");
  script_xref(name:"IAVA", value:"2020-A-0107-S");

  script_name(english:"Atlassian JIRA < 7.13.12 / 8.x < 8.5.4 / 8.6.x < 8.6.1 'Atlassian Application Links' Plugin Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian JIRA hosted on the remote web server is before 7.13.12,
or 8.x before 8.5.4, or 8.6.x before 8.6.1. It is, therefore,
affected by an improper authorization check related to the Atlassian
Application Links plugin that allows a remote attacker with
administrator privileges to edit existing applinks without passing
'WebSudo'.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-70526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.13.12 / 8.5.4 / 8.6.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20105");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include('http.inc');

app_info = vcf::combined_get_app_info(app:"Atlassian JIRA");

constraints = [
  { 'fixed_version' : '7.13.12' },
  { 'min_version':'8.0', 'fixed_version' : '8.5.4' },
  { 'min_version':'8.6', 'fixed_version' : '8.6.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
