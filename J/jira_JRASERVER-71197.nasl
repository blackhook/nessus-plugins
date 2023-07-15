#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138360);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-14167");
  script_xref(name:"IAVA", value:"2020-A-0284-S");

  script_name(english:"Atlassian JIRA < 7.13.14 / 8.5.x < 8.5.5 / 8.8.x < 8.8.2 / 8.9.x < 8.9.1 DoS (JRASERVER-71197)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is 
prior to 7.3.14, 8.5.x prior to 8.5.5, 8.8.x prior to 8.8.2 or 8.9.x prior to 8.9.1. It is, therefore, affected by a 
denial of service (DoS) vulnerability in its Dashboard & Gadgets components. An unauthenticated, remote attacker can 
exploit this issue, by sending a specially crafted request, to impose a DoS condition on the application.
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71197");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.13.14, 8.5.5, 8.8.2, 8.9.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

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

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'fixed_version' : '7.13.14' },
  { 'min_version':'8.5', 'fixed_version' : '8.5.5'},
  { 'min_version':'8.8', 'fixed_version' : '8.8.2'},
  { 'min_version':'8.9', 'fixed_version' : '8.9.1', 'fixed_display': '8.9.1 / 8.10.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
