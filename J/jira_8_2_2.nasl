#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128423);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-8448");

  script_name(english:"Atlassian JIRA Information Disclosure Vulnerability (JRASERVER-69797)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is prior
to 7.13.4 or 8.0.x prior to 8.2.2. It is, therefore, affected by an information disclosure vulnerability in its 
login.jsp component due to insufficent validation of user input. An unauthenticated, remote attacker can exploit this, 
by sending crafted HTTP requests, to enumerate the usernames of the Jira users.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69797");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.13.4 / 8.2.2");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

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
  { 'fixed_version' : '7.13.4' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.2.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
