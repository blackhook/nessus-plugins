#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140660);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-14169");

  script_name(english:"Atlassian Jira 8.0 < 8.9.1 XSS in Quick Search (JRASERVER-71205)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
version 8.x prior to 8.9.1. It is, therefore, affected by a cross-site scripting (XSS) vulnerability in the quick search
component due to improper validation of user-supplied input before returning it to users. An unauthenticated, remote
attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a
user's browser session.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://confluence.atlassian.com/jirasoftware/issues-resolved-in-8-9-1-1005349334.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0476f57");
  # https://confluence.atlassian.com/jirasoftware/issues-resolved-in-8-10-0-1004948149.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6516b7b2");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71205");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.9.1, 8.10.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");

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
  { 'min_version' : '8.0.0', 'fixed_version' : '8.9.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});

