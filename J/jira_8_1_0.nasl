#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132728);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-20239");

  script_name(english:"Atlassian JIRA < 7.13.3 / 8.x < 8.1 XSS vulnerability (JRASERVER-68855)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by an XSS vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is prior
to 7.13.3 or 8.1.0. It is, therefore, affected by a cross-site scripting (XSS) vulnerability in the applinkStartingUrl 
parameter due to improper validation of user-supplied input data. An authenticated, remote attacker can exploit this 
by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-68855");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.13.3 / 8.1.0 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'min_version' : '0.0.0', 'fixed_version' : '7.13.3' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.1.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
