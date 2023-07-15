#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110125);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-5230", "CVE-2018-5231");
  script_bugtraq_id(104205);

  script_name(english:"Atlassian JIRA 7.6.5 / 7.7.x < 7.7.4 / 7.8.x < 7.8.4 / 7.9.x < 7.9.2 Multiple Vulnerabilities (SB18-141)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially 
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian JIRA hosted on the remote web server is potentially 
affected by multiple vulnerabilities:

  - Atlassian JIRA contains a flaw that allows a reflected 
    cross-site scripting (XSS) attack. This flaw exists because 
    the issue collector does not properly sanitize input to 
    error messages for custom fields before returning it to users. 
    This may allow a context-dependent attacker to create a 
    specially crafted request that executes arbitrary script code 
    in a user's browser session within the trust relationship 
    between their browser and the server. (CVE-2018-5230)
  
  - Atlassian JIRA contains a flaw in the ForgotLoginDetails 
    resource that is triggered during the handling of a specially 
    crafted request. This may allow a remote attacker to cause 
    a denial of service. (CVE-2018-5231)");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-67289");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-67290");
  script_set_attribute(attribute:"see_also", value:"https://www.us-cert.gov/ncas/bulletins/SB18-141");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.6.6 / 7.7.4 / 7.8.4 / 7.9.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5230");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/25");

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

# no min based on advisory language : 
# The issue collector in Atlassian Jira before version 7.6.6,
constraints = [
  { 'fixed_version' : '7.6.6' },
  { 'min_version' : '7.7.0', 'fixed_version' : '7.7.4' },
  { 'min_version' : '7.8.0', 'fixed_version' : '7.8.4' },
  { 'min_version' : '7.9.0', 'fixed_version' : '7.9.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
