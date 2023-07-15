#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128282);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-11585", "CVE-2019-11589");

  script_name(english:"Atlassian JIRA Open Redirect Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially 
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian JIRA hosted on the remote web server is prior to 7.3.16, 
8.2.x prior to 8.2.3, or 8.3.x prior to 8.3.2. It is, therefore, affected
by multiple vulnerabilities:

  - An open rediect vulnerability exists in startup.jsp. An 
    unauthenticated, remote attacker can exploit this by convincing 
    a user to click a specially crafted URL, to redirect the 
    user's browser to an unexpected malicious page. 
    (CVE-2019-11585)

  - An open redirect vulnerability exists in the ChangeSharedFilterOwner
    resource. An unauthenticated, remote attacker can exploit 
    this by convincing a user to click a specially crafted URL, 
    to redirect the user's browser and potentially steal their 
    CSRF token. (CVE-2019-11589)");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69780");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69784");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.13.6 / 8.2.3 / 8.3.2  or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11589");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");

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
  { 'fixed_version' : '7.13.6' },
  { 'min_version' : '8.2.0', 'fixed_version' : '8.2.3' },
  { 'min_version' : '8.3.0', 'fixed_version' : '8.3.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xsrf:true});
