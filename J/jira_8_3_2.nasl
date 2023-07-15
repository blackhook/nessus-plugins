#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129589);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2019-8446",
    "CVE-2019-8447",
    "CVE-2019-11584",
    "CVE-2019-15005"
  );

  script_name(english:"Atlassian JIRA < 8.3.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, The version of Atlassian JIRA hosted on the remote web server is 7.6 < 8.3.2. 
It is therefore affected by the following vulnerabilities:

  - An incorrect authorization check on the /rest/issueNav/1/issueTable resource 
    in Jira allows remote attackers to enumerate usernames. (CVE-2019-8446)

  - A cross-site request forgery (XSRF) vulnerability exists in Jira due to
    ServiceExecutor. A remote attacker can exploit this to trigger the creation 
    of export files. (CVE-2019-8447)

  - A cross-site scripting (XSS) vulnerability exists due to improper validation of priority
    icon url of issue priority. An unauthenticated, remote attacker can exploit this,
    by convincing a user to click a specially crafted URL, to execute arbitrary script code
    in a user's browser session. (CVE-2019-11584)
  
  - An information disclosure vulnerability exists in the Atlassian 
    Troubleshooting and Support Tools plugin due to a missing 
    authorization check. An authenticated, remote attacker 
    can exploit this to initiate periodic log scans and send the
    results to a user-specified email address disclosing configuration
    information.(CVE-2019-15005)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69777");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69776");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-69785");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSWSERVER-20255");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 8.3.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8446");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11584");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");

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

constraints = [{ 'min_version' : '7.6', 'fixed_version' : '8.3.2' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE, xsrf:TRUE} );
