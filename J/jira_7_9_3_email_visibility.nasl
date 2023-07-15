#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117338);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-13391");
  script_bugtraq_id(105165);

  script_name(english:"Atlassian JIRA ProfileLinkUserFormat Information Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a 
vulnerability which allows remote attackers who can access and
view an issue the ability to obtain the email address of the
reporter and assignee despite the email visibility setting being set to hidden.");
  script_set_attribute(attribute:"description", value:
"The ProfileLinkUserFormat component of Jira Server before version 
7.6.8, from version 7.7.0 before version 7.7.5, from version 7.8.0 
before version 7.8.5, from version 7.9.0 before version 7.9.3, from 
version 7.10.0 before version 7.10.3 and from version 7.11.0 before 
version 7.11.2 allows remote attackers who can access & view an issue
 to obtain the email address of the reporter and assignee user of an 
issue despite the configured email visibility setting being set to 
hidden.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-67750");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.6.8 / 7.7.5 / 7.8.5 / 7.9.3 / 7.10.3 / 7.11.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/07");

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

# based on advisory language : 
# The ProfileLinkUserFormat component of Jira Server before version 7.6.8...
constraints = [
  { 'fixed_version' : '7.6.8' },
  { 'min_version' : '7.7.0', 'fixed_version' : '7.7.5' },
  { 'min_version' : '7.8.0', 'fixed_version' : '7.8.5' },
  { 'min_version' : '7.9.0', 'fixed_version' : '7.9.3' },
  { 'min_version' : '7.10.0', 'fixed_version' : '7.10.3' },
  { 'min_version' : '7.11.0', 'fixed_version' : '7.11.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
