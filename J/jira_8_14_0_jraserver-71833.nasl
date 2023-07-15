##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162759);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/06");

  script_name(english:"Atlassian Jira 8.13.x < 8.14.0 SQLI (JRASERVER-71833)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira installed on the remote host is prior to 8.13.x < 8.14.0. It is, therefore, affected by a
vulnerability as referenced in the JRASERVER-71833 advisory.

  - Affected versions of Jira Server have a SQL injection vulnerability that has now been fixed by removing
    the vulnerable HipChat integration plugin. _*Affected versions:*_ * versions < 8.14.0 _*Fixed versions:*_
    * 8.14.0 The plugin is no longer installed in new versions of Jira. However, the removal of the plugin was
    not back-ported to an LTS release. Therefore, as a workaround, we recommend disabling the plugin.
    (atlassian-JRASERVER-71833)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71833");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.14.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'min_version' : '8.13.1', 'fixed_version' : '8.14.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
