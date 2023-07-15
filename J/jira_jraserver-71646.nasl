#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143272);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-14183");
  script_xref(name:"IAVA", value:"2020-A-0432");

  script_name(english:"Atlassian JIRA < 7.13.18 / 8.0.x < 8.5.9 / 8.6.x < 8.12.1  Information Disclosure  (JRASERVER-71646)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by  Information Disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian JIRA hosted on the remote web server is
potentially affected by Information Disclosure vulnerability. Affected versions of Jira Server & Data Center allow
a remote attacker with limited (non-admin) privileges to view a Jira instance's Support Entitlement Number (SEN) via
an Information Disclosure vulnerability in the HTTP Response headers.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-71646");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 7.13.18 / 8.5.9 / 8.12.1 / 8.13.0 / 8.14.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/27");

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
  { 'fixed_version' : '7.13.18' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.5.9' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.12.1', 'fixed_display' : '8.12.1 / 8.13.0 / 8.14.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
