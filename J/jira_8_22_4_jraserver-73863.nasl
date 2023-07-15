##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162737);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/13");

  script_cve_id("CVE-2022-26135");
  script_xref(name:"IAVA", value:"2022-A-0261");

  script_name(english:"Atlassian Jira 8.0.x < 8.13.22 / 8.20.x < 8.20.10 / 8.22.x < 8.22.4 (JRASERVER-73863)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira installed on the remote host is prior to 8.0.x < 8.13.22 / 8.20.x < 8.20.10 / 8.22.x <
8.22.4. It is, therefore, affected by a vulnerability as referenced in the JRASERVER-73863 advisory.

  - Full Read SSRF in Mobile Plugin CVE-2022-26135 (CVE-2022-26135)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73863");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.22, 8.20.10, 8.22.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26135");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '8.0.0', 'fixed_version' : '8.13.22' },
  { 'min_version' : '8.20.9', 'fixed_version' : '8.20.10' },
  { 'min_version' : '8.22.3', 'fixed_version' : '8.22.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
