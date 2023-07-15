##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163432);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-26136");

  script_name(english:"Atlassian Jira < 8.13.22 / 8.20.x < 8.20.10 / 8.22.x < 8.22.4 / 9.0.0 XSS (JRASERVER-73897)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Server running on the remote host is affected by a vulnerability as referenced in the
JRASERVER-73897 advisory.

  - A vulnerability in multiple Atlassian products allows a remote, unauthenticated attacker to bypass Servlet
    Filters used by first and third party apps. The impact depends on which filters are used by each app, and
    how the filters are used. This vulnerability can result in authentication bypass and cross-site scripting.
    Atlassian has released updates that fix the root cause of this vulnerability, but has not exhaustively
    enumerated all potential consequences of this vulnerability. Atlassian Bamboo versions are affected before
    8.0.9, from 8.1.0 before 8.1.8, and from 8.2.0 before 8.2.4. Atlassian Bitbucket versions are affected
    before 7.6.16, from 7.7.0 before 7.17.8, from 7.18.0 before 7.19.5, from 7.20.0 before 7.20.2, from 7.21.0
    before 7.21.2, and versions 8.0.0 and 8.1.0. Atlassian Confluence versions are affected before 7.4.17,
    from 7.5.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4,
    from 7.17.0 before 7.17.4, and version 7.21.0. Atlassian Crowd versions are affected before 4.3.8, from
    4.4.0 before 4.4.2, and version 5.0.0. Atlassian Fisheye and Crucible versions before 4.8.10 are affected.
    Atlassian Jira versions are affected before 8.13.22, from 8.14.0 before 8.20.10, and from 8.21.0 before
    8.22.4. Atlassian Jira Service Management versions are affected before 4.13.22, from 4.14.0 before
    4.20.10, and from 4.21.0 before 4.22.4. (CVE-2022-26136)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73897");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.22, 8.20.10, 8.22.4, 9.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'fixed_version' : '8.13.22', 'fixed_display' : '8.13.22 / 8.20.10 / 8.22.4 / 9.0.0' },
  { 'min_version' : '8.20.9', 'fixed_version' : '8.20.10' },
  { 'min_version' : '8.22.3', 'fixed_version' : '8.22.4', 'fixed_display' : '8.22.4 / 9.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
