##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161272);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_name(english:"GitLab 13.2 < 14.8.6 / 14.9.x < 14.9.4 / 14.10.x < 14.10.1 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"A source control application running on the remote web server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of GitLab running on the remote web server is 13.2 prior to
14.8.6, 14.9.x prior to 14.9.4, or 14.10.x prior to 14.10.1. It is, therefore, affected by the following vulnerability:

  - An information disclosure vulnerability exists in confidential notes feature of GitLab CE/EE. An
    authenticated, remote attacker can exploit this to disclose details of confidential notes to unauthorized
    project members.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/05/02/security-release-gitlab-14-10-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c46a7cbd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 14.8.6, 14.9.4, 14.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gitlab:gitlab");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("gitlab_webui_detect.nbin", "gitlab_nix_installed.nbin");
  script_require_keys("installed_sw/GitLab");

  exit(0);
}

include('vcf.inc');

var app = 'GitLab';

var app_info = vcf::combined_get_app_info(app:app);

# Remote detection can only get the first two segments. Anything between 14.8 and 14.10 requires paranoia if only 2 segments
if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "14\.([89]|10)([^0-9]|$)")
  if (!empty_or_null(app_info.port))
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version, app_info.port);
  else
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'min_version' : '13.2',  'fixed_version' : '14.8.6' },
  { 'min_version' : '14.9',  'fixed_version' : '14.9.4' },
  { 'min_version' : '14.10', 'fixed_version' : '14.10.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
