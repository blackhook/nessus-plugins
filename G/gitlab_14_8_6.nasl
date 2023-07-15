##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160671);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/13");

  script_cve_id("CVE-2022-1413", "CVE-2022-1416", "CVE-2022-1423");
  script_xref(name:"IAVA", value:"2022-A-0187-S");

  script_name(english:"GitLab 1.0.2 < 14.8.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A source control application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of GitLab running on the remote web server is 1.0.2 prior to
14.8.6. It is, therefore, affected by the following vulnerabilities:

  - An information disclosure vulnerability exists in GitLab CE/EE due to missing input masking. An
    authenticated, remote attacker can exploit this to view sensitive integration properties in the web
    interface. (CVE-2022-1413)

  - An vulnerability exists in GitLab CE/EE due to missing sanitization of data in Pipeline error messages. An
    authenticated, remote attacker can exploit this to render attacker controlled HTML tags and CSS styling.
    (CVE-2022-1416)

  - An improper access control flaw exists in the CI/CD cache mechanism in GitLab CE/EE. An authenticated,
    remote attacker can exploit this to perform cache poisoning leading to arbitrary code execution in
    protected branches. (CVE-2022-1423)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/05/02/security-release-gitlab-14-10-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c46a7cbd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 14.8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gitlab:gitlab");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include('http.inc');

var app = 'GitLab';

var app_info = vcf::combined_get_app_info(app:app);

# Remote detection can only get the first two segments. 14.8 requires paranoia if only 2 segments
if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "14\.8([^0-9]|$)")
  if (!empty_or_null(app_info.port))
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version, app_info.port);
  else
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'min_version' : '1.0.2', 'fixed_version' : '14.8.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
