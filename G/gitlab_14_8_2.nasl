#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158560);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2022-0735", "CVE-2022-0741", "CVE-2022-0751");
  script_xref(name:"IAVA", value:"2022-A-0099-S");

  script_name(english:"GitLab 12.10.x < 14.6.5 / 14.7.x < 14.7.4 / 14.8.x < 14.8.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A source control application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of GitLab running on the remote web server is prior to 12.10.x
prior to 14.6.5, 14.7.x prior to 14.7.4, or 14.8.x prior to 14.8.2. It is, therefore, affected by the following
vulnerabilities:

  - An unauthorized user can steal runner registration tokens using an information disclosure vulnerability by
    using quick commands. (CVE-2022-0735)

  - An unauthorized user can steal environment variables using specially crafted email addresses due to
    improper input validation in sendmail. (CVE-2022-0741)

  - An unauthorized user can trick users into executing arbitrary commands due to inaccurate display of
    Snippet files with special characters. (CVE-2022-0751)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/02/25/critical-security-release-gitlab-14-8-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35c16f9f");
  # https://portswigger.net/daily-swig/critical-gitlab-vulnerability-could-allow-attackers-to-steal-runner-registration-tokens
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b85d5630");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 14.6.5, 14.7.4, 14.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gitlab:gitlab");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("gitlab_webui_detect.nbin");
  script_require_keys("installed_sw/GitLab");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'GitLab';
var port = get_http_port(default:80);

var app_info = vcf::combined_get_app_info(app:app);

# Remote detection can only get the first two segments. Anything between 12.10 and 14.8 requires paranoia if only 2 segments
if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "12\.[1-9][0-9]|13\.|(14\.[0-8]([^0-9]|$))")
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version, port);

var constraints = [
  { 'min_version' : '12.10',  'fixed_version' : '14.6.5' },
  { 'min_version' : '14.7',  'fixed_version' : '14.7.4' },
  { 'min_version' : '14.8', 'fixed_version' : '14.8.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
