#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154879);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id("CVE-2021-22205");
  script_xref(name:"IAVA", value:"2021-A-0523-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"GitLab 7.12.x < 13.8.8 / 13.9.x < 13.9.6 / 13.10.x < 13.10.3 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A source control application running on the remote web server is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of GitLab running on the remote web server is prior to 13.8.8,
13.9.x prior to 13.9.6, or 13.10.x prior to 13.10.3. It is, therefore, affected by a remote code execution due to not
properly validating image files being passed to a file parser. An authenticated, remote attacker can exploit this, by
uploading a malicious image file, to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0f673b6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 13.8.8 / 13.9.6 / 13.10.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22205");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'GitLab Unauthenticated Remote ExifTool Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gitlab:gitlab");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Remote detection can only get the first two segments. Anything between 13.8 and 13.10 requires paranoia if only 2 segments
if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "13\.(8|9|10)([^0-9]|$)")
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version, port);

var constraints = [
  { 'min_version' : '7.12',  'fixed_version' : '13.8.8' },
  { 'min_version' : '13.9',  'fixed_version' : '13.9.6' },
  { 'min_version' : '13.10', 'fixed_version' : '13.10.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
