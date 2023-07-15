#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132775);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"nginx 0.8.x < 0.8.33 / 0.7.x < 0.7.65 Windows Filename Pseudonyms (CORE-2010-0121)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its server response header, the installed version of nginx is 0.7.52 and prior to 0.7.65, or 0.8.x prior
to 0.8.33. It is, therefore, affected by a flaw in Windows installations of nginx. This is due to nginx mishandling
DOS-compatible 8.3 short filenames. An unauthenticated, remote attacker can exploit this, via web requests, to
potentially bypass server-side include (SSI) directives.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # http://www.coresecurity.com/content/filename-pseudonyms-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7e0ca7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx 0.7.65 or 0.8.33 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the CoreLabs advisory.");
  script_cwe_id(22, 755);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_detect.nasl", "nginx_nix_installed.nbin");
  script_require_keys("installed_sw/nginx");

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'nginx', exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:'nginx');
vcf::check_all_backporting(app_info:app_info);
vcf::check_granularity(app_info:app_info, sig_segments:3);
# If the detection is only remote, Detection Method won't be set, and we should require paranoia
if (empty_or_null(app_info['Detection Method']) && report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  { 'min_version' : '0.7.52', 'fixed_version' : '0.7.65' },
  { 'min_version' : '0.8.0', 'fixed_version' : '0.8.33' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
