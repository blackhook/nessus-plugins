#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107265);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747");

  script_name(english:"nginx < 1.8.1 / 1.9.x < 1.9.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in its response header, the
version of nginx hosted on the remote web server is less than 1.8.1
or 1.9.x prior to 1.9.10. It is, therefore, affected by multiple
vulnerabilities as noted in the vendor advisory.");
  # http://mailman.nginx.org/pipermail/nginx-announce/2016/000169.html?_ga=2.132092239.1970067615.1517422514-1991149942.1517422514
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cf8b270");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2016/000168.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx version 1.8.1 / 1.9.10 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_detect.nasl", "nginx_nix_installed.nbin");
  script_require_keys("installed_sw/nginx");

  exit(0);
}

include('http.inc');
include('vcf.inc');

appname = 'nginx';
get_install_count(app_name:appname, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:appname);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:3);
# If the detection is only remote, Detection Method won't be set, and we should require paranoia
if (empty_or_null(app_info['Detection Method']) && report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  {'fixed_version' : '1.8.1'},
  {'fixed_version' : '1.9.10', 'min_version' : '1.9.0'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
