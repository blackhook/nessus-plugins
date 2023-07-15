#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134220);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-20372");
  script_xref(name:"IAVB", value:"2020-B-0013-S");

  script_name(english:"nginx < 1.17.7 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its Server response header, the installed version of
nginx is prior to 1.17.7. It is, therefore, affected by an information
disclosure vulnerability.");
  # https://nginx.org/en/CHANGES
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd026623");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx version 1.17.7 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [
  {'fixed_version' : '1.17.7'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
