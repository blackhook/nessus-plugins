#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(41608);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-2629", "CVE-2009-3896");
  script_bugtraq_id(36384, 36839);
  script_xref(name:"CERT", value:"180065");

  script_name(english:"nginx HTTP Request Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy.

According to its Server response header, the installed version of
nginx is affected by multiple vulnerabilities : - A remote buffer
overflow attack related to its parsing of complex URIs.

  - A remote denial of service attack related to its parsing
    of HTTP request headers.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-0.7");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-0.6");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-0.5");
  script_set_attribute(attribute:"see_also", value:"http://sysoev.ru/nginx/patch.180065.txt");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2009/Oct/306");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.8.15, 0.7.62, 0.6.39, 0.5.38, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2629");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(119);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'0.1.0', 'fixed_version':'0.5.38'},
  {'min_version':'0.6.0', 'fixed_version':'0.6.39'},
  {'min_version':'0.7.0', 'fixed_version':'0.7.62'},
  {'min_version':'0.8.0', 'fixed_version':'0.8.15'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
