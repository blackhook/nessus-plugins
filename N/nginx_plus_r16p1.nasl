#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161696);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845");
  script_bugtraq_id(105868);

  script_name(english:"Nginx Plus R1 < R15-P2 / R16 < R16-P1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to it's self reported version, the installed version of Nginx Plus is R1 (built on Open Source version 
1.5.3-1) prior to R15-P2 or R16 (built on Open Source version 1.15.2) prior to R16-P1. It is,  therefore, affected by the 
following issues :

  - An unspecified error exists related to the module
    'ngx_http_v2_module' that allows excessive memory usage.
    (CVE-2018-16843)

  - An unspecified error exists related to the module
    'ngx_http_v2_module' that allows excessive CPU usage.
    (CVE-2018-16844)

  - An unspecified error exists related to the module
    'ngx_http_mp4_module' that allows worker process
    crashes or memory disclosure. (CVE-2018-16845)");
  script_set_attribute(attribute:"see_also", value:"https://docs.nginx.com/nginx/releases/");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2018/000220.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2018/000221.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nginx Plus R15-P2 / R16-P1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_nix_installed.nbin");
  script_require_keys("installed_sw/nginx plus");

  exit(0);
}

include('vcf_extras_nginx.inc');

var appname = 'Nginx Plus';
get_install_count(app_name:appname, exit_if_zero:TRUE);
var app_info = vcf::nginx_plus::combined_get_app_info(app:appname);

vcf::check_granularity(app_info:app_info, sig_segments:2);

# Nginx Plus has backported pactches to BOTH R15 and R16 releases at the same time
# CVE-2018-16843 Vulnerable Open Source Versions: 1.9.5-1.15.5 (Nginx Plus versions R8 -> 15-P2 or 16-P1)
# CVE-2018-16844 Vulnerable Open Source Versions: 1.9.5-1.15.5 (Nginx Plus versions R8 -> 15-P2 or 16-P1)
# CVE-2018-16845 Vulnerable Open Source Versions: 1.1.3-1.15.5, 1.0.7-1.0.15 (ALL Nginx Plus versions prior to R15-P2)

var constraints = [
  {'fixed_version' : '15.2', 'min_version' : '0', 'fixed_display' : 'R15-P2 / R16-P1'},
  {'fixed_version' : '16.1', 'min_version' : '16.0', 'fixed_display' : 'R16-P1'}
];

vcf::nginx_plus::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
