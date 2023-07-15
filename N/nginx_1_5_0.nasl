#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66672);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-2028", "CVE-2013-2070");
  script_bugtraq_id(59699, 59824);
  script_xref(name:"EDB-ID", value:"25499");
  script_xref(name:"EDB-ID", value:"26737");
  script_xref(name:"EDB-ID", value:"32277");

  script_name(english:"nginx ngx_http_proxy_module.c Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its Server response header, the installed version of nginx
is 1.1.4 through 1.2.8, 1.3.x, or 1.4.x prior to 1.4.1.  It
is, therefore, affected by multiple vulnerabilities :

  - A stack-based buffer overflow in 'ngx_http_parse.c' may
    allow a remote attacker to execute arbitrary code or
    trigger a denial of service condition via a specially
    crafted HTTP request. This vulnerability only affects
    versions greater than or equal to 1.3.9 and less than
    1.4.1. (CVE-2013-2028)

  - A memory disclosure vulnerability in 'ngx_http_parse.c'
    affects servers that use 'proxy_pass' to untrusted
    upstream servers.  This issue can be triggered by a
    remote attacker via a specially crafted HTTP request.
    Failed attempts may result in a denial of service
    condition. (CVE-2013-2070)");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000112.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000114.html");
  script_set_attribute(attribute:"solution", value:
"Either apply the patch manually or upgrade to nginx 1.4.1 / 1.5.0 or
later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2028");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'1.1.4', 'max_version':'1.2.8', 'fixed_display':'1.4.1 / 1.5.0'},
  {'min_version':'1.3.0', 'fixed_version' : '1.4.1'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
