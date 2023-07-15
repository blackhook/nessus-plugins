#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58750);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-2089");
  script_bugtraq_id(52999);

  script_name(english:"nginx 1.0.7 - 1.0.14 / 1.1.3 - 1.1.18 ngx_http_mp4_module Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy. 

According to its Server response header, the installed version of
nginx is between 1.0.7 and 1.0.14 or 1.1.3 and 1.1.18 and is,
therefore, affected by a buffer overflow vulnerability. 

An error in the module 'ngx_http_mp4_module' can allow a specially
crafted mp4 file to cause a buffer overflow and can potentially allow
arbitrary code execution. 

Note that successful exploitation requires that the 'mp4'
configuration option is enabled and the module 'ngx_http_mp4_module'
is enabled. Nessus has not checked for either of these settings.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.0");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.15 / 1.1.19 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'fixed_version' : '1.0.15', 'min_version' : '1.0.7'},
  {'fixed_version' : '1.1.19', 'min_version' : '1.1.3'}];
  
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
