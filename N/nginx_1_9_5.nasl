#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86884);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"nginx 1.9.x < 1.9.6 HTTPv2 PRI Double-Free DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in its response header, the
version of nginx hosted on the remote web server is 1.9.x prior to
1.9.6. It is, therefore, affected by a denial of service vulnerability
due to a double-free memory error in the HTTPv2 module that is
triggered when handling certain PRI packets. An unauthenticated,
remote attacker can exploit this, via a crafted RPI packet, to cause a
section of heap-based memory to be freed twice, which can result in
crashing the server.");
  # http://www.security-assessment.com/files/documents/advisory/Nginx%20ngx_destroy_pool%20HTTP2%20Double%20Free.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6f9e7f");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2015/000163.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx version 1.9.6 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor release notes.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [{'fixed_version' : '1.9.6', 'min_version' : '1.9.0'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
