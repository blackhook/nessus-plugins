#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58413);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-4315");
  script_bugtraq_id(50710);

  script_name(english:"nginx < 1.0.10 ngx_resolver_copy Function DNS Response Parsing Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy.

According to its Server response header, the installed version of
nginx is earlier than 1.0.10 and is, therefore, affected by a
heap-based buffer overflow vulnerability.

An issue related to DNS response parsing exists in the function
'ngx_resolver_copy' in the file 'ngx_resolver.c' which can allow
remote attackers to cause a denial of service or possibly execute
arbitrary code.

Note that successful exploitation requires this application's custom
DNS resolver to be enabled and that this custom resolver is not
enabled by default.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.0");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2011/11/17/8");
  script_set_attribute(attribute:"see_also", value:"https://trac.nginx.org/nginx/changeset/4268/nginx");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.10 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

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


constraints = [{'fixed_version' : '1.0.10'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
