#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58414);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-1180");
  script_bugtraq_id(52578);

  script_name(english:"nginx < 1.0.14 / 1.1.17 HTTP Header Response Memory Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host is affected by a memory disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running nginx, a lightweight, high
performance web server / reverse proxy and email (IMAP/POP3) proxy.

According to its Server response header, the installed version of
nginx is earlier than 1.0.14 or is 1.1.x before 1.1.17 and is,
therefore, affected by a memory disclosure vulnerability.

An issue related to the parsing of HTTP header responses can allow a
remote attacker to obtain the contents of previously freed memory.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.net/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.0");
  script_set_attribute(attribute:"see_also", value:"https://trac.nginx.org/nginx/changeset/4535/nginx");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.0.14 / 1.1.17 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
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

constraints = [
  {'fixed_version' : '1.0.14'},
  {'fixed_version' : '1.1.17', 'min_version' : '1.1.0'}];
  
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
