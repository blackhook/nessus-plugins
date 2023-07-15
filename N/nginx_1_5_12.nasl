#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73519);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0133");
  script_bugtraq_id(66537);

  script_name(english:"nginx < 1.4.7 / 1.5.12 SPDY Heap Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a heap buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in the server response header,
the installed 1.3.x version of nginx is 1.3.15 or higher, or 1.4.x
prior to 1.4.7, or 1.5.x prior to 1.5.12. It is, therefore, affected
by a heap buffer overflow vulnerability.

A flaw exists with the SPDY protocol implementation where user input
is not properly validated. This could allow a remote attacker to cause
a heap-based buffer overflow, causing a denial of service or potential
arbitrary code execution.

Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2014/000135.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/download/patch.2014.spdy2.txt");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES-1.4");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Apply the patch manually or upgrade to nginx 1.4.7 / 1.5.12 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'fixed_version' : '1.4.7', 'min_version' : '1.3.15'},
  {'fixed_version' : '1.5.12', 'min_version' : '1.5.0'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
