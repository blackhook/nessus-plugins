#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161697);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"nginx R8 < R18-P1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to it's self reported version, the installed version of Nginx Plus is R8 (built on Open Source version 1.9.9) 
prior to R18-P1 (built on Open Source version 1.15.10). It is, therefore, affected by multiple denial of service 
vulnerabilities :

  - A denial of service vulnerability exists in the HTTP/2 protocol stack due to improper handling of exceptional
    conditions. An unauthenticated, remote attacker can exploit this, by manipulating the window size and stream
    priority of a large data request, to cause a denial of service condition. (CVE-2019-9511)

  - A denial of service vulnerability exists in the HTTP/2 protocol stack due to improper handling of exceptional
    conditions. An unauthenticated, remote attacker can exploit this, by creating multiple request streams and
    continually shuffling the priority of the streams, to cause a denial of service condition. (CVE-2019-9513)

  - A denial of service vulnerability exists in the HTTP/2 protocol stack due to improper handling of exceptional
    conditions. An unauthenticated, remote attacker can exploit this, by sending a stream of headers with a zero length
    header name and zero length header value, to cause a denial of service condition. (CVE-2019-9516)");
  script_set_attribute(attribute:"see_also", value:"https://docs.nginx.com/nginx/releases/");
  # https://www.nginx.com/blog/nginx-updates-mitigate-august-2019-http-2-vulnerabilities/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b562be58");
  # https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ca4073f");
  # http://nginx.org/en/security_advisories.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98fc786c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nginx Plus version R18-P1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_nix_installed.nbin");
  script_require_keys("installed_sw/nginx");

  exit(0);
}

include('vcf_extras_nginx.inc');

appname = 'Nginx Plus';
get_install_count(app_name:appname, exit_if_zero:TRUE);
app_info = vcf::nginx_plus::combined_get_app_info(app:appname);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  {'min_version' : '8.0', 'fixed_version' : '18.1', 'fixed_display' : 'R18-P1'}
];

vcf::nginx_plus::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
