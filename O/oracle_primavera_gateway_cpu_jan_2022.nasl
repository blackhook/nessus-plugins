#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156893);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-44832");
  script_xref(name:"IAVA", value:"0001-A-0650");

  script_name(english:"Oracle Primavera Gateway (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 17.12.11, 18.8.13, 19.12.12, 20.12.7, and 21.12.0 versions of Primavera Gateway installed on the remote host are
affected by a vulnerability as referenced in the January 2022 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component: Admin (Apache
    Log4j)). Supported versions that are affected are 17.12.0-17.12.11, 18.8.0-18.8.13, 19.12.0-19.12.12,
    20.12.0-20.12.7 and 21.12.0. Difficult to exploit vulnerability allows high privileged attacker with network access
    via HTTP to compromise Primavera Gateway. Successful attacks of this vulnerability can result in takeover of
    Primavera Gateway. Note: This patch also addresses vulnerabilities CVE-2021-44228 and CVE-2021-45046. Customers need
    not apply the patches/mitigations of Security Alert CVE-2021-44228 and CVE-2021-45046 for this product.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_gateway.nbin");
  script_require_keys("installed_sw/Oracle Primavera Gateway");
  script_require_ports("Services/www", 8006);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera Gateway', exit_if_zero:TRUE);

var port = get_http_port(default:8006);

var app_info = vcf::get_app_info(app:'Oracle Primavera Gateway', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '17.12.0', 'max_version' : '17.12.11', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '18.8.0', 'fixed_version' : '18.8.14' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.13' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.8' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
