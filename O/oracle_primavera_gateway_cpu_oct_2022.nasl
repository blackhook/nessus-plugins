#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166331);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id("CVE-2022-31129");
  script_xref(name:"IAVA", value:"2022-A-0434-S");

  script_name(english:"Oracle Primavera Gateway (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service (DoS) vulnerability");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Gateway installed on the remote host are affected by a denial of service vulnerability as
referenced in the October 2022 CPU advisory. This vulnerability is in the Primavera Gateway product of Oracle
Construction and Engineering (component: Admin (Moment.js)). Supported versions that are affected are 18.8.0-18.8.15,
19.12.0-19.12.14, 20.12.0-20.12.9 and 21.12.0-21.12.7. This is an easily exploitable vulnerability that allows
unauthenticated attackers with network access via HTTP to compromise Primavera Gateway. Successful attacks of this
vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of
Primavera Gateway. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '18.8.0', 'fixed_version' : '18.8.16', 'fixed_display':'See vendor advisory' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.15' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.10' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
