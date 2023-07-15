##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163328);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id("CVE-2020-36518", "CVE-2022-22965", "CVE-2022-23437");
  script_xref(name:"IAVA", value:"2022-A-0285");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");

  script_name(english:"Oracle Primavera Gateway (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Gateway installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2022 CPU advisory.

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component:
    Admin (jackson-databind)). Supported versions that are affected are 17.12.0-17.12.11, 18.8.0-18.8.14,
    19.12.0-19.12.13, 20.12.0-20.12.8 and 21.12.0-21.12.1. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Primavera Gateway. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Primavera Gateway. (CVE-2020-36518)

  - Vulnerability in the Primavera Gateway product of Oracle Construction and Engineering (component:
    Admin (Apache Xerces-J)). Supported versions that are affected are 17.12.0-17.12.11, 18.8.0-18.8.14,
    19.12.0-19.12.13 and 20.12.0-20.12.8. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Primavera Gateway. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Primavera Gateway.
    (CVE-2022-23437)

  - Security-in-Depth issue in the Primavera Gateway product of Oracle Construction and Engineering
    (component: Admin (Spring Framework)). This vulnerability cannot be exploited in the context of this
    product. (CVE-2022-22965)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Spring Framework Class property RCE (Spring4Shell)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

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
  { 'min_version' : '17.12.0', 'max_version' : '17.12.11.999999', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '18.8.0', 'fixed_version' : '18.8.15' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.14' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.9' },
  { 'min_version' : '21.12.0', 'max_version': '21.12.1', 'fixed_version' : '21.12.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
