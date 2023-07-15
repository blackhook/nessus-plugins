#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154297);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-2351",
    "CVE-2021-23337",
    "CVE-2021-29425",
    "CVE-2021-36090",
    "CVE-2021-36374"
  );
  script_xref(name:"IAVA", value:"2021-A-0480");

  script_name(english:"Oracle Primavera Gateway (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Primavera Gateway installed on the remote host is affected by multiple vulnerabilities as referenced in
the October 2021 CPU advisory, including the following:

  - Vulnerability in the Oracle Retail Store Inventory Management product of Oracle Retail Applications
    (component: SIM Integration (JDBC)). Supported versions that are affected are 14.1, 15.0 and 16.0.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via Oracle Net to
    compromise Oracle Retail Store Inventory Management. Successful attacks require human interaction from a
    person other than the attacker and while the vulnerability is in Oracle Retail Store Inventory Management,
    attacks may significantly impact additional products. Successful attacks of this vulnerability can result
    in takeover of Oracle Retail Store Inventory Management. (CVE-2021-2351)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: File
    Management (Apache Commons Compress)). Supported versions that are affected are 17.7-17.12, 18.8, 19.12
    and 20.12. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP
    to compromise Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Primavera Unifier. (CVE-2021-36090)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component:
    Platform, UI (Lodash)). Supported versions that are affected are 17.7-17.12, 18.8, 19.12 and 20.12. Easily
    exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise
    Primavera Unifier. (CVE-2021-23337)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23337");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '18.8.0', 'fixed_version': '18.8.13' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.12' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.7.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
