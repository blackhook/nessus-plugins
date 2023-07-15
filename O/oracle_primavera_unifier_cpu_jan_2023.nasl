#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170193);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/24");

  script_cve_id(
    "CVE-2021-23358",
    "CVE-2022-34917",
    "CVE-2022-42003",
    "CVE-2022-42004"
  );
  script_xref(name:"IAVA", value:"2023-A-0049");

  script_name(english:"Oracle Primavera Unifier (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Unifier installed on the remote host are affected by multiple vulnerabilities as referenced in
the January 2023 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: User
    Interface (UnderscoreJS)). Supported versions that are affected are 18.8, 19.12, 20.12, 21.12 and 22.12.
    Difficult to exploit vulnerability allows high privileged attacker with network access via HTTP to
    compromise Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Primavera Unifier accessible data as well as unauthorized read access
    to a subset of Primavera Unifier accessible data. (CVE-2021-23358)
    
  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Event
    Streams and Communications (Apache Kafka)). Supported versions that are affected are 18.8, 19.12, 20.12,
    21.12 and 22.12. Easily exploitable vulnerability allows unauthenticated attacker with network access via
    HTTP to compromise Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Primavera Unifier.
    (CVE-2022-34917)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Management (jackson-databind)). Supported versions that are affected are 18.8, 19.12, 20.12, 21.12 and
    22.12. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to
    compromise Primavera Unifier. Successful attacks require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Primavera Unifier. (CVE-2022-42003)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera Unifier', exit_if_zero:TRUE);

var port = get_http_port(default:8002);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

var app_info = vcf::get_app_info(app:'Oracle Primavera Unifier', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '18.8', 'fixed_version' : '18.8.18.14' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.16.6' },
  { 'min_version' : '20.12', 'fixed_version' : '20.12.16.3' },
  { 'min_version' : '21.12', 'fixed_version' : '21.12.13' },
  { 'min_version' : '22.12', 'fixed_version' : '22.12.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
