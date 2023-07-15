#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138508);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-1945",
    "CVE-2020-9546",
    "CVE-2020-9547",
    "CVE-2020-9548",
    "CVE-2020-10650",
    "CVE-2020-10672",
    "CVE-2020-10968",
    "CVE-2020-10969",
    "CVE-2020-11111",
    "CVE-2020-11112",
    "CVE-2020-11113",
    "CVE-2020-11619",
    "CVE-2020-11620",
    "CVE-2020-14617"
  );
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Unifier Multiple Vulnerabilities (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera Unifier installation running on the remote web
server is 16.1.x or 16.2.x prior to 16.2.16.2, or 17.7.x through 17.12.x prior to 17.12.11.4, or 18.8.x prior to
18.8.17, or 19.12.x prior to 19.12.7. It is, therefore, affected by multiple vulnerabilities, including the following:

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (jackson-databind)). Supported versions that are affected are 16.1, 16.2, 17.7-17.12, 18.8 and 19.12.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Primavera Unifier. Successful attacks of this vulnerability can result in takeover of Primavera
    Unifier. (CVE-2020-9546)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Core
    (Apache Ant)). Supported versions that are affected are 16.1, 16.2, 17.7-17.12, 18.8 and 19.12. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Primavera Unifier accessible data as well as unauthorized
    access to critical data or complete access to all Primavera Unifier accessible data. (CVE-2020-1945)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Mobile
    App). The supported version that is affected is Prior to 20.6. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via HTTPS to compromise Primavera Unifier. Successful attacks
    require human interaction from a person other than the attacker. Successful attacks of this vulnerability
    can result in unauthorized access to critical data or complete access to all Primavera Unifier accessible
    data as well as unauthorized update, insert or delete access to some of Primavera Unifier accessible data.
    (CVE-2020-14618)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera Unifier', exit_if_zero:TRUE);

port = get_http_port(default:8002);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

app_info = vcf::get_app_info(app:'Oracle Primavera Unifier', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '16.1', 'fixed_version' : '16.2.16.2' },
  { 'min_version' : '17.7', 'fixed_version' : '17.12.11.4' },
  { 'min_version' : '18.8', 'fixed_version' : '18.8.17' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
