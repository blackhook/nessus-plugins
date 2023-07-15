#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148918);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2020-13956",
    "CVE-2020-17521"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Primavera Unifier (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera Unifier installation running on the remote host is
16.x prior to 16.2.16.5 or 17.x prior to 17.12.11.7 or 18.8.x prior to 18.8.18.4 or 19.12.x prior to 19.12.14 or 20.12.x
prior to 20.12.4. It is, therefore, affected by multiple vulnerabilities as referenced in the April 2021 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Core UI
    (jQuery)). Supported versions that are affected are 16.1, 16.2, 17.7-17.12, 18.8, 19.12 and 20.12. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks require human interaction from a person other than the attacker
    and while the vulnerability is in Primavera Unifier, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some
    of Primavera Unifier accessible data as well as unauthorized read access to a subset of Primavera Unifier
    accessible data. (CVE-2020-11022)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Core (HTTP
    Client)). Supported versions that are affected are 16.1, 16.2, 17.7-17.12, 18.8, 19.12 and 20.12. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Primavera Unifier accessible data. (CVE-2020-13956)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (Apache Groovy)). Supported versions that are affected are 16.1, 16.2, 17.7-17.12, 18.8, 19.12 and 20.12.
    Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where
    Primavera Unifier executes to compromise Primavera Unifier. Successful attacks of this vulnerability can
    result in unauthorized access to critical data or complete access to all Primavera Unifier accessible data.
    (CVE-2020-17521)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13956");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '16.1', 'fixed_version' : '16.2.16.5' },
  { 'min_version' : '17.7', 'fixed_version' : '17.12.11.7' },
  { 'min_version' : '18.8', 'fixed_version' : '18.8.18.4' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.14' },
  { 'min_version' : '20.12', 'fixed_version' : '20.12.4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
