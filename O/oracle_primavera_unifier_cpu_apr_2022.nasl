#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159919);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/20");

  script_cve_id("CVE-2021-23450", "CVE-2021-41184");

  script_name(english:"Oracle Primavera Unifier (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Primavera Unifier installed on the remote host is affected by multiple vulnerabilities as referenced in
the April 2022 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Platform
    (dojo)). Supported versions that are affected are 17.7-17.12, 18.8, 19.12, 20.12 and 21.12. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    hang or frequently repeatable crash (complete DOS) of Primavera Unifier as well as unauthorized update,
    insert or delete access to some of Primavera Unifier accessible data and unauthorized read access to a
    subset of Primavera Unifier accessible data. (CVE-2021-23450)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console,
    Samples (jQueryUI)). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle WebLogic Server. Successful attacks require human interaction from a person other than
    the attacker and while the vulnerability is in Oracle WebLogic Server, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle WebLogic Server accessible data as well as unauthorized
    read access to a subset of Oracle WebLogic Server accessible data. (CVE-2021-41184)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '17.7', 'fixed_version' : '17.12.11.11' },
  { 'min_version' : '18.8', 'fixed_version' : '18.8.18.10' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.16.3' },
  { 'min_version' : '20.12', 'fixed_version' : '20.12.14' },
  { 'min_version' : '21.12', 'fixed_version' : '21.12.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
