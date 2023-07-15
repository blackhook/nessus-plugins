#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174471);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2021-23413", "CVE-2022-27404", "CVE-2022-36033");
  script_xref(name:"IAVA", value:"2023-A-0207");

  script_name(english:"Oracle Primavera Unifier (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Unifier installed on the remote host are affected by multiple vulnerabilities as referenced in
the April 2023 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Management (FreeType)). Supported versions that are affected are 18.8.0-18.8.18, 19.12.0-19.12.16,
    20.12.0-20.12.16, 21.12.0-21.12.14 and 22.12.0-22.12.3. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Primavera Unifier. Successful attacks
    of this vulnerability can result in takeover of Primavera Unifier. (CVE-2022-27404)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering
    (component: User Interface (jsoup)). Supported versions that are affected are 18.8.0-18.8.18, 19.12.0-19.12.16,
    20.12.0-20.12.16, 21.12.0-21.12.14 and 22.12.0-22.12.3. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Primavera Unifier. Successful attacks require human
    interaction from a person other than the attacker and while the vulnerability is in Primavera Unifier,
    attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete access to some of Primavera Unifier accessible data as
    well as unauthorized read access to a subset of Primavera Unifier accessible data. (CVE-2022-36033)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: User
    Interface (JSZip)). Supported versions that are affected are 18.8.0-18.8.18, 19.12.0-19.12.16,
    20.12.0-20.12.16, 21.12.0-21.12.14 and 22.12.0-22.12.3. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Primavera Unifier. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS)
    of Primavera Unifier. (CVE-2021-23413)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27404");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

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
  { 'min_version' : '18.8.0', 'fixed_version' : '18.8.18.15' },
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.16.7' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.16.5' },
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.15' },
  { 'min_version' : '22.12.0', 'fixed_version' : '22.12.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
