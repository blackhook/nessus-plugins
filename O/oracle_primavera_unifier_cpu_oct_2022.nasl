#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166305);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id(
    "CVE-2020-7712",
    "CVE-2020-9492",
    "CVE-2020-13936",
    "CVE-2022-23457",
    "CVE-2022-31129",
    "CVE-2022-33879"
  );
  script_xref(name:"IAVA", value:"2022-A-0434-S");

  script_name(english:"Oracle Primavera Unifier (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera Unifier installed on the remote host are affected by multiple vulnerabilities as referenced in
the October 2022 CPU advisory.

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Management (Apache Solr)). Supported versions that are affected are 18.8, 19.12, 20.12 and 21.12. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks of this vulnerability can result in takeover of Primavera Unifier.
    (CVE-2020-9492)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: User
    Interface (Enterprise Security API)). Supported versions that are affected are 18.8, 19.12, 20.12 and
    21.12. Difficult to exploit vulnerability allows low privileged attacker with network access via HTTP to
    compromise Primavera Unifier. Successful attacks of this vulnerability can result in takeover of Primavera
    Unifier. (CVE-2022-23457)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: User
    Interface (Moment.js)). Supported versions that are affected are 19.12, 20.12 and 21.12. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Primavera Unifier. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Primavera Unifier. (CVE-2022-31129)

  - Vulnerability in the Primavera Unifier product of Oracle Construction and Engineering (component: Document
    Management (Apache Tika)). Supported versions that are affected are 18.8, 19.12, 20.12 and 21.12. Easily
    exploitable vulnerability allows unauthenticated attacker with logon to the infrastructure where Primavera
    Unifier executes to compromise Primavera Unifier. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Primavera Unifier.  (CVE-2022-33879)

  - Security-in-Depth issue in the Primavera Unifier product of Oracle Construction and Engineering
    (component: Platform, User Interface (Apache Velocity Engine)). This vulnerability cannot be exploited
    in the context of this product. (CVE-2020-13936)

  - Security-in-Depth issue in the Primavera Unifier product of Oracle Construction and Engineering
    (component: Document Management (Apache ZooKeeper)). This vulnerability cannot be exploited in the context
    of this product. (CVE-2020-7712)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13936");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '18.8', 'fixed_version' : '18.8.18.12' },
  { 'min_version' : '19.12', 'fixed_version' : '19.12.16.5' },
  { 'min_version' : '20.12', 'fixed_version' : '20.12.16' },
  { 'min_version' : '21.12', 'fixed_version' : '21.12.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
