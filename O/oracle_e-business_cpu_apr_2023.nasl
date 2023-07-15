#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174519);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2023-21959",
    "CVE-2023-21973",
    "CVE-2023-21978",
    "CVE-2023-21997"
  );
  script_xref(name:"IAVA", value:"2023-A-0208");

  script_name(english:"Oracle E-Business Suite (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2023 CPU advisory.

  - Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component:
    GUI). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows
    low privileged attacker with network access via HTTP to compromise Oracle Application Object Library.
    Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in Oracle Application Object Library, attacks may significantly impact additional
    products (scope change). Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Application Object Library accessible data as well as
    unauthorized read access to a subset of Oracle Application Object Library accessible data and
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Application Object
    Library. (CVE-2023-21978)

  - Vulnerability in the Oracle iProcurement product of Oracle E-Business Suite (component: E-Content
    Manager Catalog). Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
    iProcurement. Successful attacks require human interaction from a person other than the attacker and
    while the vulnerability is in Oracle iProcurement, attacks may significantly impact additional products
    (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle iProcurement accessible data as well as unauthorized read access to a
    subset of Oracle iProcurement accessible data. (CVE-2023-21973)

  - Vulnerability in the Oracle iReceivables product of Oracle E-Business Suite (component: Attachments).
    Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle iReceivables. Successful attacks
    of this vulnerability can result in unauthorized read access to a subset of Oracle iReceivables
    accessible data. (CVE-2023-21959)

  - Vulnerability in the Oracle User Management product of Oracle E-Business Suite (component: Proxy User
    Delegation). Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Oracle User Management.
    Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle
    User Management accessible data. (CVE-2023-21997)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21978");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.99999999', 'fix_patches' : '35020334' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches' : '35020334, 35051969' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches' : '35020334, 35052044' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches' : '35020334, 35052634' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches' : '35020334, 35052794' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches' : '35020334, 35055584' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches' : '35020334, 35055624' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches' : '35020334, 34882047' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '35020334, 35055676' },
  { 'min_version' : '12.2.12', 'max_version' : '12.2.12.99999999', 'fix_patches' : '35020334' }
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  fix_date:'202304'
);
