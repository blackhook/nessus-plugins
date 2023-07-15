#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170140);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2023-21834",
    "CVE-2023-21847",
    "CVE-2023-21849",
    "CVE-2023-21851",
    "CVE-2023-21852",
    "CVE-2023-21853",
    "CVE-2023-21854",
    "CVE-2023-21855",
    "CVE-2023-21856",
    "CVE-2023-21857",
    "CVE-2023-21858"
  );
  script_xref(name:"IAVA", value:"2023-A-0037-S");

  script_name(english:"Oracle E-Business Suite (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2023 CPU advisory.

  - Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite
    (component: Download). Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Web
    Applications Desktop Integrator. Successful attacks require human interaction from a person other than
    the attacker and while the vulnerability is in Oracle Web Applications Desktop Integrator, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to some of Oracle Web Applications Desktop
    Integrator accessible data as well as unauthorized read access to a subset of Oracle Web Applications
    Desktop Integrator accessible data. (CVE-2023-21847)

  - Vulnerability in the Oracle Applications DBA product of Oracle E-Business Suite (component: Java utils).
    Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Applications DBA. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Oracle Applications DBA accessible data. (CVE-2023-21849)

  - Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing
    Administration). Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Oracle Marketing accessible data. (CVE-2023-21851)

  - Vulnerability in the Oracle Sales Offline product of Oracle E-Business Suite (component: Core Components).
    Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Sales Offline. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Oracle Sales Offline accessible data. (CVE-2023-21854)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/18");

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
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.99999999', 'fix_patches' : '34726978' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches' : '34726978, 34821292' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches' : '34726978, 34821560' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches' : '34726978, 34744189' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches' : '34726978, 34744189' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches' : '34726978, 34744189' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches' : '34726978, 34744189' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches' : '34726978, 34744189' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '34726978, 34744189' },
  { 'min_version' : '12.2.12', 'max_version' : '12.2.12.99999999', 'fix_patches' : '34726978, 34744189' }
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  fix_date:'202301'
);
