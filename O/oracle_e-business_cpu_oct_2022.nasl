#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166317);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id(
    "CVE-2019-10086",
    "CVE-2022-21587",
    "CVE-2022-21636",
    "CVE-2022-39428"
  );
  script_xref(name:"IAVA", value:"2022-A-0425");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/02/23");

  script_name(english:"Oracle E-Business Suite (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2022 CPU advisory.

  - Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite
    (component: Upload). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Web
    Applications Desktop Integrator. Successful attacks of this vulnerability can result in takeover of Oracle
    Web Applications Desktop Integrator. (CVE-2022-21587, CVE-2022-39428)

  - Vulnerability in the Oracle Human Resources product of Oracle E-Business Suite (component: Common Modules
    (Apache Commons BeanUtils)). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Human
    Resources. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of Oracle Human Resources accessible data as well as unauthorized read access to a subset
    of Oracle Human Resources accessible data and unauthorized ability to cause a partial denial of service
    (partial DOS) of Oracle Human Resources. (CVE-2019-10086)

  - Vulnerability in the Oracle Applications Framework product of Oracle E-Business Suite (component: Session
    Management). Supported versions that are affected are 12.2.6-12.2.11. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Oracle Applications Framework.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Oracle Applications Framework accessible data. (CVE-2022-21636)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10086");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39428");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle E-Business Suite (EBS) Unauthenticated Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.99999999', 'fix_patches' : '34450992, 34700264' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches' : '34450992, 34700264, 34291981' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches' : '34450992, 34700264, 34291981' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches' : '34450992, 34461755, 34534507, 34291981' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches' : '34450992, 34285063, 34556525, 34291981' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches' : '34450992, 34285063, 34556525, 34291981' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches' : '34450992, 34461761, 34556525, 34291981' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches' : '34450992, 34461765, 34556525, 34291981' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '34450992, 34461768, 34556525, 34291981' }
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  fix_date:'202210'
);
