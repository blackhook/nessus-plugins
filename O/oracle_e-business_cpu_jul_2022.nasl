##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163411);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2022-21500",
    "CVE-2022-21545",
    "CVE-2022-21566",
    "CVE-2022-21567",
    "CVE-2022-21568",
    "CVE-2022-23305"
  );
  script_xref(name:"IAVA", value:"2022-A-0284");

  script_name(english:"Oracle E-Business Suite (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2022 CPU advisory.

  - Vulnerability in the Oracle E-Business Suite Information Discovery product of Oracle E-Business Suite
    (component: Packaging issues (Apache Log4j)). Supported versions that are affected are 12.2.3-12.2.11. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
    E-Business Suite Information Discovery. Successful attacks of this vulnerability can result in takeover of Oracle
    E-Business Suite Information Discovery. (CVE-2022-23305)

  - Vulnerability in the Oracle Applications Framework product of Oracle E-Business Suite (component:
    Diagnostics). Supported versions that are affected are 12.2.9-12.2.11. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Applications Framework. Successful attacks
    of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle
    Applications Framework accessible data. (CVE-2022-21566)

  - Vulnerability in the Oracle Workflow product of Oracle E-Business Suite (component: Worklist). Supported
    versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Oracle Workflow. Successful attacks of this vulnerability can result
    in unauthorized access to critical data or complete access to all Oracle Workflow accessible data. (CVE-2022-21567)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.99999999', 'fix_patches' : '34127951' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches' : '34127951, 34164667' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches' : '34127951, 34164667' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches' : '34127951, 34164667' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches' : '34127951, 34196316, 34212478, 34164667' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches' : '34127951, 34196316, 34212478, 34164667' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches' : '34127951, 34197714, 34196316, 34212478, 34164667' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches' : '34127951, 34197573, 34196316, 34212478, 34164667' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '34127951, 34197137, 34196316, 34212478, 34164667' }
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info    : app_info,
  severity    : SECURITY_WARNING,
  constraints : constraints,
  fix_date    : '202207'
);