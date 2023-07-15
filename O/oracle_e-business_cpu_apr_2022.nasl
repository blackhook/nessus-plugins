#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160080);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-21468", "CVE-2022-21477");
  script_xref(name:"IAVA", value:"2022-A-0167");

  script_name(english:"Oracle E-Business Suite (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2022 CPU advisory.

  - Vulnerability in the Oracle Applications Framework product of Oracle E-Business Suite (component: Popups).
    Supported versions that are affected are 12.2.4-12.2.11. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Applications Framework.
    Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in Oracle Applications Framework, attacks may significantly impact additional products
    (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle Applications Framework accessible data as well as unauthorized read access
    to a subset of Oracle Applications Framework accessible data. (CVE-2022-21468)

  - Vulnerability in the Oracle Applications Framework product of Oracle E-Business Suite (component:
    Attachments, File Upload). Supported versions that are affected are 12.2.6-12.2.11. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
    Applications Framework. Successful attacks require human interaction from a person other than the attacker
    and while the vulnerability is in Oracle Applications Framework, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Applications Framework accessible data as well as
    unauthorized read access to a subset of Oracle Applications Framework accessible data. 
    (CVE-2022-21477)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

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
  { 'min_version' : '12.2.3', 'max_version' : '12.2.5.9999999', 'fix_patches' : '33782739' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.9999999', 'fix_patches' : '33782739, 33908186' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.9999999', 'fix_patches' : '33782739, 33908189' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.9999999', 'fix_patches' : '33782739, 33908199' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.9999999', 'fix_patches' : '33782739, 33908199' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.9999999', 'fix_patches' : '33782739, 33908208' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.9999999', 'fix_patches' : '33782739, 33862025, 33908216' },
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info    : app_info,
  severity    : SECURITY_WARNING,
  constraints : constraints,
  fix_date    : '202204'
);
