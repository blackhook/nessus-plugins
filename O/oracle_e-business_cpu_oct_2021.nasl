#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154291);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2021-2474",
    "CVE-2021-2477",
    "CVE-2021-2482",
    "CVE-2021-2483",
    "CVE-2021-2484",
    "CVE-2021-2485",
    "CVE-2021-35536",
    "CVE-2021-35554",
    "CVE-2021-35562",
    "CVE-2021-35563",
    "CVE-2021-35566",
    "CVE-2021-35569",
    "CVE-2021-35570",
    "CVE-2021-35580",
    "CVE-2021-35581",
    "CVE-2021-35582",
    "CVE-2021-35585",
    "CVE-2021-35611"
  );
  script_xref(name:"IAVA", value:"2021-A-0485-S");

  script_name(english:"Oracle E-Business Suite Multiple Vulnerabilities (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business Suite installed on the remote host is affected by multiple vulnerabilities as
referenced in the October 2021 CPU advisory, including the following:

  - An easily exploitable vulnerability in the Oracle Content Manager product's Content Item Manager component
    that allows a low privileged, remote attacker to compromise confidentiality and integrity. (CVE-2021-2483)

  - An easily exploitable vulnerability in the Oracle Applications Manager Diagnostics component that allows a
    low privileged, remote attacker to compromise confidentiality and integrity. (CVE-2021-35566)
  
  - An easily exploitable vulnerability in a Miscellaneous component of the Oracle Deal Management product
    that allows a low privileged, remote attacker to compromise confidentiality and integrity.
    (CVE-2021-35536)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixEBS");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35570");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.1.1', 'max_version' : '12.1.3',  'fix_patches' : '33154541' },
  { 'min_version' : '12.2.0', 'max_version' : '12.2.2',  'fix_patches' : '33154561', 'fixed_display' : '12.2.3' },
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.9999999', 'fix_patches' : '33154561' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.9999999', 'fix_patches' : '33154561, 33168623' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.9999999', 'fix_patches' : '33154561, 33168635' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.9999999', 'fix_patches' : '33154561, 33168644' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.9999999', 'fix_patches' : '33154561, 33245199, 33168651' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.9999999', 'fix_patches' : '33154561, 33245199, 33168655' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.9999999', 'fix_patches' : '33154561, 33245199, 33168655' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.9999999', 'fix_patches' : '33154561, 33286000, 33207251, 33168664' },
];

var fix_date = '202110';

vcf::oracle_ebusiness::check_version_and_report(
  app_info    : app_info,
  severity    : SECURITY_HOLE,
  constraints : constraints,
  fix_date    : fix_date
);
