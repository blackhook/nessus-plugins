#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152040);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-2343",
    "CVE-2021-2355",
    "CVE-2021-2359",
    "CVE-2021-2360",
    "CVE-2021-2361",
    "CVE-2021-2362",
    "CVE-2021-2363",
    "CVE-2021-2364",
    "CVE-2021-2365",
    "CVE-2021-2380",
    "CVE-2021-2393",
    "CVE-2021-2398",
    "CVE-2021-2405",
    "CVE-2021-2406",
    "CVE-2021-2415",
    "CVE-2021-2434",
    "CVE-2021-2436"
  );
  script_xref(name:"IAVA", value:"2021-A-0332-S");

  script_name(english:"Oracle E-Business Suite Multiple Vulnerabilities (July 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business Suite installed on the remote host is affected by multiple vulnerabilities as
referenced in the July 2021 CPU advisory.

  - Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing
    Administration). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Marketing. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Marketing accessible data as well as unauthorized
    access to critical data or complete access to all Oracle Marketing accessible data. (CVE-2021-2355)

  - Vulnerability in the Oracle Common Applications product of Oracle E-Business Suite (component: CRM User
    Management Framework). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Common Applications. Successful attacks require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle Common Applications, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle Common Applications accessible data as well as unauthorized
    update, insert or delete access to some of Oracle Common Applications accessible data. (CVE-2021-2436)

  - Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing
    Administration). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Marketing. Successful attacks require human interaction from a person other than the attacker and
    while the vulnerability is in Oracle Marketing, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Oracle Marketing accessible data as well as unauthorized update, insert or delete access to
    some of Oracle Marketing accessible data. (CVE-2021-2359)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2415");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2355");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

var fix_date = '202107';

var app_name = 'Oracle E-Business';
var version = get_kb_item_or_exit('Oracle/E-Business/Version');
var patched_versions = get_kb_item('Oracle/E-Business/patched_versions');

# check if patched
var version_regex = "(^|[^0-9])" + version + "\." + fix_date + "([^0-9]|$)";
if (!empty_or_null(patched_versions) && patched_versions =~ version_regex)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# set report fixed version and patches
var fix_patches;
var fix_version = version;
if (version =~ "^12\.1\.[123]($|\.)") fix_patches = '32841266';
else if (version =~ "^12\.2.([0-3])($|\.)")
{
  fix_version = '12.2.3';
  fix_patches = '32841270';
}
else if (version =~ "^12\.2.4($|\.)") fix_patches = ['32841270', '32979944'];
else if (version =~ "^12\.2.5($|\.)") fix_patches = ['32841270', '32979959'];
else if (version =~ "^12\.2.6($|\.)") fix_patches = ['32841270', '32979890'];
else if (version =~ "^12\.2.7($|\.)") fix_patches = ['32841270', '32980025'];
else if (version =~ "^12\.2.[89]($|\.)") fix_patches = ['32841270', '32946859', '32980025'];
else if (version =~ "^12\.2.10($|\.)") fix_patches = ['32841270', '32946878', '32980025'];
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version);

var report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_version +
    '\n  Required Patches  : ' + join(sep:', ', fix_patches);

security_report_v4(port:0,extra:report,severity:SECURITY_HOLE);
