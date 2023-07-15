#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145220);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2021-2015",
    "CVE-2021-2017",
    "CVE-2021-2023",
    "CVE-2021-2026",
    "CVE-2021-2027",
    "CVE-2021-2029",
    "CVE-2021-2034",
    "CVE-2021-2059",
    "CVE-2021-2077",
    "CVE-2021-2082",
    "CVE-2021-2083",
    "CVE-2021-2084",
    "CVE-2021-2085",
    "CVE-2021-2089",
    "CVE-2021-2090",
    "CVE-2021-2091",
    "CVE-2021-2092",
    "CVE-2021-2093",
    "CVE-2021-2094",
    "CVE-2021-2096",
    "CVE-2021-2097",
    "CVE-2021-2098",
    "CVE-2021-2099",
    "CVE-2021-2100",
    "CVE-2021-2101",
    "CVE-2021-2105",
    "CVE-2021-2106",
    "CVE-2021-2107",
    "CVE-2021-2114",
    "CVE-2021-2115",
    "CVE-2021-2118"
  );
  script_xref(name:"IAVA", value:"2021-A-0031-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle E-Business Suite Multiple Vulnerabilities (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2021 CPU advisory.

  - Vulnerability in the Oracle Scripting product of Oracle E-Business Suite (component: Miscellaneous).
    Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.8. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Scripting. Successful
    attacks of this vulnerability can result in takeover of Oracle Scripting. (CVE-2021-2029)

  - Vulnerability in the Oracle One-to-One Fulfillment product of Oracle E-Business Suite (component: Print
    Server). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.10. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle One-to-One
    Fulfillment. Successful attacks of this vulnerability can result in unauthorized creation, deletion or
    modification access to critical data or all Oracle One-to-One Fulfillment accessible data as well as
    unauthorized access to critical data or complete access to all Oracle One-to-One Fulfillment accessible
    data. (CVE-2021-2100, CVE-2021-2101)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2029");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

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

fix_date = '202101';

app_name = 'Oracle E-Business';
version = get_kb_item_or_exit('Oracle/E-Business/Version');
patched_versions = get_kb_item('Oracle/E-Business/patched_versions');

# check if patched
version_regex = "(^|[^0-9])" + version + "\." + fix_date + "([^0-9]|$)";
if (!empty_or_null(patched_versions) && patched_versions =~ version_regex)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# Report fixed version and required patches
fix_version = version;

# 12.1.1 - 12.1.3
if (version =~ "^12\.1\.[1-3]($|[^0-9])")
  fix_patches = '32071645';

# 12.2.0 - 12.2.3
else if (version =~ "^12\.2.[0-3]($|[^0-9])")
{
  fix_version = '12.2.3';
  fix_patches = '32071646';
}

# 12.2.4 - 12.2.6
else if (version =~ "^12\.2\.[4-6]($|[^0-9])")
  fix_patches = make_list('32071646');

# 12.2.7 - 12.2.9
else if (version =~ "^12\.2\.[7-9]($|[^[0-9])")
  fix_patches = make_list('32071646', '32117360');

# 12.2.10
else if (version =~ "^12\.2\.10($|[^0-9])")
  fix_patches = make_list('32071646', '32117360', '32163187');

else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version);

report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_version +
    '\n  Required Patches  : ' + join(sep:', ', fix_patches);

security_report_v4(port:0,extra:report,severity:SECURITY_HOLE);


