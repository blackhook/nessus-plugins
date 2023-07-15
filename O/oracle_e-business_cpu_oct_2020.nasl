#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141808);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/12");

  script_cve_id(
    "CVE-2020-14746",
    "CVE-2020-14761",
    "CVE-2020-14774",
    "CVE-2020-14805",
    "CVE-2020-14808",
    "CVE-2020-14811",
    "CVE-2020-14816",
    "CVE-2020-14817",
    "CVE-2020-14819",
    "CVE-2020-14822",
    "CVE-2020-14823",
    "CVE-2020-14826",
    "CVE-2020-14831",
    "CVE-2020-14833",
    "CVE-2020-14834",
    "CVE-2020-14835",
    "CVE-2020-14840",
    "CVE-2020-14849",
    "CVE-2020-14850",
    "CVE-2020-14851",
    "CVE-2020-14855",
    "CVE-2020-14856",
    "CVE-2020-14857",
    "CVE-2020-14862",
    "CVE-2020-14863",
    "CVE-2020-14875",
    "CVE-2020-14876"
  );
  script_xref(name:"IAVA", value:"2020-A-0476-S");

  script_name(english:"Oracle Oracle E-Business Suite (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2020 CPU advisory, including the following:

  - Vulnerability in the Oracle Universal Work Queue product of Oracle E-Business Suite (component: Work
    Provider Administration). The supported version that is affected is 12.1.3. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Universal
    Work Queue. Successful attacks of this vulnerability can result in takeover of Oracle Universal Work
    Queue. (CVE-2020-14855)

  - Vulnerability in the Oracle E-Business Suite Secure Enterprise Search product of Oracle E-Business Suite
    (component: Search Integration Engine). Supported versions that are affected are 12.1.3 and 12.2.3 -
    12.2.10. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle E-Business Suite Secure Enterprise Search. Successful attacks of this vulnerability can
    result in unauthorized creation, deletion or modification access to critical data or all Oracle E-Business
    Suite Secure Enterprise Search accessible data as well as unauthorized access to critical data or complete
    access to all Oracle E-Business Suite Secure Enterprise Search accessible data. (CVE-2020-14805)

  - Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing
    Administration). Supported versions that are affected are 12.1.1 - 12.1.3 and 12.2.3 - 12.2.10. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Marketing. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Marketing accessible data as well as unauthorized
    access to critical data or complete access to all Oracle Marketing accessible data.  (CVE-2020-14875)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14855");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

fix_date = '202010';

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
  fix_patches = '31643022';

# 12.2.0 - 12.2.3
else if (version =~ "^12\.2.[0-3]($|[^0-9])")
{
  fix_version = '12.2.3';
  fix_patches = '31643029';
}
# 12.2.4 
else if (version =~ "^12\.2\.4($|[^0-9])")
  fix_patches = make_list('31643029', '31745897');
# 12.2.5
else if (version =~ "^12\.2\.5($|[^0-9])")
  fix_patches = make_list('31643029', '31745911');
# 12.2.6
else if (version =~ "^12\.2\.6($|[^0-9])")
  fix_patches = make_list('31643029', '31745931');
# 12.2.7-8
else if (version =~ "^12\.2\.[78]($|[^0-9])")
  fix_patches = make_list('31643029', '31745963');
# 12.2.9
else if (version =~ "^12\.2\.9($|[^0-9])")
  fix_patches = make_list('31643029', '31745969');
# 12.2.10
else if (version =~ "^12\.2\.10($|[^0-9])")
  fix_patches = make_list('31643029', '31745982');
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version);

report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_version +
    '\n  Required Patches  : ' + join(sep:', ', fix_patches);

security_report_v4(port:0,extra:report,severity:SECURITY_HOLE);
