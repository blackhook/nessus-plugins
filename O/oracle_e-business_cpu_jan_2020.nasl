#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133213);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2020-2566",
    "CVE-2020-2582",
    "CVE-2020-2586",
    "CVE-2020-2587",
    "CVE-2020-2591",
    "CVE-2020-2596",
    "CVE-2020-2597",
    "CVE-2020-2603",
    "CVE-2020-2651",
    "CVE-2020-2652",
    "CVE-2020-2653",
    "CVE-2020-2657",
    "CVE-2020-2658",
    "CVE-2020-2661",
    "CVE-2020-2662",
    "CVE-2020-2665",
    "CVE-2020-2666",
    "CVE-2020-2667",
    "CVE-2020-2668",
    "CVE-2020-2669",
    "CVE-2020-2670",
    "CVE-2020-2671",
    "CVE-2020-2672"
  );

  script_name(english:"Oracle E-Business Suite Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the January 2020 Oracle Critical Patch Update (CPU). It is,
as noted in the January 2020 Critical Patch Update advisory, affected
by flaws in the following components :

  - Oracle Human Resources
  - Oracle CRM Technical Foundation
  - Oracle Email Center
  - Oracle Field Service
  - Oracle iStore
  - Oracle Web Applications Desktop Integrator
  - Oracle iSupport
  - Oracle Applications Framework
  - Oracle One-to-One Fulfillment

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

fix_date = '202001';

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
  fix_patches = '30445462';

# 12.2.0 - 12.2.3
else if (version =~ "^12\.2.[0-3]($|[^0-9])") 
{
  fix_version = '12.2.3';
  fix_patches = '30445472';
}
# 12.2.4 
else if (version =~ "^12\.2\.4($|[^0-9])")
  fix_patches = make_list('30445472', '30119058');
# 12.2.5
else if (version =~ "^12\.2\.5($|[^0-9])")
  fix_patches = make_list('30445472', '30611153', '30515569');
# 12.2.6
else if (version =~ "^12\.2\.6($|[^0-9])")
  fix_patches = make_list('30445472', '30406645');
# 12.2.7-8
else if (version =~ "^12\.2\.[78]($|[^0-9])")
  fix_patches = make_list('30445472', '30515670');
# 12.2.9
else if (version =~ "^12\.2\.9($|[^0-9])")
  fix_patches = make_list('30445472', '30751854', '30367367');
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version);

report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_version +
    '\n  Required Patches  : ' + join(sep:', ', fix_patches);

security_report_v4(port:0,extra:report,severity:SECURITY_WARNING);
