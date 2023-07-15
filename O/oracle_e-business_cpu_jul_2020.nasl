#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138507);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2020-14534",
    "CVE-2020-14554",
    "CVE-2020-14555",
    "CVE-2020-14582",
    "CVE-2020-14590",
    "CVE-2020-14596",
    "CVE-2020-14598",
    "CVE-2020-14599",
    "CVE-2020-14610",
    "CVE-2020-14635",
    "CVE-2020-14657",
    "CVE-2020-14658",
    "CVE-2020-14659",
    "CVE-2020-14660",
    "CVE-2020-14661",
    "CVE-2020-14665",
    "CVE-2020-14666",
    "CVE-2020-14667",
    "CVE-2020-14668",
    "CVE-2020-14670",
    "CVE-2020-14671",
    "CVE-2020-14679",
    "CVE-2020-14681",
    "CVE-2020-14682",
    "CVE-2020-14686",
    "CVE-2020-14688",
    "CVE-2020-14716",
    "CVE-2020-14717",
    "CVE-2020-14719",
    "CVE-2020-14720"
  );
  script_xref(name:"IAVA", value:"2020-A-0329-S");

  script_name(english:"Oracle Oracle E-Business Suite (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2020 CPU advisory, including the following:

  - Vulnerability in the Oracle Trade Management product of Oracle E-Business Suite (component: Invoice).
    Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.9. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Trade Management.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Oracle Trade Management accessible data as well as unauthorized access to
    critical data or complete access to all Oracle Trade Management accessible data. (CVE-2020-14665)

  - Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing
    Administration). Supported versions that are affected are 12.1.1-12.1.3 and 12.2.3-12.2.9. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Marketing. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Marketing accessible data as well as unauthorized
    access to critical data or complete access to all Oracle Marketing accessible data. (CVE-2020-14658)

  - Vulnerability in the Oracle CRM Gateway for Mobile Devices product of Oracle E-Business Suite (component:
    Setup of Mobile Applications). Supported versions that are affected are 12.1.1-12.1.3. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle CRM
    Gateway for Mobile Devices. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Oracle CRM Gateway for Mobile Devices accessible
    data as well as unauthorized access to critical data or complete access to all Oracle CRM Gateway for
    Mobile Devices accessible data. (CVE-2020-14599)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/15");

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
fix_date = '202007';

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
  fix_patches = '31198341';

# 12.2.0 - 12.2.3
else if (version =~ "^12\.2.[0-3]($|[^0-9])") 
{
  fix_version = '12.2.3';
  fix_patches = '31198342';
}
# 12.2.4 
else if (version =~ "^12\.2\.4($|[^0-9])")
  fix_patches = make_list('31198342', '31444255');
# 12.2.5
else if (version =~ "^12\.2\.5($|[^0-9])")
  fix_patches = make_list('31198342', '31444257', '31206584');
# 12.2.6
else if (version =~ "^12\.2\.6($|[^0-9])")
  fix_patches = make_list('31198342', '31444264', '31206584');
# 12.2.7-8
else if (version =~ "^12\.2\.[78]($|[^0-9])")
  fix_patches = make_list('31198342', '31444270', '31206584');
# 12.2.9
else if (version =~ "^12\.2\.9($|[^0-9])")
  fix_patches = make_list('31198342', '31354997', '31206584');
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version);

report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_version +
    '\n  Required Patches  : ' + join(sep:', ', fix_patches);

security_report_v4(port:0,extra:report,severity:SECURITY_WARNING);
