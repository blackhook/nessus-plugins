#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138610);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-5645", "CVE-2019-17091");
  script_bugtraq_id(97702);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Application Testing Suite (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Application Testing Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2020 CPU advisory.

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component: Load
    Testing for Web Apps (Log4j)). The supported version that is affected is 13.3.0.1. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Application Testing Suite. Successful attacks of this vulnerability can result in takeover of Oracle
    Application Testing Suite. (CVE-2017-5645)

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component: Load
    Testing for Web Apps (Eclipse Mojarra). Supported versions that are affected are 13.2.0.1 and 13.3.0.1.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Application Testing Suite. Successful attacks require human interaction from a person other than the
    attacker and while the vulnerability is in Oracle Application Testing Suite, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Application Testing Suite accessible data as well as unauthorized
    read access to a subset of Oracle Application Testing Suite accessible data. (CVE-2019-17091)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include('smb_func.inc');
include('install_func.inc');
include('oracle_rdbms_cpu_func.inc');
include('obj.inc');

app_name = 'Oracle Application Testing Suite';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install['Oracle Home'];
subdir = install['path'];
version = install['version'];

fix = NULL;
fix_ver = NULL;


# 13.2.0.1 and 13.3.0.1 get checked against the same fix
if ((version =~ "^13\.[23]\."))
{
  fix_ver = '13.3.0.1.374';
  fix = '31517976';
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);

is_nix = TRUE;
if (get_kb_item('SMB/Registry/Enumerated'))
  is_nix = FALSE;
if (is_nix)
{
  second_patch = FALSE;

  # Check for 2nd patch.
  ohomes = make_list(ohome);
  additional_patch = '31517994';
  patches = find_patches_in_ohomes(ohomes:ohomes);
  if (!empty_or_null(patches))
  {

    foreach patch (keys(patches[ohome]))
    {
      if (patch == additional_patch)
      {
        second_patch = TRUE;
        break;
     }
    }
  }
}

# stay vuln until we prove we are patched...
VULN = FALSE;

# 2 Vulnerable scenario chks:
# 1 - Windows and missing 31517976 patch - simple ver_compare
if (!is_nix && (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1))
{
  VULN=TRUE;
}
# 2 - linux and [ missing 31517976 patch OR missing additional 31517994 patch ]
else if (is_nix && (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1 || !second_patch))
{
  VULN=TRUE;
}
else
{
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
}

# if we've reached this, we are vuln
report =
  '\n  Oracle home        : ' + ohome +
  '\n  Install path       : ' + subdir +
  '\n  Version            : ' + version +
  '\n  Required patch(es) : ' ;

if (VULN)
    report += fix + ' \n';

if (is_nix){
  if (!second_patch)
    report += '                     : ' + additional_patch + '\n';
}

security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
