#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148934);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-5064");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Application Testing Suite (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 13.3.0.1 versions of Application Testing Suite installed on the remote host are affected by a vulnerability as
referenced in the April 2021 CPU advisory.

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component:
    Load Testing for Web Apps (OpenCV)). The supported version that is affected is 13.3.0.1. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Application Testing Suite. Successful attacks require human interaction from a person other than
    the attacker. Successful attacks of this vulnerability can result in takeover of Oracle Application
    Testing Suite. CVSS 3.1 Base Score 8.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H). (CVE-2019-5064)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include('smb_func.inc');
include('install_func.inc');
include('oracle_rdbms_cpu_func.inc');
include('obj.inc');

var app_name = 'Oracle Application Testing Suite';

var install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
var ohome = install['Oracle Home'];
var subdir = install['path'];
var version = install['version'];

var fix = NULL;
var fix_ver = NULL;


if (version =~ "^13\.3\.0\.1")
{
  fix_ver = '13.3.0.1.402';
  fix = '32690142';
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);

var is_nix = TRUE;
if (get_kb_item('SMB/Registry/Enumerated'))
  is_nix = FALSE;

if (is_nix)
{
  var second_patch = FALSE;

  # Check for 2nd patch.
  var ohomes = make_list(ohome);
  var additional_patch = '32690139';
  var patches = find_patches_in_ohomes(ohomes:ohomes);
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
var VULN = FALSE;

# 2 Vulnerable scenario chks:
# 1 - Windows and missing 32690142 patch - simple ver_compare
if (!is_nix && (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1))
{
  VULN=TRUE;
}
# 2 - linux and [ missing 32690142 patch OR missing additional 32690139 patch ]
else if (is_nix && (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1 || !second_patch))
{
  VULN=TRUE;
}
else
{
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
}

# if we've reached this, we are vuln
var report =
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

security_report_v4(extra:report, port:0, severity:SECURITY_WARNING);