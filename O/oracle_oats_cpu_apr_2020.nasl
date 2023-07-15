#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135681);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-0227");
  script_bugtraq_id(107867);
  script_xref(name:"IAVA", value:"2020-A-0150");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Application Testing Suite (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Testing Suite installed on the remote host is affected by a Server Side Request
Forgery (SSRF) vulnerability in the Oracle FLEXCUBE Private Banking product of Oracle Financial Services Applications
(component: Core (Apache Axis)). The supported versions which are affected are 12.0 and 12.1. This is a difficult to
exploit vulnerability which allows an unauthenticated, adjacent attacker with access to the physical segment attached
to the hardware where Oracle FLEXCUBE Private Banking executes to compromise Oracle FLEXCUBE Private Banking in order to
take it over.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  fix_ver = '13.3.0.1.365';
  fix = '30733044';
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
  additional_patch = '30733056';
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
# 1 - Windows and missing 30733044 patch - simple ver_compare
if (!is_nix && (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1))
{
  VULN=TRUE;
}
# 2 - linux and [ missing 3044 patch OR missing additional 3056 patch ]
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

security_report_v4(extra:report, port:0, severity:SECURITY_WARNING);
