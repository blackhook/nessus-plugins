#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133260);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2016-4000",
    "CVE-2017-12626",
    "CVE-2017-14735",
    "CVE-2019-2904",
    "CVE-2019-11358",
    "CVE-2019-12415",
    "CVE-2020-2673"
  );
  script_bugtraq_id(
    102879,
    105647,
    105656,
    108023
  );
  script_xref(name:"IAVA", value:"2020-A-0150");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Application Testing Suite Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Testing Suite installed on the
remote host is affected by multiple vulnerabilities : 

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component: Oracle Flow Builder (Jython)). 
  Supported versions that are affected are 12.5.0.3, 13.1.0.1, 13.2.0.1 and 13.3.0.1. 
  Easily exploitable vulnerability allows unauthenticated attacker with network 
  access via HTTP to compromise Oracle Application Testing Suite. Successful attacks
   of this vulnerability can result in takeover of Oracle Application Testing Suite. 
  (CVE-2016-4000)	

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Oracle Flow Builder (Jython).  An unauthenticated, remote attacker with network 
    access via HTTP to compromise Oracle Application Testing Suite. (CVE-2016-4000)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Load Testing for Web Apps (Apache POI).  An unauthenticated, remote attacker with network 
    access via HTTP to compromise Oracle Application Testing Suite and cause the process to hang 
    or frequently repeatable crash (complete DOS). (CVE-2017-12626)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Oracle Flow Builder (Apache POI).  An unauthenticated, remote attacker with network 
    access via HTTP to compromise Oracle Application Testing Suite and cause the process to hang 
    or frequently repeatable crash (complete DOS). (CVE-2017-12626)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Load Testing for Web Apps (AntiSamy).  An unauthenticated, remote attacker with network 
    access via HTTP who is able to obtain human interaction can impact additional products and result in
    an unauthorized update, insert, or delete access to some accessible data as well as unauthorized
    read access to a subset of accessible data. (CVE-2017-14735)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Oracle Flow Builder (Antisamy).  An unauthenticated, remote attacker with network 
    access via HTTP who is able to obtain human interaction can impact additional products and result in
    an unauthorized update, insert, or delete access to some accessible data as well as unauthorized
    read access to a subset of accessible data. (CVE-2017-14735)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Load Testing for Web Apps (Application Development Framework).  An unauthenticated, remote attacker with network 
    access via HTTP can result in takeover of Oracle Application Testing Suite. (CVE-2019-2904)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Oracle Flow Builder (jQuery).  An unauthenticated, remote attacker with network 
    access via HTTP who is able to obtain human interaction can impact additional products and result in
    an unauthorized update, insert, or delete access to some accessible data as well as unauthorized
    read access to a subset of accessible data. (CVE-2019-11358)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Load Testing for Web Apps (Apache POI).  An authenticated, low priviledged remote attacker 
    with network access to the infrastructure can result in unauthorized access to critical data or 
   complete access to all Oracle Application Testing Suite accessible data. (CVE-2019-12415)

  - An unspecified vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager
    subcomponent Oracle Flow Builder.  An unauthenticated remote attacker 
    with network access via HTTP can result in unauthorized access to critical data or 
   complete access to all Oracle Application Testing Suite accessible data. (CVE-2020-2673)");
  # https://www.oracle.com/security-alerts/cpujan2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d22a1e87");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2904");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/27");

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

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
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


# 12.5.0.3, 13.1.0.1, 13.2.0.1 and 13.3.0.1 get checked against the same fix
if ((version =~ "^13\.[0123]\.") || version =~ "^12\.5\.0\.3")
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

security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
