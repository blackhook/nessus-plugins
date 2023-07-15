#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(140465);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-1130",
    "CVE-2020-1133",
    "CVE-2020-16856",
    "CVE-2020-16874"
  );
  script_xref(name:"MSKB", value:"4571480");
  script_xref(name:"MSKB", value:"4571479");
  script_xref(name:"MSKB", value:"4571481");
  script_xref(name:"MSKB", value:"4576950");
  script_xref(name:"MSFT", value:"MS20-4571480");
  script_xref(name:"MSFT", value:"MS20-4571479");
  script_xref(name:"MSFT", value:"MS20-4571481");
  script_xref(name:"MSFT", value:"MS20-4576950");
  script_xref(name:"IAVA", value:"2020-A-0414-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector improperly handles
    file operations. An attacker who successfully exploited
    this vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Diagnostics Hub Standard
    Collector handles file operations. (CVE-2020-1133)

  - A remote code execution vulnerability exists in Visual
    Studio when it improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current
    user. If the current user is logged on with
    administrative user rights, an attacker could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2020-16856,
    CVE-2020-16874)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector improperly handles
    data operations. An attacker who successfully exploited
    this vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Diagnostics Hub Standard
    Collector handles data operations. (CVE-2020-1130)");
  # https://support.microsoft.com/en-us/help/4571480/security-update-for-visual-studio-2013-update-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1837f66d");
  # https://support.microsoft.com/en-us/help/4571479/security-update-for-visual-studio-2012-update-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40ae669c");
  # https://support.microsoft.com/en-us/help/4571481/security-update-for-visual-studio-2015-update-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c1500e4");
  # https://support.microsoft.com/en-us/help/4576950/security-update-for-visual-studio-2015-update-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d7d095b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4571480
  -KB4571479
  -KB4571481
  -KB4576950");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16874");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

port = kb_smb_transport();
appname = 'Microsoft Visual Studio';

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['product_version'];

  fix = '';

  # VS 2012 Up5
  if (version =~ '^11\\.0\\.')
  {
    fix = '11.0.61246.400';
    file = hotfix_append_path(path:path,
             value:'Common7\\IDE\\Extensions\\Microsoft\\VsGraphics\\Dxtex.dll');
    fver = hotfix_get_fversion(path:file);
    if (fver['error'] != HCF_OK || empty_or_null(fver['value']))
      continue;

    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + file +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2013 Up5
  else if (version =~ '^12\\.0\\.')
  {
    fix = '12.0.40689.0';
    file = hotfix_append_path(path:path,
             value:'Common7\\IDE\\Extensions\\Microsoft\\VsGraphics\\Dxtex.dll');
    fver = hotfix_get_fversion(path:file);

    if (fver['error'] != HCF_OK || empty_or_null(fver['value']))
      continue;

    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + file +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2015 Up3
  else if (version =~ '^14\\.0\\.')
  {
    fix = '14.0.27543.0';
    file = hotfix_append_path(path:path,
             value:'Common7\\IDE\\Extensions\\Microsoft\\VsGraphics\\Dxtex.dll');
    fver = hotfix_get_fversion(path:file);

    if (fver['error'] != HCF_OK || empty_or_null(fver['value']))
      continue;

    fversion = join(sep:'.', fver['value']);
    if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + file +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2017
  #
  # VS 2017
  else if (prod == '2017')
  {
    fix = '15.9.28307.1259';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2019
  #
  # VS 2019 Version 16.0
  else if (prod == '2019' && version =~ "^16\.0\.")
  {
    fix = '16.0.28803.826';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.4
  else if (prod == '2019' && version =~ "^16\.[1-4]\.")
  {
    fix = '16.4.30427.197';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.7
  else if (prod == '2019' && version =~ "^16\.[5-7]\.")
  {
    fix = '16.7.30503.244';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
}

hotfix_check_fversion_end();

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);




