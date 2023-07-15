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
  script_id(135481);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2020-0899", "CVE-2020-0900");
  script_xref(name:"MSKB", value:"4540102");
  script_xref(name:"MSFT", value:"MS20-4540102");
  script_xref(name:"IAVA", value:"2020-A-0148-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (April 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities :

  - An elevation of privilege vulnerability exists when Microsoft Visual Studio updater service improperly
    handles file permissions. An attacker who successfully exploited this vulnerability could overwrite
    arbitrary file content in the security context of the local system.  (CVE-2020-0899)

  - An elevation of privilege vulnerability exists when the Visual Studio Extension Installer Service
    improperly handles file operations. An attacker who successfully exploited the vulnerability could delete
    files in arbitrary locations with elevated permissions. (CVE-2020-0900)");
  # https://support.microsoft.com/en-us/help/4540102/april-14-2020-security-update-for-microsoft-visual-studio-2015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3cd44a9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - KB4540102 (for Visual Studio 2015)
  - Update 15.9.22 for Visual Studio 2017
  - Update 16.0.13 for Visual Studio 2019
  - Update 16.4.7 for Visual Studio 2019
  - Update 16.5.4 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0900");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");

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

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

port = get_kb_item("SMB/transport");
appname = 'Microsoft Visual Studio';

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['product_version'];

  fix = '';

  # VS 2015 Up3
  if (version =~ '^14\\.0\\.')
  {
    patch_installed = false;
    foreach name (get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName'))
      if ('4540102' >< name)
        patch_installed = true;

    if (!patch_installed)
      report +=
        '\nNote: The fix for this issue is available in the following update:\n' +
        '\n  - KB4540102 : Security update for Microsoft Visual Studio 2015 Update 3: April 14, 2020\n' +
        '\n';
  }
  # VS 2017 (15.9)
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.1093';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.0
  else if (prod == '2019' && version =~ '^16\\.0\\.')
  {
    fix = '16.0.28803.718';
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
  else if (prod == '2019' && version =~ '^16\\.4\\.')
  {
    fix = '16.4.30011.19';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.5
  else if (prod == '2019' && version =~ '^16\\.5\\.')
  {
    fix = '16.5.30011.22';
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

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
