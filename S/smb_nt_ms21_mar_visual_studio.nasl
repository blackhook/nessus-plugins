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
  script_id(147749);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2021-21300");
  script_xref(name:"IAVA", value:"2021-A-0133-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security
update. It is, therefore, affected by the following
vulnerability:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-21300)");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.34
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?35639538");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.13
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?59306b22");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.8#16.8.7
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?ceb97f0f");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.9.1
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?2e4fedc9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
 - Update 15.9.34 for Visual Studio 2017
 - Update 16.7.13 for Visual Studio 2019
 - Update 16.8.7 for Visual Studio 2019
 - Update 16.9.1 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21300");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Git LFS Clone Command Exec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2017
  #
  # VS 2017
  if (prod == '2017')
  {
    fix = '15.9.28307.1440';

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
  # VS 2019 Version 16.4
  else if (prod == '2019' && version =~ "^16\.[0-4]\.")
  {
    fix = '16.4.31026.101';
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
    fix = '16.7.31026.100';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.8
  else if (prod == '2019' && version =~ "^16\.8\.")
  {
    fix = '16.8.31025.109';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.9
  else if (prod == '2019' && version =~ "^16\.9\.")
  {
    fix = '16.9.31105.61';
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

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
