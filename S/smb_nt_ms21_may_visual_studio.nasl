#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149436);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2021-27068", "CVE-2021-31204");
  script_xref(name:"IAVA", value:"2021-A-0220-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (May 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security update. It is, therefore, affected by the multiple
vulnerabilities, including the following:

  - A remote code execution vulnerability exists in Visual Studio. An unauthenticated, remote attacker can
   exploit this to bypass authentication and execute arbitrary commands (CVE-2021-27068). 

  - A privilege escalation vulnerability exists in Visual Studio. An authenticated, local attacker can 
  exploit this to escalate their privileges of an affected system (CVE-2021-31204)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.36
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e238a3e");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.4#16.4.22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f7f7927");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6da57842");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.9.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b804329");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
 - Update 15.9.36 for Visual Studio 2017
 - Update 16.4.22 for Visual Studio 2019
 - Update 16.7.15 for Visual Studio 2019
 - Update 16.9.5 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

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
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

var port = kb_smb_transport();
var appname = 'Microsoft Visual Studio';
var installs = get_installs(app_name:appname, exit_if_not_found:TRUE);
var report = '';

foreach var install (installs[1])
{
  var version = install['version'];
  var path = install['path'];
  var prod = install['product_version'];
  var fix = '';

  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2017
  # VS 2017
  if (prod == '2017')
  {
    fix = '15.9.28307.1525';

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
  # VS 2019 Version 16.0-4
  else if (prod == '2019' && version =~ "^16\.[0-4]\.")
  {
    fix = '16.4.31229.387';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.5-7
  else if (prod == '2019' && version =~ "^16\.[5-7]\.")
  {
    fix = '16.7.31229.181';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.8-9
  else if (prod == '2019' && version =~ "^16\.[89]\.")
  {
    fix = '16.9.31229.75';
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
