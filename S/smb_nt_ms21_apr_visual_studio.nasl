##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(148552);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id(
    "CVE-2021-27064",
    "CVE-2021-28313",
    "CVE-2021-28321",
    "CVE-2021-28322"
  );
  script_xref(name:"MSKB", value:"5001292");
  script_xref(name:"MSFT", value:"MS21-5001292");
  script_xref(name:"IAVA", value:"2021-A-0169-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security update. It is, therefore, affected by the multiple
vulnerabilities, including the following:

  - A privilege escalation vulnerability exists in Microsoft Visual Studio's installer component. An authenticated, 
  local attacker can exploit this, to escalate privileges on an affected system (CVE-2021-27064).

  - Several privilege escalation vulnerabilities exist in Microsoft Visual Studio's diagnostic hub standard collector 
  service component. An authenticated, local attacker can exploit these, to escalate privileges on an affected system 
  (CVE-2021-28313, CVE-2021-28321, CVE-2021-28322).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-the-elevation-of-privilege-vulnerability-in-microsoft-visual-studio-2015-update-3-april-13-2021-kb5001292-5cc101fc-387a-18ac-858b-ad0413ebf8f1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65973f66");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a4be15a");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.4#16.4.21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4025edb6");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?274ed228");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.9.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9691e1b1");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
 - KB5001292 (for Visual Studio 2015)
 - Update 15.9.35 for Visual Studio 2017
 - Update 16.4.21 for Visual Studio 2019
 - Update 16.7.14 for Visual Studio 2019
 - Update 16.9.4 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28322");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/14");

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

var install;
foreach install (installs[1])
{
  var version = install['version'];
  var path = install['path'];
  var prod = install['product_version'];
  var fix = '';

  # VS 2015 Update 3
  if (version =~ '^14\\.0\\.')
  {
    fix = '14.0.27549.0';
    file = hotfix_append_path(path:path, 
      value:'\\Team Tools\\DiagnosticHubCollector\\Collector\\DiagnosticsHub.StandardCollector.Runtime.dll');
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
  # VS 2017
  else if (prod == '2017')
  {
    fix = '15.9.28307.1500';

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
    fix = '16.4.31205.175';
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
    fix = '16.7.31205.176';
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
    fix = '16.9.31205.134';
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
