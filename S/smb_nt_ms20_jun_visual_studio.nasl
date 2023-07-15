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
  script_id(137271);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id(
    "CVE-2020-1202",
    "CVE-2020-1203",
    "CVE-2020-1257",
    "CVE-2020-1278",
    "CVE-2020-1293"
  );
  script_xref(name:"MSKB", value:"4562053");
  script_xref(name:"MSFT", value:"MS20-4562053");
  script_xref(name:"IAVA", value:"2020-A-0257-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector or the Visual Studio
    Standard Collector fail to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-1202, CVE-2020-1203)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector Service improperly
    handles file operations. An attacker who successfully
    exploited this vulnerability could gain elevated
    privileges. An attacker with unprivileged access to a
    vulnerable system could exploit this vulnerability. The
    security update addresses the vulnerability by ensuring
    the Diagnostics Hub Standard Collector Service properly
    handles file operations. (CVE-2020-1257, CVE-2020-1278,
    CVE-2020-1293)");
  # https://support.microsoft.com/en-us/help/4562053/june-9-2020-security-update-for-microsoft-visual-studio-2015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cefba37b");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?702c8c2e");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.0#16.0.15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f7a8135");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.4#16.4.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a60d006");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.6.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edec5481");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - KB4562053 (for Visual Studio 2015)
  - Update 15.9.24 for Visual Studio 2017
  - Update 16.0.15 for Visual Studio 2019
  - Update 16.4.10 for Visual Studio 2019
  - Update 16.6.2 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1203");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/09");

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
    fix = '14.0.27541.0';
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
  # VS 2017 Version 15.9.24
  if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.1177';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.0.15
  else if (prod == '2019' && version =~ '^16\\.0\\.')
  {
    fix = '16.0.28803.753';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.4.10
  else if (prod == '2019' && version =~ '^16\\.[1-4]\\.')
  {
    fix = '16.4.30204.51';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.6.2
  else if (prod == '2019' && version =~ '^16\\.[56]\\.')
  {
    fix = '16.6.30204.135';
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

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
