#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(128708);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2019-1232", "CVE-2019-1301");
  script_xref(name:"MSKB", value:"4513696");
  script_xref(name:"MSFT", value:"MS19-4513696");
  script_xref(name:"IAVA", value:"2019-A-0332");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (September 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - An elevation of privilege vulnerability exists when the Diagnostics Hub Standard Collector Service improperly
    impersonates certain file operations. An attacker who successfully exploited this vulnerability could gain
    elevated privileges. An attacker with unprivileged access to a vulnerable system could exploit this vulnerability.
    The security update addresses the vulnerability by ensuring the Diagnostics Hub Standard Collector Service
    properly impersonates file operations. (CVE-2019-1232)

  - A denial of service vulnerability exists when .NET Core improperly handles web requests. An attacker who
    successfully exploited this vulnerability could cause a denial of service against a .NET Core web application.
    The vulnerability can be exploited remotely, without authentication. The update addresses the vulnerability by
    correcting how the .NET Core web application handles web requests. (CVE-2019-1301)");
  # https://support.microsoft.com/en-ie/help/4513696/security-update-for-elevation-of-privilege-vulnerability-vs-2015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfa387b3");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d93e731");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8a4791b");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30855885");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8a4791b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - KB4513696
  - Update 15.9.16 for Visual Studio 2017
  - Update 16.0.8 for Visual Studio 2019
  - Update 15.0 (26228.98) for Visual Studio 2017
  - Update 16.2.5 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1232");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('install_func.inc');
include('global_settings.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

var port = kb_smb_transport();
var appname = 'Microsoft Visual Studio';

var installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

var report = '';

foreach install (installs[1])
{
  var version = install['version'];
  var path = install['path'];
  var prod = install['product_version'];

  var fix = '';

  # VS 2015 Up3
 # Adjusting this per the advisory to use mspdbcore.dll
  if (version =~ '^14\\.0\\.')
  {
    var fix = '14.0.27537.0';
    var path = hotfix_append_path(path:path, value:'Team Tools\\DiagnosticsHub\\Collector\\DiagnosticsHub.StandardCollector.Runtime.dll');

    var fver = hotfix_get_fversion(path:path);
    if (fver['error'] != HCF_OK)
     continue;
     fver = join(sep:'.', fver['value']);
    if (ver_compare(ver:fver, fix:fix, strict:FALSE) < 0)
    {
      report +=
       '\n  Path              : ' + path +
       '\n  Installed version : ' + fver +
       '\n  Fixed version     : ' + fix +
       '\n';
    }
  }
  # VS 2017 (15.0)
  else if (prod == '2017' && version =~ '^15\\.0\\.')
  {
    foreach name (get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName'))
    if ('4513696' >< name)
    patch_installed = true;

    var fix = '15.0.26228.98';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2017 version 15.9
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    var fix = '15.9.28307.858';

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
    var fix = '16.0.28803.584';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.2
  else if (prod == '2019' && version =~ '^16\\.2\\.')
  {
    var fix = '16.2.29306.81';

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
