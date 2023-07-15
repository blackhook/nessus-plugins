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
  script_id(134381);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id(
    "CVE-2020-0789",
    "CVE-2020-0793",
    "CVE-2020-0810",
    "CVE-2020-0884"
  );
  script_xref(name:"MSKB", value:"4538032");
  script_xref(name:"MSFT", value:"MS20-4538032");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (March 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - A spoofing vulnerability exists in Microsoft Visual
    Studio as it includes a reply URL that is not secured by
    SSL. An attacker who successfully exploited this
    vulnerability could compromise the access tokens,
    exposing security and privacy risks.  (CVE-2020-0884)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector or the Visual Studio
    Standard Collector allows file creation in arbitrary
    locations.  (CVE-2020-0810)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector Service improperly
    handles file operations. An attacker who successfully
    exploited this vulnerability could gain elevated
    privileges. An attacker with unprivileged access to a
    vulnerable system could exploit this vulnerability. The
    security update addresses the vulnerability by ensuring
    the Diagnostics Hub Standard Collector Service properly
    handles file operations. (CVE-2020-0793)

  - A denial of service vulnerability exists when the Visual
    Studio Extension Installer Service improperly handles
    hard links. An attacker who successfully exploited the
    vulnerability could cause a target system to stop
    responding.  (CVE-2020-0789)");
  # https://support.microsoft.com/en-us/help/4538032/march-10-2020-security-update-for-microsoft-visual-studio-2015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?627290b1");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - KB4538032
  - Update 15.9.21 for Visual Studio 2017
  - Update 16.0.12 for Visual Studio 2019
  - Update 16.4.6 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  # VS 2015 Up3
  if (version =~ '^14\\.0\\.')
  {
    fix = '14.0.27539.1';
    path = hotfix_append_path(path:path, value:'Team Tools\\DiagnosticsHub\\Collector\\DiagnosticsHub.StandardCollector.Runtime.dll');

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
  # VS 2017 (15.9)
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.1064';

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
    fix = '16.0.28803.697';
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
    fix = '16.4.29905.134';
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
