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
  script_id(138473);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-1147", "CVE-2020-1393", "CVE-2020-1416");
  script_xref(name:"MSKB", value:"4567703");
  script_xref(name:"MSFT", value:"MS20-4567703");
  script_xref(name:"IAVA", value:"2020-A-0309-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (July 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists in Visual
    Studio when the software fails to check the source
    markup of XML file input. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the process responsible for
    deserialization of the XML content. (CVE-2020-1147)

  - An elevation of privilege vulnerability exists when the
    Windows Diagnostics Hub Standard Collector Service fails
    to properly sanitize input, leading to an unsecure
    library-loading behavior. An attacker who successfully
    exploited this vulnerability could run arbitrary code with
    elevated system privileges. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. To exploit this
    vulnerability, an attacker would have to log on to an
    affected system and run a specially crafted application.
    (CVE-2020-1393)

  - An elevation of privilege vulnerability exists in Visual
    Studio and Visual Studio Code when they load software
    dependencies. A local attacker who successfully exploited
    the vulnerability could inject arbitrary code to run in the
    context of the current user. If the current user is logged
    on with administrative user rights, an attacker could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or create
    new accounts with full user rights. To exploit this
    vulnerability, a local attacker would need to plant malicious
    content on an affected computer and wait for another user to
    launch Visual Studio or Visual Studio Code. (CVE-2020-1416)");
  # https://support.microsoft.com/en-us/help/4567703/description-of-the-security-update-for-microsoft-visual-studio-2015-up
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e09a167");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - KB4567703
  - Update 15.9.25 for Visual Studio 2017
  - Update 16.0.16 for Visual Studio 2019
  - Update 16.4.11 for Visual Studio 2019
  - Update 16.6.4 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1416");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SharePoint DataSet / DataTable Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

var port, appname, installs, report, install, version, path, prod, fix, file, fver, fversion;

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
    fix = '14.0.27542.0';
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
    # patch_installed = false;
    # foreach name (get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName'))
    #   if ('4567703' >< name)
    #     patch_installed = true;

    # if (!patch_installed)
    #   report +=
    #     '\nNote: The fix for this issue is available in the following update:\n' +
    #     '\n  - KB4567703 : Security update for Microsoft Visual Studio 2015 Update 3: July 14, 2020\n' +
    #     '\n';
  }
  # VS 2017 (15.9)
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.1216';

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
    fix = '16.0.28803.791';
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
    fix = '16.4.30308.118';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.6
  else if (prod == '2019' && version =~ '^16\\.6\\.')
  {
    fix = '16.6.30309.148';
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

