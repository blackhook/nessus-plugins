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
  script_id(111042);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-8171",
    "CVE-2018-8172",
    "CVE-2018-8232",
    "CVE-2018-8260"
  );
  script_bugtraq_id(
    104616,
    104640,
    104659,
    104666
  );
  script_xref(name:"MSKB", value:"4336946");
  script_xref(name:"MSKB", value:"4336986");
  script_xref(name:"MSKB", value:"4336999");
  script_xref(name:"MSKB", value:"4336919");
  script_xref(name:"MSKB", value:"4339279");
  script_xref(name:"MSFT", value:"MS18-4336946");
  script_xref(name:"MSFT", value:"MS18-4336986");
  script_xref(name:"MSFT", value:"MS18-4336999");
  script_xref(name:"MSFT", value:"MS18-4336919");
  script_xref(name:"MSFT", value:"MS18-4339279");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (July 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists in Visual
    Studio software when the software does not check the
    source markup of a file for an unbuilt project. An
    attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current
    user. If the current user is logged on with
    administrative user rights, an attacker could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2018-8172)

  - A Security Feature Bypass vulnerability exists in
    ASP.NET when the number of incorrect login attempts is
    not validated. An attacker who successfully exploited
    this vulnerability could try an infinite number of
    authentication attempts. The update addresses the
    vulnerability by validating the number of incorrect
    login attempts. (CVE-2018-8171)
    
  - A remote code execution vulnerability exists in .NET
    software which can lead to exploitation of a user's
    machine by allowing attackers to run arbitrary code.
    The update addresses the vulnerability by correcting
    how .NET checks the source markup of a file.
    (CVE-2018-8260)
  
  - A tampering vulnerability exists in Microsoft Macro
    Assembler when code is improperly validated. The
    security update addresses the vulnerability asserting
    that Microsoft Macro Assembler properly validates
    code logic. (CVE-2018-8232)");
  # https://support.microsoft.com/en-us/help/4336946/security-update-for-vulnerabilities-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81426623");
  # https://support.microsoft.com/en-us/help/4336986/security-update-for-vulnerabilities-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8520cbfa");
  # https://support.microsoft.com/en-us/help/4336999/security-update-for-vulnerabilities-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8200e172");
  # https://support.microsoft.com/en-us/help/4336919/security-update-for-vulnerabilities-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eee030b0");
  # https://support.microsoft.com/en-us/help/4339279/description-of-the-security-update-for-the-asp-net-security-featu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59900f80");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4336946
  -KB4336986
  -KB4336999
  -KB4336919
  -KB4339279");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');
port = kb_smb_transport();
appname = "Microsoft Visual Studio";

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['prod'];

  fix = '';

  # VS 2010 SP1                 
  if (version =~ '^10\\.0\\.')
  {
    filechkd = "Common7\IDE\setupui.dll";
    
    fver = hotfix_get_fversion(path:path+filechkd);
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '10.0.40219.493', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + filechkd +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 10.0.40219.493' +
        '\n';
    }
  }

  # VS 2012 Up5
  else if (version =~ '^11\\.0\\.')
  {
    filechkd = "Common7\IDE\xdesproc.exe";
    
    fver = hotfix_get_fversion(path:path + filechkd);
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '11.0.61236.400', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + filechkd +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 11.0.61236.400' +
        '\n';
    }
  }

  # VS 2013 Up5
  else if (version =~ '^12\\.0\\.')
  {
    filechkd = "Common7\IDE\xdesproc.exe";
    
    fver = hotfix_get_fversion(path:path+filechkd);
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '12.0.40675.0', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + filechkd +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 12.0.40675.0' +
        '\n';
    }
  }

  # VS 2015 Up3 - #verified
  # File Check change: using file 'preparation.exe',
  # but only the one in 'Common7\IDE\'.
  else if (version =~ '^14\\.0\\.')
  {
    filechkd = "Common7\IDE\xdesproc.exe";

    fver = hotfix_get_fversion(path:path+filechkd);
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '14.0.27522.0', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + filechkd +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 14.0.27522.0' +
        '\n';
    }
  }

  # VS 2017 15.0 Preview
  else if (prod == '2017 Preview' && version =~ '^15\\.0\\.') 
  {
    fix = '15.0.26228.43';
    
    filechkd = "Common7\IDE\xdesproc.exe";
    fver = hotfix_get_fversion(path:path+filechkd);
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + filechkd +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 15.0.26228.43' +
        '\n';
    }
  }

  # VS 2017 15.x
  else if (prod == '2017' && version =~ '^15\\.[1-7]\\.')
  {
    fix = '15.7.27703.2042';
    fver =  install["version"];

    if (ver_compare(ver: fver, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +"Common7\IDE\devenv.exe" +
        '\n  Installed version : ' + fver +
        '\n  Fixed version     : 15.7.27703.2042' +
        '\n';
    }
  }
}

hotfix_check_fversion_end();

if (report != '')
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
