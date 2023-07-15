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
  script_id(109029);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/01");

  script_cve_id("CVE-2018-1037");
  script_bugtraq_id(103715);
  script_xref(name:"MSKB", value:"4089501");
  script_xref(name:"MSKB", value:"4091346");
  script_xref(name:"MSKB", value:"4087371");
  script_xref(name:"MSKB", value:"4089283");
  script_xref(name:"MSFT", value:"MS18-4089501");
  script_xref(name:"MSFT", value:"MS18-4091346");
  script_xref(name:"MSFT", value:"MS18-4087371");
  script_xref(name:"MSFT", value:"MS18-4089283");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (April 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An information disclosure vulnerability exists when
    Visual Studio improperly discloses limited contents of
    uninitialized memory while compiling program database
    (PDB) files. An attacker who took advantage of this
    information disclosure could view uninitialized memory
    from the Visual Studio instance used to compile the PDB
    file. To take advantage of the vulnerability, an
    attacker would require access to an affected PDB file
    created using a vulnerable version of Visual Studio. An
    attacker would have no way to force a developer to
    produce this information disclosure. The security update
    addresses the vulnerability by correcting how PDB files
    are generated when a project is compiled.
    (CVE-2018-1037)");
  # https://support.microsoft.com/en-us/help/4089501/description-of-the-security-update-for-the-information-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a8e7d73");
  # https://support.microsoft.com/en-us/help/4091346/information-disclosure-vulnerability-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b4e94bf");
  # https://support.microsoft.com/en-us/help/4087371/information-disclosure-vulnerability-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b61645d0");
  # https://support.microsoft.com/en-us/help/4089283/information-disclosure-vulnerability-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de1ae25a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4089501
  -KB4091346
  -KB4087371
  -KB4089283");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1037");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var port, appname, installs, report, version, path, prod, fix, fver, fversion, digits, vcomp_out;

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
    fver = hotfix_get_fversion(path:path+"Common7\IDE\mspdbsrv.exe");
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
      fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '10.0.40219.478', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "Common7\IDE\mspdbsrv.exe" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 10.0.40219.478' +
        '\n';
    }
  }

  # VS 2012 Up5
  else if (version =~ '^11\\.0\\.')
  {
        fver = hotfix_get_fversion(path:path+"Common7\IDE\mspdbsrv.exe");
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
      fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '11.0.61232.400', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "Common7\IDE\mspdbsrv.exe" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 11.0.61232.400' +
        '\n';
    }
  }

  # VS 2013 Up5
  else if (version =~ '^12\\.0\\.')
  {
    fver = hotfix_get_fversion(path:path+"VC\bin\mspdbsrv.exe");
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
      fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '12.0.40669.0', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "VC\bin\mspdbsrv.exe" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 12.0.40669.0' +
        '\n';
    }
  }

  # VS 2015 Up3
 # Adjusting this per the advisory to use mspdbcore.dll
  else if (version =~ '^14\\.0\\.')
  {
    fver = hotfix_get_fversion(path:path+"Common7\IDE\mspdbcore.dll");
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
      fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '14.0.24235.0', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "Common7\IDE\mspdbcore.dll" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 14.0.24235.0' +
        '\n';
    }
  }

  # VS 2017 and VS 15.6
  # VS had inconsistent versioning
  else if (prod == '2017')
  {
    digits = split(version, sep:'.', keep:false);

    if (int(digits[1]) > 0 || int(digits[2]) > 26228)
    {
      fix = '15.6.27428.2037';
    }
    else
    {
      fix = '15.0.26228.30';
    }
  }
  # VS 2017 15.7 Preview
  else if (prod == '2017 Preview' && version =~ '^15\\.7\\.')
    fix = '15.7.27617.1';

  if (fix != '');
  {
    vcomp_out = ver_compare(ver:version, fix:fix);
    if (!isnull(vcomp_out) && vcomp_out < 0)
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

if (report != '')
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
