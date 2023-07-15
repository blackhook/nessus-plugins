#TRUSTED 48e96f0bf6b3152170449b972c6213ed617c50c2634f900d85391a168554ad725f3c53441a46debde53e019f10efda6d7d38143c48061c9fecdd12cdc180b51d8226f0c6881eab2190c9e891cc9382c6e0b55d16fff61dd77683fba8bb86f4068403f1918fed34ed98a6b6851031cf21302deca00bd267b1d0ab842af2e85a43289f6c5ac94f79620d6414d15b8a1f99440ffbc986e4bd61de024e71ace456d107612f4dedaaa2277ba638677950b464ccd5ab55041ed847dab3c26fbf396238132830c67472a6663260ab5f7b3b5abda523faf62146fc0e59665a650913ae1c59354f726773d9178dd75d96ed3ee05a413643b238e6122250d96b6669366bac48ad5f10f3116adfacba22291a460ee65b5b5a4430f289fd4d70a219b50774ba6a410b7ac08419e9e9e55080dfef261a0cea1f8d7d98f7656b5f8c3895267f9b405e93874683cadaa8acbe16b45f073a8136a8279454f208cf39a8d5b5e6157024f6d19ee377f0336ae59f164434c9aa41e39d052e7c9d221243a8388efaea3a307de04285f9328c203fe7177bcfcee17b383d87edbde4d4f657352a9b54cf80dee2d5dc658f6aa7b76387de7a89ea901fd0272a5d0f8a12b1138e43190a8ae02ae515792f4e2a47078f440a5bea39871dcdfcbadb70f4f1fe56eb30aca932406213bd0ddf46fbe3a9a001cd34d28a4618c6f743d089a37249c67b5dc194c0ed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85878);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-2520", "CVE-2015-2523");
  script_bugtraq_id(76561, 76564);
  script_xref(name:"MSFT", value:"MS15-099");
  script_xref(name:"IAVA", value:"2015-A-0214");
  script_xref(name:"EDB-ID", value:"38214");
  script_xref(name:"EDB-ID", value:"38215");
  script_xref(name:"MSKB", value:"3088501");

  script_name(english:"MS15-099: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3089664) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office installed
that is affected by multiple remote code execution vulnerabilities due
to improper handling of objects in memory. A remote attacker can
exploit these vulnerabilities by convincing a user to open a specially
crafted file in Microsoft Office, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-099");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and for Office
2016 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2016:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2016");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# Gather version info for Office 2011
info = '';
installs = make_array();
office_2011_found = FALSE;

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';

version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.")
    exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  office_2011_found = TRUE;
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.5.5';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

# Checking for Office 2016. The same path for the overall install
# doesn't exist for 2016, so we need to check each app, as each one
# is listed as needing an update to 15.14.

apps = make_list(
         "Microsoft Outlook",
         "Microsoft Excel",
         "Microsoft Word",
         "Microsoft PowerPoint",
         "Microsoft OneNote");
fix_2016 = "15.14.0";

office_2016_found = FALSE;
foreach app (apps)
{
  plist = "/Applications/"+app+".app/Contents/Info.plist";
  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  ver_2016 = exec_cmd(cmd:cmd);

  # check all of the applications
  if (!strlen(ver_2016))
    continue;

  office_2016_found = TRUE;
  if(ver_2016 =~ "^15\." &&
     ver_compare(ver:ver_2016, fix:fix_2016, strict:FALSE) < 0)
  {
    vuln[app] = ver_2016;
  }
}

if (office_2016_found)
{
    foreach app (keys(vuln))
    {
      info +=
        '\n  Product           : ' + app +
        '\n  Installed version : ' + vuln[app] +
        '\n  Fixed version     : ' + fix_2016 + '\n';
    }
}

# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  msg = '';
  is = 'is';

  if (! office_2016_found && ! office_2011_found)
    audit(AUDIT_NOT_INST, "Office for Mac 2011/2016");
  if (office_2011_found)
  {
    msg = "Office for Mac 2011";
  }
  if (office_2016_found)
  {
    if (office_2011_found)
    {
      msg += " and ";
      is = "are";
    }
    msg += "Office 2016 for Mac";
  }

  exit(0, msg + " " + is + " not vulnerable.");
}
