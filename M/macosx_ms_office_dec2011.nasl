#TRUSTED adb55e64754b53be8d9ed4b26518798e901766695c0c72647658131e8db7da2f078b9e24dba51de84a9554a989ea38d2e1ab911bf2a7179082de7d8c1474d511b054f98bc8e6f1bedc6f1606ec42673f9eee8d1c1d7e9cd2e86a6f29f78f084b36db66352ba95b068ec2fe2eac0da3bb069b607da26d3fb6dd29b3f9db4a7d79184aac6a8fe31ad294462a29b48e0d712f1ab93aa15b390e48f344429cd8439ed87fd2607da803d77e34f2279e87a8b55e6d8c50156a9f6a81d46846663c2091558c495e6896944464adea771bb6b035373001cb0d6060df77b256a667313075d2d013dc27292b0944798d38e6c016130b3680240b347125ae409f50521a8d39898b2a7f7abd2f3f169234fc5fac3b69d1630586fc530d4ea2d43233782b69e5a094c89c5e736e6e12ae2bf98904104f713fe92dedc28f2fdfd46395da7072fa2e04086a377b238b94e00a8730c15635513b9323236f3508164d24011ff978e81634d4b6767f10082f07c8f7194f9c5f0b67498cf82d1ed5c0ae9ea00f5a5f6f0736dca3e657ba33ea768d409af56ea8b3c181fb716346a09426b3259ba5cda44d411ca51a393d8ce8b7e95101263f1558faaaf485e4297b94bcb45c7b2ab7f2c95ebdf518e2fc8225eeb2ab8f11b7a45533b9523790e51f042abb743f464d527eee248c2459cdc5e2dfe9af6fcd99f731395bc0eea5e6d0527b05ef9e43466f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57286);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2011-1983", "CVE-2011-3403", "CVE-2011-3413");
  script_bugtraq_id(50954, 50956, 50964);
  script_xref(name:"MSFT", value:"MS11-089");
  script_xref(name:"IAVA", value:"2011-A-0166");
  script_xref(name:"MSFT", value:"MS11-094");
  script_xref(name:"MSFT", value:"MS11-096");
  script_xref(name:"MSKB", value:"2590602");
  script_xref(name:"MSKB", value:"2639142");
  script_xref(name:"MSKB", value:"2640241");
  script_xref(name:"MSKB", value:"2644347");
  script_xref(name:"MSKB", value:"2644354");
  script_xref(name:"MSKB", value:"2644358");

  script_name(english:"MS11-089 / MS11-094 / MS11-096 : Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2590602 / 2639142 / 2640241) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by the following vulnerabilities :

  - A use-after-free vulnerability could be triggered when
    reading a specially crafted Word file. (CVE-2011-1983)

  - A memory corruption vulnerability could be triggered
    when reading a specially crafted Excel file.
    (CVE-2011-3403)

  - A memory corruption vulnerability could be triggered
    when reading an invalid record in a specially crafted
    PowerPoint file. (CVE-2011-3413)

If a remote attacker can trick a user into opening a malicious file
using the affected install, these vulnerabilities could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-089");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-094");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-096");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011, Office 2008
for Mac, and Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

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


# Gather version info.
info = '';
installs = make_array();

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
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.1.4';
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

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '12.3.2';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.6.6';
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


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
