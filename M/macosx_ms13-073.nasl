#TRUSTED b0f1ce2af5be68c246a41cbb9813fbbb0a4ea33087337876b609f1f0df569382be56159100142584349c3fa6603044803546a023e8bab1cb7c7ff5cc0578047f74bf6b560ceb8c01a5cd5a10c7d0c6991d9901b96f19eb4961d773d39aac5cf2f7e20311743e8edc1c9e53894ee0a8a8a440e75b869aec90903915823640a816033c08da443f657fed91f691cd025d5becced0cee06f4304e17e472acdccdb4c8cc6993fb44c3d6c49155d95f059e180508ec0b2e4aa2803de258b11ce9f51ba98ec99eeb5a3b8d5d3f9117da6a943c7ef468fad622db5f61dfec8a9aa25a0e0d8cbda7e096a4b0b449a7c6eb7c575ee10ec82af59d5c473b6c6e911eb5409b05ecfa08179b651a9e6236de88bf1d59e1f9bb98d1fff6482d053ee83da92f6af8d96252425878e0b03248ce125b9a697c5a122def4c78b03100618c13a8b64a72a626ee1b080672952bfefc709ba9bc43244d60279d0c3243b9914b24641055f36663caf2dacd08c47bdc71cd62b699e63d0552a94632aa725d2047ceb3657499ede131e311b957542af9fb170c620597467d562b62c2950049c90a90c5a94f3e6e01238e4d65b2e24339346f8fea08cf606f0f6778e40a471922693af8fb866fadb493cd2da5750685ce406917cb9b9e1b4bbe10d3e549c0980347fb4a0f954cc3c623a9256caffb615ba781463b6b378170b65b802242a15e1464711cce6e6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69839);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-1315", "CVE-2013-3158", "CVE-2013-3159");
  script_bugtraq_id(62167, 62219, 62225);
  script_xref(name:"MSFT", value:"MS13-073");
  script_xref(name:"MSKB", value:"2877813");

  script_name(english:"MS13-073: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2858300) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - Two memory corruption vulnerabilities exist due to the
    way the application handles objects in memory when
    parsing Office files. (CVE-2013-1315 / CVE-2013-3158)

  - An information disclosure vulnerability exists due to
    the way the application parses XML files containing
    external entities. (CVE-2013-3159)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to read arbitrary files on the target system or execute
arbitrary code, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-073");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  fixed_version = '14.3.7';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
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
