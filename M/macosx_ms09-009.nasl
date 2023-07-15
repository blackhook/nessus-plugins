#TRUSTED 28b809f6c37f8170ca5b7c7a1ad128b130856e97065b402a2d8738033247594435551f7f6c0b5892f2d04c8ccaae39f397283e0beee146fa0445900a0ffe4439a7be7c69645da31c5d30352f07d904a8ccbb40aa7cf0fba10c417ccbe445239afff0be530791d118596b3fffc92daeef7df2d1b066ddbe191919686d10397fd8fc3d33e4bcd41aa3a06fafb2e184bcc081d2e7860389c66002dd261d7e368561c6ad51b01baee021750b8b3b9c2fe233bed37ad8dfaa65f324dba0e99fcd6f50ceb5c0bf73104b51a1866e63d7e0dbbab52f21da07aeac002c5a7a4d52c5edf89de18140244e9023cb89b30829a44ee7b4bcba60b1cb9adcbd561b3d69948c4a48079fd5884b3e27a80d3e8d4a714ec43baf89cb60fa788c4cddf9872c8b68d4b60bf1087dcbc5b986c9445ba92a3d1aa041a04c7647e51aac69fdd1bf7c24e2f562d8b21e2ca8163a710bab3ad8004db20e5e1a4f1d02c86f9726d2110a6e14fc3f67eccd4a7c76a86ef035160dc3279e106ee7d67385f1d3a93eea70a790f1254fe3fbb58acda57aecefbdc4d08351d54c595dec180251e3316bfa6203ee904d213a3358583d07a1d90fa70b3526566463db6f4b5ece612d7cd25787711c6b33470d6656270d467b62047f7c4f94cd022cf764f0c5c31924e4669a3dde2357de9adcbbdd0d808c88290d9207f5cd27b12660be564a88abc97e3d1a0e5b9b76
#TRUST-RSA-SHA256 abe508cc3a0322482c2dc65a5269a8bc938391999a44ccff8b8e09e268cff0d9e50f7f012a2f4881d8d135dc8271b694927a61d1b1f0b8ff448478dbbf5b0da0d27a3f93d96e70511a2588a93261f8f75ace052f3efab0987ea517a3ef93c6a6f5ac9d72a60966f20ad88a5f9bfc03c865d2e5b7386020b1f6cbc4f9ef67cde315c539512b3db69e60a5350265496429504d847a02817916e824f656988161939e6d2be7f667afb2366db3a5f2fac48bf2835463051891fdbf697bdb786a8accc877ded25ea28067ba6f48d254e4371eb37678336b688a214604349eaf0b63bc447c49200e08673681153af700de92ac2c4feafc0b4a69313213b8b10967f8ed025a9b2a3eaeb33c1686ce893b7b00b9bf9cb91ce162d38f2b36bcb2772f2d34ea7467bedb2f77b71e99c97a896ad57dad11e30f53530d594b32bdf64eef11f9d87d356bb52e982243b60a902779c60a86872b19c0cb2e43f0b16d4779e91b22f185f1a36b672440fda902ddcefc60ebbd89cc3e7a2dd8a93fcbb74cda35b38761f1dce3921f3b2ed5bef16b73762996249dfde9c600035c180b4489200663117773a9589d7929490a3961d8af1390556c25f307406345ade5a6bbe3754175e85abcb928d692eecfd12cb3a10d46f7cee0a294dedcf23fb9b2b3f84c03f4fac57a442e33bf59e8694f3e39cb063eda8862e5b41a7a61c9926c1e71387d5314c9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50061);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2009-0100", "CVE-2009-0238");
  script_bugtraq_id(33870, 34413);
  script_xref(name:"MSFT", value:"MS09-009");
  script_xref(name:"MSKB", value:"968557");
  script_xref(name:"MSKB", value:"968694");
  script_xref(name:"MSKB", value:"968695");

  script_name(english:"MS09-009: Vulnerabilities in Microsoft Office Excel Could Cause Remote Code Execution (968557) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office
Excel that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-009");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0238");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function exec(cmd)
{
  local_var buf, ret;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.1.7';
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

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.5.4';
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
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:info);
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
