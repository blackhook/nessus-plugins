#TRUSTED 4438505dab68f9937aeb5f42a7295671241883d430593c1280f5f69119b0369e95e1b5183baac1b1ee370eb82256ac78ea7abeefd6d495a1c38fbe67299fecb06dc8af7baa7534fc0a836e75cab1e2c73ec478c90e5023d494cc240fbba441442f6ac0d79b108a4d00fd71716abd8fb1451b15841279a920c8e155e6023ade9e28612a653879096bd1bb21a703574c5b4d3bd2498319a4a08fd57142eb1b46712d2fb26dd7f3f8426a0db1dcfcec5a8f4bcb26557b9536e025c3397277aa13612fa668eea5dad2e051fb3d1a7b524bbf98d64abfd65f99e375adad77c078ae8a2a7113bc45c8b01cff121effdaf59bc2192310ff74fa35673417542d1652444aae1ecac3783f66ea420b73b6d8e2180ee8ab8d1fb76ad21b86f38f155239ef9d6e422c1d3c396251cfc782d020ca4d012cd1a4e9bf48400c36032855b8bfbbfd25e1e12e6df27f3433dc7c382d947a6025aee5a20564bcbfb9cc246822815bb7b6628d705e6a2c43aea698fa3dc0ea184f419c5a2c0275199df7f1bd353a15bf855599151c27a5a0bb1d81408fe58a6f68f51ed9c85cb2c0678dff784324a9d664c22c94863868da035de9e976834e22e39188466b3326395b1f68d6cf45d927ad38fb0d359c6b80c2466e92a40b9ab638be459d02e67644801e110c04561843cadda5690168174b6fed6dfc82c0ca1dff765337ec23e77af8607205a5859a2e
#TRUST-RSA-SHA256 b04ec8e2011fc01d5497c26b152fded13457dec5c18a1868086a2384979aa1b3dad3abda3cdc4c829adc1ae7ad5100e773cbd79908294a3c7504a4c70725d04bce053367a48a1e3bc0ae49e569ccb26dae751dae7c89a5b3064432bc67b9089ac1f8b01fcff1468e4a217ed4217fc0b7a151dfcbda5362d3869446532ab0f791922caf670c1fc383124426a42142953c8806bc7ea1e53274f1ce1b35856bae58f6f74ee22cd7b5d6816f2451620481182a37aab753c820010744e993a15794b221a808dd429a887f46ae011acfc8c60d8c998e3208e435b7a7d61ee63743d520523b75bf3edb9ccd0206e99c07449f732c0daf1909b7358f61c8db02d551fd5b41754438bc7e226eb49d4fcb74ab71108119fe73d11468d8338f43254d10a23e45b9ec9c07da59be45bbf251a13e9b1fe8206f7f0103765bd11bccf7ca4624321275362d0fc5ad9901632d36e437d60c21d861d434cb28ee51812d53a2287e60e8edc4af9a9df7cfb431963d540d6790c53512d778ace39cd8b6b938813f8169171a2f5f515f9716e6c61458feb5ca5905bc4b4a00be4c51b971c6f4c4973abf32013bcc4f4115d51e206d0a10a50be70c4405d31aa6dc7d4e986f6a9aa12df055aad63d115fd17f1e034b8903b29b4cb7322bed72bd2af422ae850c4cab88f9283b82de0db60d9980f32a7edb3f88ac901cb38fd10e5f7ed31030cf93a22ef3
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50058);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2008-1455",
    "CVE-2008-3003",
    "CVE-2008-3004",
    "CVE-2008-3005",
    "CVE-2008-3006"
  );
  script_bugtraq_id(30579, 30638, 30639, 30640, 30641);
  script_xref(name:"MSFT", value:"MS08-043");
  script_xref(name:"MSFT", value:"MS08-051");
  script_xref(name:"MSKB", value:"949785");
  script_xref(name:"MSKB", value:"954066");
  script_xref(name:"MSKB", value:"956343");
  script_xref(name:"MSKB", value:"956344");

  script_name(english:"MS08-043 / MS08-051: Vulnerabilities in Microsoft Could Allow Remote Code Execution (954066 / 949785) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or PowerPoint file, these issues could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-043");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3006");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
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

  fixed_version = '12.1.2';
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

  fixed_version = '11.5.1';
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
