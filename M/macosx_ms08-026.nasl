#TRUSTED ac9f2d515e552631e9a93efb407bfe4a76dc570ca1dd985f6216dc2d4258746485c766d96d18c84fb09d5b6d4bd5c979f81b9d601f2d11e2bb14450e0229e71c2fc5c407f9d0e6634ce68a8e1746e174db0a2e7056076e5880a03d1d56e59cd04974df509180e8a90bac8da094f3576615cab92c1399c1f2ad88ab6acdc83a07b5a2b489878af02b76f54e6c515c374fe965975e64b00e9cfbd51a36228f000e6df200fa4bc536aab773c3361650dbbb65ee31ea097c770e6041c324bf8026804f09d910f0b1e3e4f20c9dd4d45fe582e260b5c12071698a626b54f165551fba62204109c0851d44689da10a7bee887620ffd95f01322c983830f46ae8005363b29adaac53968234204be5380f6f240fdcdbbd11566607bf301ffe6cf2b2790735826f21b67dc0fb5a1055f9ccf11231d8370466b87083ae68725cc26868b9b90648ccd23b41a46749aa75faec6ab72062c67bdbb0febf6470f69852db38f4a6403459b10ab90e3769dc988b062fe62e7107aefe1046e09c9d608984b87a65dcf0691ac19f43f3702e093909e6d981088427ac52141bd896e4f215ee9611ac19feeb77a465275dff1afff952790bd3eced9aa01e9a362ecc6b7c2d500e57791cce1ff09a2616c4f90d54cd0f99b50b1935d8334e88c3783162830e9f33c63bae25adc7ca40b05e5ff850847abd5c5d0a4abb3a02156083a613bd11c8067f9b51
#TRUST-RSA-SHA256 46e8714099e649fe965dbe647d698a08c34abcbd0dbfcc2608e49420739a56603314efb83a81e44b419f28309facdc2309d27406516d5cb616440159eaef06dd1be243a3ee8b8ecfeb67ce7573e95f44293a13dc7ba5dbc94e98cfcc8f002f6aec1201efdb973a466b4b13bbbaa298e7cb1768ccec2a98b0306328aa4ec32504c83dbd275c70ddb1ed9b9b585d1dd52b0781d6ef2584b187bbd284ed4f3e5fb8f1c1c74136e92156f2ca59a605fac1b0f034fc128c2bb173ffe1b8da6e9ba653ebcd8ac5dfde7fe5f428f7731cd4232f5c92322ac7aff491a5d9482f55e84d7b07b142c97f68b587c68332e992f81789e9e1a5c0fc3cedb87734d401b3864210de03d2997f4355443585cf8173b9d877aa3bfa69409516e11c1782cb4faeee83cf0035114a1d9ef618c26d6118b79a692b2ce66fc778177f87b4b8b6795b9a8f5688a8e60144d7e77126e4b25505897e3c17b5371dd3ac125ee80733e4cc28a8e77c431307cc2d6fccbaf32cc5adbfcfd9ccd6d09a904f0b3092266be473b29b95cdadf5f0dd8d648c776500d1783b85411b6e5fccbc54d85af3c2f5f354b99e1a4a2604efe247365c9edc31d4b243957bb474b8e7cb6d61576497f70169b1465c2fe2d42a2e246a9c4317ae11f89c9a00cfec71d3bb6f23da7ccb7a7ca2717a6bec02e5b851482ca553fb3ab1c74a82eac4729cde94cfcbc02fe2cebe8bf325
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50057);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2008-1091", "CVE-2008-1434");
  script_bugtraq_id(29104, 29105);
  script_xref(name:"MSFT", value:"MS08-026");
  script_xref(name:"MSKB", value:"952331");
  script_xref(name:"MSKB", value:"952332");
  script_xref(name:"MSKB", value:"951207");

  script_name(english:"MS08-026: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (951207) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Word file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-026");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-1434");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
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

  fixed_version = '12.1.0';
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

  fixed_version = '11.4.2';
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
