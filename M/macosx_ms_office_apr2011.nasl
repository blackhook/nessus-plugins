#TRUSTED 79578016d34271457f351deb54dba5a29112447da9e3d952dd791b837bbe7094bcbd0c5ce11af26965a0a6062819183dccbe6aec7fd9f6b063db1e48b73c1d916fd3742df99bb2acd810e861b77155bb7cea4ff6246661588ef6536eef0e578e4a923a0ee959c9c81f13f9e4c8fcea60d7bb806f2d41f408b7a2954cbf5fb503bb707a3e9369b8a11239c78c1e48837bcb6f1604f8be9628609f38e14026512e87ca0d1178ade8a6b6a1fd7a0a7299c4fc126cc55fcef885226f28fa5680e173c56556c97e2ec208c48d12a707b3c6321cafbd54cf0515e887bb28457ad897ed6888629a3e2fcf3fe666d7476b9fe6493acbc7d2be9605a9b1bdf414d9c652f395c96c0a4f1e17910df1636b237b3b639e381c1bd842e69fceb95304b45fff953bdc51467eacd5efdff66dedbb8b3e05a9f2d5b539e7b254e3620620191c91ca0bf5f4df66a6c4a996678a1e0d678ce476cf9019c84a79a6deeb55974457852fc5ee43b18e6f14808ca0b28441029a4d96e7d70a274c25b35e86148a928cebfffb7ca35d8ea9dce4fe001aab299f705a270c001f935d1d4bec1a1587596753a96ec4bea65b75377bf95fa1c10fc850eefeb9a8628db3f54a567a83363116987edc5dd2151e5256baffccd61d43479265a376156c8fa254f7da4af00085d9e6902842187e15a5d54cc29f832cafed17c16bbd4c5494c269a3fa1eb0892fdd441d
#TRUST-RSA-SHA256 a2fcb28154482f0412fb49aa6c64c497a6adc494eb2934108daea6d877bf11d48a792d75e221fd0d97ee99cce3d08036a3beaefc14e601fcd865e6493f3cac90b02bad3a641a4063621cb7085b5aa5c082bd52f7a8292f8def07a00f4d16f8c7b9883a613fa3058ccb855e33f2063e4b66106471bdc4872a33dbe80f3783f2237e30351cf37a617d9901d144ecd87d61154b5a9f4d7ff33e1bd60f0513baeab8081859ae7519fd3adf2318cf4c311b2397b7ae3c2a951a095b0c7051fb9f544cd560ef086cc58b5a9b369f5f4867ea4d2df9debf8b758761fbf7dfed4a4fc03780de9209f82c0f2b0d16bcf5d0a84f0bd68013249dd40c9b1e8b0aafcb1a152652d1a027e61a25d0173e38cf285899c71ec39cb565567daf0966d4b52efd22a2850412a443cf1080e356b25b8768674c29ae4bcc2aeb0e37d89d2f366e983c905ecdcb620278c73cff0bfd02b47e0be3d6c1f7560ad464b8116bce0e58ee55fbb3d20c11069423d848eede9b6f060aebeaa29da32f50de9e6481e2e2185db0401c974612dc042e4f5eb16a86e12d97797e863f04ad9adb10758c8318b27c66768536050ad1fbb38de5fd2039eb95d63caaf7666a26b16495dbbe6fa8dc8cd3dd6ed14905dc55daf4873866b6954f50745d8e5ac430020833a11c154264019773d5ac183801c041fb394de6d83c3101dffa1fc11a5aabc091c272ca7c47506f18
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53374);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2011-0097",
    "CVE-2011-0098",
    "CVE-2011-0101",
    "CVE-2011-0103",
    "CVE-2011-0104",
    "CVE-2011-0105",
    "CVE-2011-0655",
    "CVE-2011-0656",
    "CVE-2011-0976",
    "CVE-2011-0977",
    "CVE-2011-0978",
    "CVE-2011-0979",
    "CVE-2011-0980"
  );
  script_bugtraq_id(
    46225,
    46226,
    46227,
    46228,
    46229,
    47201,
    47243,
    47244,
    47245,
    47251,
    47252
  );
  script_xref(name:"MSFT", value:"MS11-021");
  script_xref(name:"IAVA", value:"2011-A-0045-S");
  script_xref(name:"MSFT", value:"MS11-022");
  script_xref(name:"MSFT", value:"MS11-023");
  script_xref(name:"MSKB", value:"2489279");
  script_xref(name:"MSKB", value:"2489283");
  script_xref(name:"MSKB", value:"2489293");
  script_xref(name:"MSKB", value:"2505924");
  script_xref(name:"MSKB", value:"2505927");
  script_xref(name:"MSKB", value:"2505935");
  script_xref(name:"MSKB", value:"2525412");

  script_name(english:"MS11-021 / MS11-022 / MS11-023: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2489279 / 2489283 / 2489293) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-021");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-022");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-023");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011,
Office 2008 for Mac, Office 2004 for Mac, and Open XML File Format
Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0980");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_set_attribute(attribute:"metasploit_name", value:'MS11-021 Microsoft Office 2007 Excel .xlb Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.1.0';
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
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.2.9';
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

  fixed_version = '11.6.3';
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

prod = 'Open XML File Format Converter for Mac';
plist = "/Applications/Open XML Converter.app/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '1.1.9';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac / Open XML File Format Converter is not installed.");
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
