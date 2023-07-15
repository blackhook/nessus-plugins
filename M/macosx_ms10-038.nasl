#TRUSTED 8ba5a97bc87ded8acfbe0cb9feeda5b61841cd9fc4e2119a727f657332cc0b65d7f283c440965746f2a0bfc53219b66eecf79587e0e40cffc0c2454af5a54e71caa02783df0e70e4d0d928152c21bb375871d5e14b938e69cc84c2bcbb1578156f2944b1c1030db3f1c44dc8ed18df527a453df6cbcbd9684b5ca3f19c2ce5e3daf4ca7014497a802f4ee7ed18f0228e146067de94c24b489877439960162c5b8e32162b6e8b28d6c0f4663537af8e60d355c41d613769edc91ce8a95ed4b478c353565f9b58322eeb735727a920c87ca5f8335557d350c295a726eea7ca3037b628a2697670e847bb28ba880c7bbae50a45bda89383a2ef53c75669d0e2222b3d8845fd4972df199f4426e680fcd2e81a9cd39229c6f2b4f874df70068c34a8c0eb148e3069ec778dca0c3181b5af8f527deba75c44abba42a86eefc8ed7dd918704bdc76aa2151856b338129e641077b35cf1b0eb24f21b4ef763c7329b99a05647bf496000ef8ef0d0cd9f92d2d446d3c51c0e5683dc9dfe635351a50862dc4d8c264507b67c79eb5830867e6ba5b80766f693e396f0f911c275b1b28324bc35ef4ce77f2a7eca7dcae6b83854d8c843c73f49f9eb520067307279ac5f97c26b7b709eb00680ba65883c2a0b694181d753055e34edba9495d9802ff5020a9a4e6175c0c2a185f64c4e45a39cff2fe1a21ee2f2d9685cb44cbf35a850f3502
#TRUST-RSA-SHA256 1c69a89fe79044a0e9f6b27effc15d1fd5ca89e05e4f4ad39a4837ab6853bdbbd232b2c1c0dd3d67dadb153237676081fe0afd3e7f2e0d45945698943dac64b9b972b019f3ecc26735c91553a5635f23e3a0fa9f78042dd73189d9f83fe9adcd3abf38f9754b5316d125699949551e370c3908ef153a2a978af5cd4eba3dcbbec5bc0549fa630f320a3e7d05e94b06e3b131331f497636de4b70029b3887c9c6a5dbd8df17b4c9dfa08576e84ceeec8dc0b2b551f64a3f90a344ed1d9ff755308a765612ab015bfef35541aaa914e023035695be90e2545f81e9c85cab4db34e40d1a6e512f4f839251e8488cf45bda22102380499e2adcef736d7a7899554c12d13eb96157a91ee593900a24ae6da1b744900d6af854a1c5bb0409b4cf527e95539c6edc6b27eca2b3c987375fa938b7f129aaf58debada69fedeedc35e34b15caf223c69246d0576b333292c2ca8cd23cdd2170a503e74b1f64663ff566e3a4b19acb93b36681d0d40855f575b8a839096726c2a28834704586494fbe39650a56d2dd041c9e2ac3da1f9835b17a6e8dd4a581b4bf79c5a35d4a8176e14784954cb88d2ac4541a9594c5b31f4bda5281c4cd6ac15f13573b76cfc5f7e214d4c7c418e2b499e0dcb65960ff8ad26b830f8642d03eb355120e43be7ad483c93606a33a7e1915c2ff3e917bf10a9b6a9dacf56d5b8c670313936ba4253d4d6f873
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50066);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2010-0821",
    "CVE-2010-0822",
    "CVE-2010-0823",
    "CVE-2010-0824",
    "CVE-2010-1245",
    "CVE-2010-1248",
    "CVE-2010-1249",
    "CVE-2010-1250",
    "CVE-2010-1251",
    "CVE-2010-1252",
    "CVE-2010-1253",
    "CVE-2010-1254"
  );
  script_bugtraq_id(
    40518,
    40520,
    40521,
    40522,
    40523,
    40526,
    40527,
    40528,
    40529,
    40530,
    40531,
    40533
  );
  script_xref(name:"MSFT", value:"MS10-038");
  script_xref(name:"MSKB", value:"2027452");
  script_xref(name:"MSKB", value:"2028864");
  script_xref(name:"MSKB", value:"202886");
  script_xref(name:"MSKB", value:"2078051");

  script_name(english:"MS10-038: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2027452) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-038");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1253");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_set_attribute(attribute:"metasploit_name", value:'MS11-038 Microsoft Office Excel Malformed OBJ Record Handling Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
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

  fixed_version = '12.2.5';
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

  fixed_version = '11.5.9';
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

  fixed_version = '1.1.5';
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
