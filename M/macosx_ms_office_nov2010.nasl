#TRUSTED 805b4a0908f271f3150df8c4ecccd9a45b2e4b24afdb268f2f169fe0cfee1bc62aba5230cb8215c4162fcb39580f4009a24dd839e638f6d30c3559d82aa220968b76ce4391007e5da4531a41c3236061ff626ef1e0cb3f8fd05920ddb05f3d9bf36f485e91ee9011026a34b469f63ee439039ed2cdff0565679296e93ad7d061dce7bf95a816638d483732032fad78c63eba4e8a1e7aeeac3c1a98c544456668d59620753d89326cca19e0d61919282b82c9df7a4368e34a2e709dcd3cc3267988629b02935f20cde47279de4c5be3f93a84dbdc16547467e5ba70ff18964c803a22a9f1ce8f80a78b815327c6c81ec7c5c83e3000a3c68a5192147bd5ab8c174a060b7d240c96b13a0ea4a6c87455085f82b427f25c6033a4bb4068789ed4a2fa606b51105c72166d341ff4115df3b37781ac906d5bf9ecd8e8c1ac43ad031149a4c51cc689da6bde95b8734dd61c27273f335c3179048295ef35f20424f8dd39fe35af3d651962cc79e6797962014cd8bebfb1b5eacff5def5dcd3c768eaf1560e26af78ff2083d08de2fc9223358da1f1b3d535c1734347d9742cef7ffbcfdb1f782ac3763eb0a8dae4739de22799097606f982ae042fa7602326376e88089eee298ab0fa196ac8eb2fbfd4afaf662f60006ef52861e34faf160b7904b44475108655625b174770c378f3b77af5e7492e58daf55d7dad3114f56ea0684696
#TRUST-RSA-SHA256 3647f9fac0777a1333086fe2e2e5359cb6557c1e725f3842bcedb1dea5bffa1a0e8f3fe3c110a049eb82420914348d049d95b2ff3d72526ea78340281a396c4eee31ea3ac0b1b2c5bdfcc9f2d68110352ac9582048bed4f6adf4693075e8daf351eae61fe9e4298cae9764b04ecb1314f0b7f4b68828e3de7ae1c1a3fed6d696ecd49ca868ed679ce95936cbab80740037f8eb59429f50c8fd71b2b6eb8b28c978d65366836a68fb38ffe14707fd8ad395802298cab6914a6fadcc0780d6161c7b92b6cdcf2c1b9a8d8df3b7b0ea2530ba3b46c400fd47b211eabaa66235dc50be7e885e608fcdf72ee5f693a16c9ca3f8356d798e6de048789bae9b92752b6f09e11292b884b2455f679a918961af745442f90e42c3132a526de6cba5141c31b50a8a16e60b14f4c85b13699e016aaa73d04f0d171cf7f54903120a0092e8754b028ff0d5d6f2767a250856b22cdf57329c7123c1c10c60dd24dcd6a76514227bf5e1bffdeb58448921c385dfa788a09f6ab0c5fbb8a4ac2438fa3c483db538f3f92e1c0399365cae1fb40506992cf61d85b7654b48e4d89ffd087e720884d51ab6e64b93f261b485b6ef2113e7ef484aeb4f628639b11b5a7d54d27a4bc38fa8240deecb0aa93879da20906ab47be020ca290594814479bc984d7e91ab7e55ad7f35031f160e8f4fad3cad2d5f8bfd2f71f30fda98cc93b7e0de36067ac4be
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50531);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2010-3333",
    "CVE-2010-3334",
    "CVE-2010-3335",
    "CVE-2010-3336"
  );
  script_bugtraq_id(
    44652,
    44656,
    44659,
    44660
  );
  script_xref(name:"MSFT", value:"MS10-087");
  script_xref(name:"MSKB", value:"2423930");
  script_xref(name:"MSKB", value:"2454823");
  script_xref(name:"MSKB", value:"2476511");
  script_xref(name:"MSKB", value:"2476512");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"MS10-087: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2423930) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-087");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-087 Microsoft Word RTF pFragments Stack Buffer Overflow (File Format)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
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

  fixed_version = '14.0.1';
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

  fixed_version = '12.2.8';
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

  fixed_version = '1.1.8';
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
