#TRUSTED a17f3fe9de819c3bcd8e36ca74d8dd23576b863bb3434372f9a9a837f0af152cd1cccff97600b0c2e6f46828a65306e9da274f6861590fd3d5b7567f725633951c97c2a8b926729882ef194d44e54e4b93337696fb013300f9f442a466b785e1a1117a852829e54ec48333ce3980275bc3ab8a563fbfb239368ef9ef635f6c0d5ded72b939aafd65497ce3fcfb3188915fea6659b4488114b238054c3ca8501d33345f9554d019434f3c9fb02ffd42b3a6c6fd344aadb911eb55adb27b5cc1f5e5d360ce763ac51d64ddd83497b31f8ba44d1654bb96d2739f2ca0c5dc9fe0cd4df973d4a1b55ba7151fe7223a28a29157ad69b8b47ac5ed59a415394cb53c2dabb2932ab3ea6bb1ff90d441801cd79f60459c8966891b0eec88033f21248eeb5a4b23897932a944350c51906d13d7ff1ec45fdb52c881c306021f487d0f8bd6bd1eb648ffba5a9205e95d9eff63f969e8cff4c3f72502b422af529689c2e98a8a0d069e2d2de5aaceb89d2f88719ce3b2f3f19ed57222ac164cc3b99bf577eb79f507bc339e6267a41c0b11c883bdc758b3f7d6eef899a9cb0ddde893de67ae381e584a65d63673ed4e550ab018e559ff8ccffaef082a962b54f5c57006c4dea16226e5f113b4c886431928a2d466f68fa5d91ecc99ae4f187c7e21c2b389d8e9923031f576bcaa1ca6410c75297ebc6a0ec6d365419b32193d63d7b241d853
#TRUST-RSA-SHA256 6776ce4fda73f6bbec301e999886674ed5238c07b22eef7492edfa8f43eb10cd24d7e010238fc63fc387294b7a962af21b19f26dcdc616cc89f35573bf362d2511b4c640b549d26b54358d83d2ffc9666f1ec459a4cd6422822cfd103c6cd19b3b7ff5668f56f87a5dae9da18e231804c31f43fff4cd9cc74696acf349053ea9b8d498674d88ea90ec8019db627bbbbae33ca6ce51a6f66fac927e15ec0ac344dcaedf5b9457e129c4f897406ce914b4da86c517be9e08121f28689a6b568c66b83eafb50bd9b236b08b48386730a27905db52fbd80ddea9fbe9a7cbeefeb32ba5ec7b0852d22593417d72aa71ba176b76f0421f53293e03e23d3cb020af50d14104f3bfae0b68a5de3c6254631184464fa6e8cfd4182e9283217b7516dec538cfd0caf0bc7871f66b0503bd89fc9b8115125c7c6e41c41b324e82e8e37d3e061befbe64a9b700c204b0bf60e20f7bc36ea2862f4d3b0a83cdec2d151f85a8fc2e8029cc1bda04a1ef11eb7aef63b75aeac38ae07b1317e3ad4873999e155dfb17b1402a9976557f6cc7f6f642a7e9c5dedf1a212fcfcbb6b6b5e550f0895844cbc77a66050738ec374478b150d9a9f9a841ac2af3e2690f15364278dc31bdcecbdf15b830e9e5c92fe0e3b44c7397c2b008f08e5022697c4acb400fc1e6f9c73dfac3cce4ed2f4f061b743162e543faeec3509ed6610e626785e1419f4f4aee
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50056);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2008-0081",
    "CVE-2008-0111",
    "CVE-2008-0112",
    "CVE-2008-0114",
    "CVE-2008-0115",
    "CVE-2008-0116",
    "CVE-2008-0117",
    "CVE-2008-0118"
  );
  script_bugtraq_id(27305, 28094, 28095, 28146, 28166, 28167, 28168, 28170);
  script_xref(name:"MSFT", value:"MS08-014");
  script_xref(name:"MSFT", value:"MS08-016");
  script_xref(name:"MSKB", value:"949029");
  script_xref(name:"MSKB", value:"949030");
  script_xref(name:"MSKB", value:"949357");

  script_name(english:"MS08-014 / MS08-016: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (949029 / 949030) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or Office file, these issues could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-014");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-016");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0118");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

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
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

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

  fixed_version = '12.0.1';
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

  fixed_version = '11.4.1';
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
