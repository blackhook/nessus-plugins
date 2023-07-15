#TRUSTED 81d152b2011b023c541ce248db61df8c3335a091634451048250a2af2ff8e507d05883641d2e83955dc0306da88b24e7003762cdb278a2d871250a7bb3c59f38428b4fb8bce18e9f61acdc3ccf9958ae9eec6202324b6a1c043f38c806b94ba9c9e40bd02b22b2bee31c22695bdd1f8122bfdcb700a2665cdb36cec3c2fe16b91dd2c9162e1211ac6161a2e0c08926eaa0c142ea4124b027a0d79470791db81831deabe894783329d5a0480a825f7938c001b923112c7a48a4a5e715564903db7c451c7be903d698eba8a595f3bd4b551d59378dad20036f10b2fc0f063608bf5012afd843e0b9d4509cf4c91ca81aacd0c62a26ec03efc09591c724e3453d8cd95770f379c86c5b3f6639068f6d8b8b0469bc341f1f52a437bded09b8f82ae388ff606b3eeb06fa51951d61cf76f37db22f9da770ee093b964366c293cf82c69dcd301cce05eb6962408413e2093c0d088d756a00db1d17008e43ab6027ec0e2652aa2da9dd733261754876b0e8ba0b38d80f81521017a9f30de1fa867094952a3951963e39f4ae5c3e135b5639e91cda83c1f19feb5a9e2c0211dff9399e55d7a1f93ceaf482a4d986752b2b8742efd46dbe7d2ed830f447bdc21eadebecff4b630d26b4017fc439025c7d9a34ff55aa87156a5effcd4ee0a92a295587700bcf696436002cb7b90128bc82187cb1628072467065f5f00fd9b3f57305b1a95c
#TRUST-RSA-SHA256 a5ab375bb67f5837e6ffc38fbbcb2c2d9d28f19514d0ca64a62fdf6f0752a3c5cb92697dc8836cce092acf3494ec689e387de20bd344c1ec10e7bdfcdc26147e7453e7efe6db8835bdb07360fe46f75665a9ba69ff954fae55c5e3130555e2ea23322e03969615106844b65ea2273c6b1ce8d78f947fcf7b9f05f11ee038873f422215c769d2ad25df153aa26bdbb2b17e0db12247218b5dc7fbedecc40179577cf42a51d571519af061e59e8b2db9f1967035b684d5c0e5caf480dc9547b18b410a1e3e270c1891fdbb0030efbb4d6a738a78978544dddc587d2218b4a30c56e3022d8e0feb5a713d2d5c6d1629926e75c4481ef5d3d7afad79cdfbce94876755460bd65c24d2fedb4aeac0d8e3e930e9e8e2f6f0dc1a714c13b6ad196bd5523d2f865e13fddb07e04d8499e40582a4f3f0f784ff90bbc1cd4a08bca4c28f96c18b8aed8c30b6105e886a959688daab6241422872dbd67c5b08b8b74f9ca807dba51ec05afaa96c6c83d087dc28871d6f01e3510363d40e34009fc1fc50fd384860c259ff36c36a8677ea069dcf169710fc2bf511e1ed82e9c19ee1513e0bed61ce7cca31d0fbec1c6da72ca0daa7c3054b12d57245eec8e104cae06d76fd8b86b608570af37f3514630381b63762aa241f3847b7fbc2e137d4d2b05d26945edce36af0d0413cae432f75cbfcc6d30462f51a194d825b861667187c7c92a928
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50067);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2010-1900", "CVE-2010-1901", "CVE-2010-1902", "CVE-2010-2562");
  script_bugtraq_id(42132, 42133, 42136, 42199);
  script_xref(name:"MSFT", value:"MS10-056");
  script_xref(name:"MSFT", value:"MS10-057");
  script_xref(name:"MSKB", value:"2269638");
  script_xref(name:"MSKB", value:"2269707");
  script_xref(name:"MSKB", value:"2284162");
  script_xref(name:"MSKB", value:"2284171");
  script_xref(name:"MSKB", value:"2284179");

  script_name(english:"MS10-056 / MS10-057: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2269638 / 2269707) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Word or Excel file, these issues could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-056");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-057");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2562");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
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

  fixed_version = '12.2.6';
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

  fixed_version = '11.6.0';
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

  fixed_version = '1.1.6';
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
