#TRUSTED 55c6c450c30f92598cf9543f40f63263ce27953b8db94a8308fe1e888e7c5fed9fe95388cd62e6e42f52124b92827a6cc8d12157151ce1f1ec7e4934164a19acccd69f61dc76e2b758f6ea260e32ed52e01ddb624ea620b4f28cd730b4e60bd6b35df2e73b7254342b5fd57dacfafcef8006bc0bfaa1eb01b3c807fddc3df5054fd5a8f97419a1437d82c3a5a7b9a4afdb8bd3b8f1a7c3aec51cf1a1fe1a260bb2cc1037afa4bbb640d54a51af360179767add535fe614ab1db586c90fb92d4946d5850d2dd8ea232bbfed26e09450da38446ea27a0fca21a6d273b44317b368ed5ce7c8e04b294986bc41ace0a8a949798d63d3847d18b44a411d7f21bf3c26dc3b138bb9ba3338bac857e7dd6cfe52546a073f68f2a74630e5b5fdc68a08d54300504eeaf112e7b596d6d922f7a1e976855bd59ac7f5683c5a39871bac082e2b7f41ebc55c2c66b1362a945f7fdc9620a23983c56b0075ce8a17e859f9a37b769f2c76fc97f67d74982156edaeab884d5ec1a82ee18f663e69ec9fc501d85abbba1e673ae7c85b7b04bd2bc7f493ef75db15d1ce13b08d7cf8d2f5383026f8a13722c273951823c5a942afe7b0cd22f2ef62b47ef6598002b07be200f88574347d0fd98197454d94eba4227181ecb5f69ca6e04ba0a981a70522ba1c70fe64fc6f0f6982d36d96d0294a2f5a7b337be3b6088bcacedc5d37e5da1740cef47a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59046);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2012-0141",
    "CVE-2012-0142",
    "CVE-2012-0143",
    "CVE-2012-0183",
    "CVE-2012-0184",
    "CVE-2012-1847"
  );
  script_bugtraq_id(53342, 53344, 53373, 53374, 53375, 53379);
  script_xref(name:"MSFT", value:"MS12-029");
  script_xref(name:"MSFT", value:"MS12-030");
  script_xref(name:"MSKB", value:"2665346");
  script_xref(name:"MSKB", value:"2665351");

  script_name(english:"MS12-029 / MS12-030: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2680352 / 2663830) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by the following vulnerabilities :

  - A memory corruption vulnerability could be triggered
    when parsing specially crafted RTF-formatted data.
    (CVE-2012-0183)

  - Several memory corruption vulnerabilities could be
    triggered when reading a specially crafted Excel file.
    (CVE-2012-0141 / CVE-2012-0142 / CVE-2012-0143 /
    CVE-2012-0184)

  - A record parsing mismatch exists when opening a
    specially crafted Excel file. (CVE-2012-1847)

If a remote attacker can trick a user into opening a malicious file
using the affected install, these vulnerabilities could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-157/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/279");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-029");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and Office 2008
for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


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

  fixed_version = '14.2.2';
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

  fixed_version = '12.3.3';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
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
