#TRUSTED affe7f9c132412d2bfe3764f063c4050cbd81468e6fceaf3dab1449359ef7482ce6fa7810c0501f1516bebda2273a11b1525e224cc0648588f3a495fc95227754bec8b3450985fd557dbf676bbe0c79654913f563d58dbe98e3dc15492d50267d0ef24a4ecf6c706ce09bb96232a2cc8174fee116d5cb9a925d74fdc964f168a3c0ca77fb99378be0d8b8d05bf970080ebf32f2556595c61c0b45d6e14a463ffbc4ab13c3aabf5bcc746de0521c6666d468ae51850ffdd87a3e7a7752c8dad4f1e975faf8cf39820aaf920d5fd82955084231c014c2b2c74487451260efc2cddd0127611c0e64e8ec7ff889837b7cb52e6cae049d33ab5b4e4f0d4ae4f670493a0b4f1313366b5fcb44814a2c0ecaf72bb6198ae1ad92a03d0a78ba24ed71041ca88e201d28c36530d8b160c173c9bd0c79b3894048a57441aa6f327b8f6aca30ff36d03dc13b9c7629bde09886d81f1633a641e9be4da0ffd4e32888be726a1b5483d00e3d3f750402dfc1425e8315e5c74d77ebacd430ddc92ac7dede371e00194eb72e9aa8b3616bc6c9dbc796fdfd5f0a38be519621cf0451f030bc9c3a2d2cdcb805486a0798b8d376403990f612ce971cd5520718a7fc3985b4835851bdaa84274d242c34875b9344ab9284b46fd4f57256045f9fe2032d59901072e471b999e0dd4ac27cd0ab6dcfed9237c0aa182c7b4945f9d26da988aa50ca8e3b6
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56178);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2011-1987", "CVE-2011-1988", "CVE-2011-1989");
  script_bugtraq_id(49477, 49478, 49518);
  script_xref(name:"MSFT", value:"MS11-072");
  script_xref(name:"MSKB", value:"2587505");
  script_xref(name:"MSKB", value:"2598781");
  script_xref(name:"MSKB", value:"2598782");
  script_xref(name:"MSKB", value:"2598783");
  script_xref(name:"MSKB", value:"2598785");

  script_name(english:"MS11-072: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2587505) (Mac OS X)");
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
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-072");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, Office for Mac 2011, and Open XML File Format
Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

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

  fixed_version = '14.1.3';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
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

  fixed_version = '12.3.1';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '11.6.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Open XML File Format Converter for Mac';
plist = "/Applications/Open XML Converter.app/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);

  installs[prod] = version;

  fixed_version = '1.2.1';
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
