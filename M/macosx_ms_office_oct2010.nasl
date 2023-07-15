#TRUSTED 7b7e53ec23bfc12f9dc5a436c9a48aa10c0e2f852d7c50a1fe97ec0334ff2db6b58652a288604683120353b6bd742643c0d1e5f90c55fea5c43d985b252169b6e6a074ccb9a00931fb0f6a95982c5f5b3ee500333c223eeb72c73795be417cb24fed72edd26dc663b695851dc25121f3179e4176ee15c982c2f8ccd0a53312fbd6c22385b30d58302103adf56bf82774d80461d7adc99fe7bd798e989cb89f3ee90f2b2fdfb19310b21ae0d1266ca7c3af75affdea1a6d42cd3da67f2b99abac1949ae406a2216d23fe9e2a0a5284dbcd0a2046cba4cbce2a4de4e5c0dc1c28d12eda6b03047c31f2b56d7054d98bc07a5113a4ed3a04097b2cd69de5f7fb2c3fd98d13613862006ef5b0e14d08be6bdabd91e85fb452b760bc8240017b1183d12f78b9b51c7053bc3960a5597354255f8abf2bb2c6f674c60d0d795fa18b5a9f1a8aca1ffea8c5c4ad3a95546dcf02efc4c9be7c29cd1828dad86bec0ca103d4f62f638acf499faceb29ef20865b20f17b7882bf3ceef054b319a0c2631ca0d663b55a7f9ef4edf321e5b7f5f8314011fb23a1c5c5710c98ba40477c75f2bf9146f350797f984e178169422a3ba587398d025342e7a32ce9664e3b12817ae23807135ee393e4dff8e31476a7648f0ba4a0a5c9cba69c7ab18433d117b82da619f04294b09967fbef33a339144ab13382a8f987ef2757d3eba7f0eee63de72d4
#TRUST-RSA-SHA256 6c48963e83e50108b5508437c54d3833e872048c5dc6becce51f5476b93820822b11ce7edca32149c334f3b8c5b309f23d771fc2f10a77c81092d34a9149964d68c7f3cb299ae66c63c49910e954bea8f6cd201cdd2c94f4466b09b0f231aa748ad430c22e4370c4ccb04e22a3f07a986aa4077cb32f4f573c64426e64fad287d3dd4acd245e60e505822d2105118776b0c64d2aefd9fb847baec010f4733d2f392e1c5ac3a87c8cc63ed0c46f65ee4b0e962f2b02ecd142121f153771374d1efc40b617bb349d9c70a362981481cf557f4fe6adb9f4fee9657507f7591096f9d0542378668bdd64c8db4491121734bd2d8f7155e140a053136b8aadb7d48bb4e42f7f6c51bef00586505f24a481dfa9c74fe8784dd9ac17200c4e89e20c18681894ebaa09bb641c0dff35f8abf9568d2ce86f1d815f0efd7e162992e73196f6e480c752184c2762183c9f232c8d7a5743356b13ec492cfe1977009b6ddf56a753f46358067efda907f05385b250f9494ea5405b295776375c5aaa457763ec6f221919bac916432b2c1672fe300a633bc9f0754b5c39629fc2104f459dcffb717e2bc57b1ca54d1da3ce537da43fd4efa59504de2b8ae52024d70e7d9ad18f0a0b898b16c750863ad937001ac5f2d3e840caa771704ca5789413ca2e8a1081fa357f85dc6c51bd2b12ac1fdb9868d7f41492ad48f9f223acc5f7e0b41b3673f4
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50068);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2010-3214",
    "CVE-2010-3215",
    "CVE-2010-3216",
    "CVE-2010-3231",
    "CVE-2010-3232",
    "CVE-2010-3236",
    "CVE-2010-3237",
    "CVE-2010-3238",
    "CVE-2010-3241",
    "CVE-2010-3242"
  );
  script_bugtraq_id(
    43646,
    43647,
    43651,
    43652,
    43653,
    43656,
    43657,
    43769,
    43767,
    43760
  );
  script_xref(name:"MSFT", value:"MS10-079");
  script_xref(name:"IAVA", value:"2010-A-0145-S");
  script_xref(name:"MSFT", value:"MS10-080");
  script_xref(name:"MSKB", value:"2293194");
  script_xref(name:"MSKB", value:"2293211");
  script_xref(name:"MSKB", value:"2422343");
  script_xref(name:"MSKB", value:"2422352");
  script_xref(name:"MSKB", value:"2422398");

  script_name(english:"MS10-079 / MS10-080 : Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2293194 / 2293211) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by multiple remote code execution vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Word, Excel, or Lotus 1-2-3 file, these issues could
be leveraged to execute arbitrary code subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-079");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-080");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3242");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  fixed_version = '12.2.7';
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

  fixed_version = '11.6.1';
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

  fixed_version = '1.1.7';
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
