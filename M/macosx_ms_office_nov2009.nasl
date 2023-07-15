#TRUSTED 867116f23b97c4ab88ac7294c8694a539c26166f6ae30085d2dbf8f4bed6ed23ed100aa802423c811c615d862ad7e8508101d85e101201206c0a82e265de7329d26804877dd3962f73c87a8a0854a6fcd033231608f7ec51820f0ebb64be42434004d5fdf8eee962c4217ad9e3fdc83c9144b788b16f2c8c2d972cac87ceff14ac628835b4a5923c63208b516f20480aa63f47f4108d37339c224a27b2993dedefc43d02bc2a38ffa4edc18d21e991fee85c74c8427ca38107a70d632ae1a08efc551716408124d20fdbf0be87e9eb1c4f7ebdf9c194dfcbfee3631079b20ca75985f2ba390677ba021ec01389a1d17e1517f331762fe5035440ca74ff1e6fe92d187bcd0a771c1a357eef3e3536b02c18be03aeb049234a8a11f40baab14c938360ee83ae25ce1b25b0262673b6fda39e570ffabb920db25c39ff077cebcd65ddcda5276dfd2a97918da8d40d5e1410fe839bb06f9c6a156d3b3bb6b1014c14950b9539d1e376b228e2e939b8c51b76a1e72dcb9ce334c8a97d13548922a995c668a811bc14a4c9ab88b27706623d504540a0bf782154f50d265e5c3496d6818f969b67d9f8bd5005aa9c623986e84a4536db16d5ddd4903b5a2b7a0e36734e23c782bc0c8ec094a8f09055c63d4dadabc9813f5d5616d665c2424622866dc93a5cbf31c1897e499019fb591bc584d0413eafa929ed234de65d95c05e482bf3
#TRUST-RSA-SHA256 6b09c379d6899eeeb09049b0b08564a3f0e50fb5fc5c3ae1293f2406b29fa8b729adb457b4428f469728a492db03e880bc6856a8e00fe35ad9ac1b6327e4479eb01b26a7b15871c54894618f283538af689f201c72e4bdcb020ff49acb74aa15c408467f95a8bbf9a0059344fca323655014259ee6441b3fe808a42a42a4e418045329227fc7cfdbd0e8a0474a4bbc661b6e883d8dcd5257b921f05217386ae5e08067c7e09813be04d65e4a0873f381b7d2832f34c2a214945debfa171245be21090d4fa856623eca5add7fcecd8488ab9ec2b5e14174bc831c4fe0622c43c8c53a0228a50b2fd84ce2e519981b1aa209973662c71e9d8e01f99e799b0d9497b1b626b87f2adc071bf3e0da8f36563cb72ab42c9e0d710dec911d3327808215481587a119d3f30d34f5f9e3b423a495e06d1226045b740169e7d74bad802e3f82432321cf6d088d536f5efd0e99d56f250eabc1bef847bf0a3453fea09d0d6012b0df020158a652669cbf3d63da4fc6d5568c2cbe1f4d5949fca9832efb413d885c98bd17358ab1d7890f999249b7a3ab071ddb690f5082b1368eddf6618b9309cf3bb94079127212337e384508b1426479ddb5c39adbd788d83a2a3cd3b33eb2e1ac21014c6eb120b66409d10814a53d8f22b4abb5ce5fd9780972e87bfb76de421cb25ef34ef0b299cb83dadb253dd801305e112cb24081a9bd09188d6fc5
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50063);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-3127",
    "CVE-2009-3129",
    "CVE-2009-3130",
    "CVE-2009-3131",
    "CVE-2009-3132",
    "CVE-2009-3133",
    "CVE-2009-3134",
    "CVE-2009-3135"
  );
  script_bugtraq_id(
    36908,
    36909,
    36911,
    36912,
    36943,
    36945,
    36946,
    36950
  );
  script_xref(name:"MSFT", value:"MS09-067");
  script_xref(name:"MSFT", value:"MS09-068");
  script_xref(name:"MSKB", value:"972652");
  script_xref(name:"MSKB", value:"976307");
  script_xref(name:"MSKB", value:"976828");
  script_xref(name:"MSKB", value:"976830");
  script_xref(name:"MSKB", value:"976831");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"MS09-067 / MS09-068: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (972652 / 976307) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or Word file, these issues could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-067");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-068");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-067 Microsoft Excel Malformed FEATHEADER Record Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
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

  fixed_version = '12.2.3';
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

  fixed_version = '11.5.6';
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

  fixed_version = '1.1.3';
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
