#TRUSTED 488c4810813a3c1ae5df0f573b89cb3d5a466467f84293d5c2f38b22b1db353b8886debdd53b6d8129fc0f45e94c65a7f7a431faa26b8403f7c1e5e61f1ea51b456d2e8715f17d9a4ab84318ad7b7a33e5a20d79c83d15ea57b50470589c2e6a401eeef6c02253288fabb47fcaacbb13706856f4951e9acb745ce81403a2365c2c439a5dd448a5ea9110ea3a771a93202b57e93d8dbf78e9672deb9156078acfe9fbac3986494435d72dfb605e5ca5af1eca619b7d0e5112c4eadbb385fb6c16bf6e522e23a92f5ecb5ee6adc59adc66a1e1fecd997862a2204d83cd53a411b831ea33ad136b53ebc594113b611b9b96fa21597d1aa64922b0bef0395bbf9905d928521df3245915ce6e09d05fdae0c6838b940435d3c206e1a293998b86641fa38394f89b7cfccb84fbec082d7365ca5dc47caf3cd6b45921c6302145743b26b125aebf297678e82c7a60564335c16965a14f2929aaa427e91ea4d85066ddea92d95eb2c32eeba4f41dd2f89494a4afc5e8735f3f9fb577a86c78683538bfc9b52e8a674146cefe57bd47f5acdde55d535032cc3fe20f5eeb229b55325bda78d95b1a405eea41fbdac832875056db993ce877466e6694e10e254872341c93965281f3c10a6e137c491b00017af2303ebbae24b60d376fb1377c55ffe9c0e32954a8c88789381f0f7755aff73e829d0cf395be6f984e75db8494b60027666456
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55135);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2011-1269",
    "CVE-2011-1270",
    "CVE-2011-1272",
    "CVE-2011-1273",
    "CVE-2011-1274",
    "CVE-2011-1275",
    "CVE-2011-1276",
    "CVE-2011-1277",
    "CVE-2011-1278",
    "CVE-2011-1279"
  );
  script_bugtraq_id(
    47699,
    47700,
    48157,
    48158,
    48159,
    48160,
    48161,
    48162,
    48163,
    48164
  );
  script_xref(name:"MSFT", value:"MS11-036");
  script_xref(name:"IAVA", value:"2011-A-0086-S");
  script_xref(name:"MSFT", value:"MS11-045");
  script_xref(name:"MSKB", value:"2537146");
  script_xref(name:"MSKB", value:"2545814");
  script_xref(name:"MSKB", value:"2555784");
  script_xref(name:"MSKB", value:"2555785");
  script_xref(name:"MSKB", value:"2555786");
  script_xref(name:"MSKB", value:"2555787");

  script_name(english:"MS11-036 / MS11-045: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2545814 / 2537146) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office that is
affected by multiple vulnerabilities that could lead to arbitrary code
execution.

If a remote attacker can trick a user into opening a malicious
PowerPoint or Excel file using the affected install, these
vulnerabilities could be leveraged to execute arbitrary code subject
to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-036");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-045");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011,
Office 2008 for Mac, Office 2004 for Mac, and Open XML File Format
Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

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

packages = get_kb_item_or_exit("Host/MacOSX/packages");

uname = get_kb_item_or_exit("Host/uname");
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
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.1.2';
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

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.3.0';
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
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.6.4';
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
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '1.2.0';
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
