#TRUSTED 8c1494933e77e80ef3a7f6bd65df671a17d56304af398ebbb94ad8d989e68befca12535c3a5058522728995d014ed126fdfc8390336b760f3a822a217b7afe0591846b71ea4ec044a63e9a7d50a95ac675f14a2935a5b94c928bd03511ef1f0228178df1f4cf90f3fe4044723f45e2b4bdecc3d7a2bfa7c8c79ce38e68da8beb32089f4750e8a4db33827f5b4addd5291ba4d4be72430242f3cda07f6ebfd8ce16102014f9bdfe430082dec894596661569620950a68b08c57a2803ccd9816838796cf13e7486f04951dddfbdf69e9623dfaf9ac1740eac36cec71cfed4a00471bc883eeb353c30111b5263dd882e9cc29a7580f048741960c053c134d6391f8caa832cb818149dec511c8873e725f0b0a5a04b7ebfd4b004cd87aad420a5046c1f34d3103e7689d11f7d09893e6b22c75fa5a8a333f3776502b8a8141e2bfa0bea47cb37097e360871c42d1ebb7891d3c51a0841451c76cc1fae1970a23249d48493691ef0969c6aa4faee5296b841b268b8fd59a180e3102a4c1f604cb59a79a81862a42700e8b5e38fb8acdca4caaaf87ad95fb1632bfbc80299a4491aa420c3551ab63a05e0a4fc52acac0b720d64c0c36ec47a8501d60231df5e512a1b5fc25a79bf330613d9c79c453b46552fda231d3155bfe7760372df7c538e233f83ade989a5b15e2b535c3917f2e6b4870018d2e556842a9ced57454ce9872fa9b
#TRUST-RSA-SHA256 76c3a89d1e2c4523fd85a9f0cc8fe55b0c508e089b6815b422b99eca2eaec6cf79846d87801c831fb1e2bd9116e91ad89829b08f710352c312d74c27124e1d82c630846d6d6d77f8a81102e7e574994c2482fb5daee52caae4e51a960810bfe53b882fbe7f7632a4621c881c11721e167d23a981fe45a1c0decf140618a37eccbf04f1fa858857364559c24d53b5a7006ecac8f0ed87b696025203fcad9c76637868807f7bd66c0905500673c68ee9bd0cdbe0b63053f32115feb0073f96d8806d21811294f6ae4e95c31ad4af2dcae7daaede4fbfa7b5d9729ed8909585c61c962625d598a21d54f2d3240d50697a5f19185c450afa821dbbec51de71ef8b61e7c52dff33e9acfcc40e788e48c9f39902f929c8a8ae99f6bc621623a9e44fca96059df8cfdb18068c3d2e3adade9da7bdeaf417f9d5f8f4b0e04bdeef3672919ad2fc3be592576a9d8fda740f5bf43e990a0051e40e04ccef5b4a5bbbf68c32c59027468157498b084bb210a9a986a8916b1644aeb2a651c39769f971f2bbc2e919d7f076ab6d2b0a18a604aee038c7b5d1f47904d2ceee6cea07cf962f925e338ed39fcc8eb7a29d4a9d1c3645ce0db4939bc9b8fb6b5e396ca879d903a38e70b695afe2b5220ae079f168d589e23b72bc0137709f01aa422f809ec213733ae60b684857ae88514d78de943a8d917c7c017781eac0f85ea5ca285de27d5617
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50062);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-0224",
    "CVE-2009-0549",
    "CVE-2009-0557",
    "CVE-2009-0558",
    "CVE-2009-0560",
    "CVE-2009-0561",
    "CVE-2009-0563",
    "CVE-2009-0565"
  );
  script_bugtraq_id(
    34879,
    35188,
    35190,
    35215,
    35241,
    35242,
    35244,
    35245
  );
  script_xref(name:"MSFT", value:"MS09-017");
  script_xref(name:"MSFT", value:"MS09-021");
  script_xref(name:"MSFT", value:"MS09-027");
  script_xref(name:"MSKB", value:"967340");
  script_xref(name:"MSKB", value:"969462");
  script_xref(name:"MSKB", value:"969514");
  script_xref(name:"MSKB", value:"969661");
  script_xref(name:"MSKB", value:"971822");
  script_xref(name:"MSKB", value:"971824");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"MS09-017 / MS09-021 / MS09-027: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (967340 / 969462 / 969514) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel, PowerPoint, or Word file, these issues could
be leveraged to execute arbitrary code subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-017");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-021");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-027");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0565");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  fixed_version = '12.1.9';
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

  fixed_version = '11.5.5';
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

  fixed_version = '1.0.3';
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
