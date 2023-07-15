#TRUSTED 35e74a8d3e08569ad6c25a0ecade2af3306302bc0abe4a8785e4dde41473db86aace2f1fcdf4ce104e89159c3907b937b623d3b6c8d3c1824093b1819ac664717139800dcb69931bb24b5349f044c8a66a410653b6d2cbdd06b426ca88c0033bf3f2d3205eb4780433f9178257a8713d3197c499a2cbaf3e00875fe7b9e541c7e7ed05dcdae65a90e3d122ccee22a5a46a3bab3e7136e5024902264aa1bba47a65ff4aa3f61c5c5130d80b4f78bae5665d8141cad99c2ccd202f002fe0894d8bcbd8491e911d584c77e0afb787e8dd041caeccc2a19a1dc62de9b44648e6bf8425a7faef6d7b61cd448c46010186a2697ca4186e31dfb555abe3e0686e417e1fcab5e52b5ba0c6a84dc69fcfa61084345d9e0cce76e9c3b3a1a79ee80e27033071f5455f53da7e31665873e69207cbbec648b03a082bbdbfdde083526d70ddb81b230165542a0bb35c54f1b65d5e9b8cb6a768dff798930736c309e91a0ae222d7ade1528ca447226f9f5328cd51e57201d55536b6c6da3f26b53fdf01bfdfaeedfb1cab9bcec807867937b4a7c05e6b19f0861a037ae717f4b9c87b71742b6e91b781687072f25fb9e9b9ec85a5f8fd9c6fa4ffdcada50bcbed92a5131111750423c44ab075f36181b2c754dc2ad8bb27b311aa60c0214016c5bae41ae9f5d0a9c899eec883175bf8460cfb1e8225f82f66a3896b4d73e97e88d62f21bd5101
#TRUST-RSA-SHA256 49c94dccbd1cc3277d7cba53fc82b315d1122a1f34c6f71b43598d732e4069b0d75c0c5370123bc6daa0dc5fab30df3d5a017b129889226624da592081b6e6a5bd1f72371e99a382163ac73041c61345a772a7d93b233789099c949c6c4c0b3e3d2391f3f4ed93ed5ec8fb4257cc31ba386475aa77e4114d22c0af74c410dc8c674a24dc02a0c6ebdb1afd479949de1ac4e719fe35d641d2de90eef4e289025591749d2db4444e7348aa2156f4356b882020dcbbc7a9ffdfd061d9bb4a93d81418b0e1c9effaf36f4e87a094230f7d53614aa6fd651531ec6f47d52e9cb15cca91964f0725c9c72c3ab94fa17dbeaefc8546cec81459816b4ef1edbdd9fd2cd9a819f698e19e452c15b8a2ef292f941b49d068eae8f9ff7efff52ade125fc2617ccc5139bbd303f76910dcabe0d22b4122eff5b0df96a602c52da5e0d6f7a43845bb4dbc331f06c10be02c4ace13cc6f1f075e0a27a3c990281d020f63119db7e17cd0a25ea2570721ed82ab8f52f1798a630d0f13631842d12fbaf4a81d958cf37fadb3133a1f46d05c17244b4470f6db763b029613a9bb1eebf6336e28044b9b364802c589dfd2301771ff487de831e77ce0ab7cc0f84f588ae1b88e93fa94ef90270de850f82d037e4bc019344b10e56baefde821d2159682eec31b3a1f36a5a2a0a65215de06d755788eb0e33fa91a554b569046b2da97e04be2f1d219e0
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50059);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2008-3471", "CVE-2008-4019");
  script_bugtraq_id(31705, 31706);
  script_xref(name:"MSFT", value:"MS08-057");
  script_xref(name:"MSKB", value:"956416");
  script_xref(name:"MSKB", value:"958267");
  script_xref(name:"MSKB", value:"958304");
  script_xref(name:"MSKB", value:"958312");

  script_name(english:"MS08-057: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (956416) (Mac OS X)");
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
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-057");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4019");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
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

  fixed_version = '12.1.3';
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

  fixed_version = '11.5.2';
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

  fixed_version = '1.0.1';
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
