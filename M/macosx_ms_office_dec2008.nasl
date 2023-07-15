#TRUSTED 243afaeeda6acec414498edb35fd4d5862f4f946479b162cdf3f5437f1eb9407adc55c6d20a96ad3d3f4c8fbe25bf0c7d8127b25ae6cded2b691b7458627642effefa31bd2dada81a77a93ee65ca6ed17046d986c54ec58e3de581a6921b0bdaf19e3cfcbdb0808cb56974d9c7030f3cb79f72a9ee231988ece22554305fdfc2638bfd9e16086b313ed0d2d39bdff7900b10ec4e9621779d7639d84f4d68fdc90abdea1f96fdcd5d363e58614d4520bb2e3f0f02dff957eec6c49d9cd42a10b30da37ca6a0dba00fefb15857d1bed3a645959bb6d7d512ff1c2f157182109fdf9ed0b8ad7fe9865df1ff79b731649a657a0b1047526c0eecf996feb1d3654e7a72b1c0a32f83065f04386d4a39759b6eaf1596293118fd0782b776ab63187b3c7ce2f17e0d4c9348414c0f11f0cde41025805047db939a7b7d9f1119ba2b7572660200b0b143ac75be62e4e4ed1ce83bb23e86c21c9bd761fd6c0b3f52a0d3935b8cdef1c14665bc02bfcf369ab2f5df70e41dc36c3110b3e142e17d0693aec73d4c58e313c0f57e7eaf20b16d77f5095293ecf9f91568b0069b399e8f25b5cadb3f38c641a97c411e4659fdaff4ac957a6fc30b7cd9b0cf0e3625858aceba9b2860d8bd4267d2b132cd3946b871ce07b010d8ad8e7be839fcb2b4ca659215baaceafd3e474f0c6b0657f54270d6e545239fa4b0e078feda8d29e0e7a8a6c149
#TRUST-RSA-SHA256 1012a5b3928141d6346786961b2a39441a02498a23f4efbc4a5c0d954a28ab2a36e9dbd89a7d0492abdde2c34a6845361bd2b2bc96c81aacb28b7880ab2d42cd958e92fc4170c494ec9dde8f5ad53774be4d78e0cb1b435e83de7f798392867cb8a2fdf610a96c66e0382536ee4dbc93144774401a8fad708754daae8b5400f5aecc9688cb1eda1f9ec8e762084f4db4677590f7c83594f074f03c8479a1929d389a9f709efcffb13160c7236ce99c2a0434b31d5748ed2b634101bc8dacb98a3d50c5403149705ea3ff641b08ec54ef0236b29bc0cf862305be2586d22377744cde132d63ee08228782f613b2eb7f82bbe7dd00f5e096f4735334d584df5ce8c19cc84b6ee4a7b118b7a876e624f716544d6772b0c6a72bf55dcf6b8f9d4b9035493fb02b3e728fb2a9bd08e4f707a4c3c746c094bac1e640573b6fba8ab4af2063392b758349cad6cc9ad11846b93600cafee7c6d89094bc068734a001ad3f16e7d8281c82251b0adf04593eb52cd3a6988d52b56a67ebbcd938700a50863ff22e28ce616d0227d1918777eb673bcdf8cde700f407e4deb135b8e03fed6f102cc24b4761a9be1d5dcbfb6d52d54c610099b77872a866707095461e69eecb7c370e6df5ab1575cecb389f599773b4227ad0eee16641cc7f16307e65e0fbcefe6443d21561554d8ec93731e4f6779948e5531cb0cd27298aebe86c6da8ca363c
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50060);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2008-4024",
    "CVE-2008-4025",
    "CVE-2008-4026",
    "CVE-2008-4027",
    "CVE-2008-4028",
    "CVE-2008-4031",
    "CVE-2008-4264",
    "CVE-2008-4266"
  );
  script_bugtraq_id(
    32579,
    32580,
    32581,
    32583,
    32585,
    32594,
    32621,
    32622
  );
  script_xref(name:"MSFT", value:"MS08-072");
  script_xref(name:"MSFT", value:"MS08-074");
  script_xref(name:"MSKB", value:"959070");
  script_xref(name:"MSKB", value:"957173");
  script_xref(name:"MSKB", value:"960401");
  script_xref(name:"MSKB", value:"960402");
  script_xref(name:"MSKB", value:"960403");

  script_name(english:"MS08-072 / MS08-074: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (957173 / 959070) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or Word file, these issues could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-072");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-074");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4266");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
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

  fixed_version = '12.1.5';
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

  fixed_version = '11.5.3';
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

  fixed_version = '1.0.2';
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
