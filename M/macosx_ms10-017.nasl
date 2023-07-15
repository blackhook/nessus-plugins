#TRUSTED 776cc5218729d314a2efc591c9586131a3d15f9dbfa44b39cb133488a9fc432500420ab2847346bacdbe15e512382949aceb14fd31fe2780e402aa83da77d054ed0a9094c9c595ece148704a209385ea93abacdf0cbb839715b2d9abe3ac3634c01be3fd18cd7e705b3c0e84844229c395fd37bf87a0f72d59ac7a8599cb0386a77fb0a6ff42183884af8b01a64a552665ad9b7577756244e82b1a7f2f01b13e8e4e144759ef0f57c77d2d0fd1175f63a05cd1e1b367f742ea3b5efab2b64431260f3e585c9cba829f0fda6e83d602f1cfc0b1ce60ca1c3c488fbbc38261024239bf64eec7e3afd88e578476c054ce7218e856272068afb0928e5ebdd9338e8d586170bd96a4440228063bf971365a723e1b2f32b572152195c58fade942cce05bda6a45b709032c9d93babe6e5c4413c6aa43fb1d3f073a76f922704066b41ee3353c1192174efd5aad5ec0cf06e8e41c039d5827443bcb8118a1e8ea693a46327c03a6b86e72c93a8d415fe1a622ab9086529a30d8cdd6b80f32325e47a2735ba19550bafedba6bcc41812842edf4d1e2cfa6b43306dfd387a7537576a45a80e51e135a169501bbec9c9f9667de09b9a3d3327936557be2ac78e059b2719db819525a57b445b8172abe25b3fbb6bc2828d6be5bd3ed7d7b48b26ad118138ec97e2271c9b48b685546cdca041b14c39bdf9abaac27c0caccaffa1b26f0b23cf
#TRUST-RSA-SHA256 0453eb4dbc312b709d2b5a34ed083dc8cfb360acb37055a28c76b2c8864330586c01c8f2ff47526615c2ff9b3c1d0052f7ae6130b5a58a34a4696bbb2c9d275de0e30108940c02218da946fdc6783cb3c2583a257a3eb28e8b5bf840a0fcee8cf9ba1a2ca4151b230bc7c9d6b51895a6dee4b512a72da0451913299fb13f3291d2f9eaa6be40f6ba5551cf2aa8efeb5faaebb5f40f673dedadbbed4dcb2ee25387f7075f2735fa32606c43bb81d424bfd3efab3756e3ab278e212b8765ba08917670e1cd4f9cc103e3ae114ce3de923dbf10b05e8dabebc741c6af45705778a0d6605afb0ee4f8dcea2f5daef1b0ec21eeb960ea96456c573af6e1cbf579db0d77e2454befd7e53e211776261ff791fe0e048b0ef1c661ea4a04fcb179b8c172715130ef7941f01c4d5f815f868a8724d8f346e383c111db3aa297069060f45426791051d927db1e7d297c6c75611772e2b5905dbec0fe9fc5c994b823313cce677276f5577bc51992294652809de2c6e17bb26a78d7d8bdbe8b02f31bba59dfd927c94970e7cc3655a8ff832de24b0033fd289542de335d05e10234de525ab18e2e7670f3fcf116a6bcf9e2151fed2fa9540f78d2e7b0c462ea2f8407ebcec1f3cfba3bbeaf9b5876a509d6887bbaf7fa4bc471d82a94db44ce666812ad9583c450a8331b5c1c39904eb5fe2edb4934a4863feee8c22cd888c08c4ecced10fc
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50065);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2010-0258",
    "CVE-2010-0262",
    "CVE-2010-0263",
    "CVE-2010-0264"
  );
  script_bugtraq_id(38550, 38553, 38554, 38555);
  script_xref(name:"MSFT", value:"MS10-017");
  script_xref(name:"MSKB", value:"980150");
  script_xref(name:"MSKB", value:"980837");
  script_xref(name:"MSKB", value:"980839");
  script_xref(name:"MSKB", value:"980840");

  script_name(english:"MS10-017: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (980150) (Mac OS X)");
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
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0264");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/09");
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

  fixed_version = '12.2.4';
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

  fixed_version = '11.5.8';
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

  fixed_version = '1.1.4';
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
