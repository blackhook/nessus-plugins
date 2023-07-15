#TRUSTED 33b9af44a7b325ef98597ed85a70f6b710289e9d609e99f6bb00dff0e38ef942ed1f8cf649826a7dbd508817603368d9e5d9129b43d4f59546d52732e447c92d7fdd4283ee34c0b894c02bcd30f6abbc6d42bfb06b16e886a3572627d4de9efccd257390787f83f71c1a79a1e50533a706890546ef902235665e5f7a4c4c05460c0ed11703adde7a49d160a163c3177d7ea3085fb701b28722ce3528feac0b63ed6bf47b5bc9afc99427e72e52e797417f10c898df1af7548ef986c57586d0366b059f374405e17acfe181d27296cba93c829063794d91ef7346b9382c53bab5376a253e2e335c7d9c12b6caaad4f6309130ac25c5015d74bd3c6894cdd6d022a613d9f133f8c28c828d01e6d15b3a319cd36b1da06ae08fd9ccd63a86cd9c2875921b63253c7b4a10782e9702f452525bec9fc6ea09dd9fcf1b05ffcf0319d90eba57ca644f1e1363188658c5323918d97cbe2e5be811a9d1b372a0818b7439197a3f1758a647c9b4cac4b21ba4b20c71a41c3f762c4ea2a12ff4aaae3e64cc6c52e9be6e0d4198f271a431db9854a027701126bb950af936078dffaa590418f4ce06dd0b34a395b8164a8e98987b35c4e6156f544ca34687112f522b1b7e686c51cc6976ab01500ba06486cedacd45870c765c4df88895330d384f212cfceda8f8732458e7aea425c717619e1af9e4b58f2fe16d2f44e3e789f8a64d9ce6be
#TRUST-RSA-SHA256 b0a460d16171f71d894d060d76c9608d3bf0e28eddc180e15ee3c9929dc15ab97ea25dfdb1dece8ac65f810e59a8e3cf301fb5a2bafcd2fe7b7bdc1497452207ae097f0c1948143fd8779e8adabb034254ec980c7cea7a1d89e6cb805c65c6026864da09a4457ba74be619ff262dbd12c75bdc361ed9e2da5eb72154b57ecd762b2262892d4bc8e4067d8597e582d2c2f21313845cd31518881fc1e7f13105e91616bc96d5bd6ce78df774e5f2eae46cae92cd5fab2301e4b19177d02249cce4396c81a774c9e295fc40c437532008c33c16a78eac4259548bda80b63ce3c4ef3c6a3dac45ab59e7073b1ab93dd7a27af005209ff9e835e0df25ddcc837a6b349e984759176ab6612306ea5997fc3732cd6a680e919bd22ff9723fd0ed693b800d556426b4727dbd456f537bc6d633252769c7b2a44bbb28d36d0d0a7fc243bdcf20f4c74a9b09392485837d0bc3a96f3e74c3524c8d97ab4ccb86513bfa152fa3522144b0141a932bc6941fd627cc4e92a33883c5c711b57a7b31852e49b3b23ceaf7aa568b2b98f5eec89718c5e6704380f1c5d2368648a536d6b1a7c5307d2f170989624a47f326930de1bdb011a23262d1799499c6df1d74d43b345f3060d7fdb76e4bc3726d76b732353a8ce874106e09e3e220f73cb41be0a715a3a19ad6a278407f574ae68d871848679f807cfd7725ecaa4e7eb2a4fe8d2b8c0c9ecb
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50055);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2007-0065", "CVE-2008-0103");
  script_bugtraq_id(27661, 27738);
  script_xref(name:"MSFT", value:"MS08-008");
  script_xref(name:"IAVA", value:"2008-A-0006-S");
  script_xref(name:"MSFT", value:"MS08-013");
  script_xref(name:"MSKB", value:"947108");
  script_xref(name:"MSKB", value:"947890");
  script_xref(name:"MSKB", value:"948056");

  script_name(english:"MS08-008 / MS08-013: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (947890 / 947108) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by multiple vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file or viewing a specially crafted web page,
these issues could be leverage to execute arbitrary code subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-008");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-013");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0065");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

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
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

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

  fixed_version = '11.4.0';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office 2004 for Mac is not installed.");
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
