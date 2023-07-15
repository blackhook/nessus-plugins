#TRUSTED 1abb79a930fad3b9d60df631085a6a72dc83fe9246fd02c2985a2ea5cf22706a221d63015a1146dbbbcff80989a2242e9303c1baf6a98bbe3c4b5bddfc532d6001e6fcd6414117e4732bec85b06af46af7e1ed48fefc3426eee6ee4737e063b75f6787f615e6e3f2cc48018b1d17244c3e4f1e96aa72b235dfce64cda64906e1142552fa4600235a67caa7c675e7bd117b3d6033f715ef3db040a8be91a53ecc99826c44fbe6f2c970a665fa40c31395814bbde220994e5a7301cdb6a8206c393b8bb10c4374b88b85979fdbbeb7020f03ca6dcf00d437361f1f000ef5af4c84714861444ba0726c16af1a92107232df8ddab8aad39356c174d4e0a4b9083d88eed8284343b53a5174fd7cee13bf2bd7b804c50c25f1b3f0e31c6ddb8caddefd0f049385b692aad93507dad5ef8718215d0360511f4bd08a19ab1952e1db348ab64dbcf2347f24ebfab3fdc81b709b61bd05dcce336c3efcd38ae9487356d5c28fe103f6a2e6dc3dd8883b4411df280dc26ca49b8d71314733006d8361998da5593c3843f8aa77c158b23bc7e83d444821eaededa83aa3736666911d5aade439282f39e480edd6a1862832198f93d4cc2ab8e637ca9d60ba5c49b433236df2c00fc7eb4f37b0fe8787c370f0bf04483961174832f517e3f3f8f838f11bd62205275e54bb0b4562331cbb58a0be62a34c9dcf19ce1e55c76627acd3150cbcfe87
#TRUST-RSA-SHA256 19d27e0c756e6690a0b00c63475c3323da9fac0a495941c1e8cf9ca6914cce9bb8aab8eb70af442f5e142de66315f7d4140cf9597f6b38430b9b1c9cb39a41a1f6cc7802a236c9a8c2e0ca036ceb6c67731cb66087ebe73fc340c892867af6e02c41eba2460e965a68997bb6801fe3fe83fcf5cd05b7f2c76f39ee2b65df73596ccb77ca3a693e8adb92a4b6955b918bc696f9adbd69c86efc0816f70e8ff7ffac4999af14e1816c012086eef5a755061bd380c919d3f6cf0683432c9cc21e759c0026bdf415fe78927ffbc7590282252552424d7beaf8b3f968e63e750f670c77b42630ad13a9459a41e94c181fa149b0c48702e6f7bea861b910399b37df6733c16768fbb8c46cef9219d776c4aa7112aa24cd97e07885a4959328c0fd92c5667de58cf1fbdc2a432544f4c20d86529adaa9ed5ef3a746d33b916a653dd54a734bd9aecb2ff0d359014d084aef3c319ffa4697cbf27b4208d0f409964467b7c612fb25b8af32b58df13cd26a9b60bacdfa2489c2a90eaf73d6b380bc53536c92f1f50ae4159f91f14944fa198ad2f06ece5374b8b37335b079a9309691f694fb8c2085959ff79fe9469b5670468dbe6e8f13d11d6c7683b96c1d050764900f15fab94753c2e47a72f6467994b8a3d51d92c68f32a590f5a9006c0c0299fe9f081244a6ee2f1f08f40bf67a669a40bf44a45017b86583690370e7ea249bd1cc
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50052);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2007-3030");
  script_bugtraq_id(24803);
  script_xref(name:"MSFT", value:"MS07-036");
  script_xref(name:"MSKB", value:"936542");

  script_name(english:"MS07-036: Vulnerability in Microsoft Excel Could Allow Remote Code Execution (936542) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by a memory corruption vulnerability.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-036");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-3030");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

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

  fixed_version = '11.3.6';
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
